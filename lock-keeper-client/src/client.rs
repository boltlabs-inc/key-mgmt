//! Client object to interact with the key server.

use crate::{
    channel::{Authenticated, Channel, Unauthenticated},
    config::Config,
    LockKeeperClientError, Result,
};
use http_body::combinators::UnsyncBoxBody;
use hyper::client::HttpConnector;
use hyper_rustls::HttpsConnector;
use lock_keeper::{
    constants::METADATA,
    crypto::{MasterKey, OpaqueSessionKey, StorageKey},
    rpc::lock_keeper_rpc_client::LockKeeperRpcClient,
    types::{
        database::account::{AccountName, UserId},
        operations::{
            logout::server as logout_server, retrieve_storage_key::server, ClientAction,
            RequestMetadata,
        },
    },
};
use rand::{rngs::StdRng, SeedableRng};
use std::{str::FromStr, sync::Arc};
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tonic::Request;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

// TODO: password security, e.g. memory management, etc... #54
#[derive(Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct Password(Vec<u8>);

impl FromStr for Password {
    type Err = LockKeeperClientError;

    fn from_str(s: &str) -> Result<Self> {
        Ok(Password(s.as_bytes().to_vec()))
    }
}

impl Password {
    pub fn new(bytes: Vec<u8>) -> Self {
        Password(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

/// A single session with the LockKeeper key server.
#[derive(Clone, Debug)]
pub(crate) struct Session {
    session_id: Uuid,
    session_key: OpaqueSessionKey,
}

/// A `LockKeeperClient` is an abstraction over client operations; that is, it
/// wraps around the state and infrastructure necessary to make requests to the
/// key server. It handles confidentiality, integrity, and authentication of
/// communication with the server.
/// A `LockKeeperClient` exists for the duration of one authenticated session,
/// during which multiple requests can be made to the server.
///
/// TODO #30: This abstraction needs a lot of design attention.
#[derive(Clone, Debug)]
#[allow(unused)]
pub struct LockKeeperClient {
    session: Session,
    config: Config,
    account_name: AccountName,
    user_id: UserId,
    master_key: MasterKey,
    pub(crate) tonic_client: LockKeeperRpcClient<LockKeeperRpcClientInner>,
    pub(crate) rng: Arc<Mutex<StdRng>>,
}

/// Connection type used by `LockKeeperRpcClient`.
/// This would normally be `tonic::transport:Channel` but TLS makes it more
/// complicated.
type LockKeeperRpcClientInner = hyper::Client<
    HttpsConnector<HttpConnector>,
    UnsyncBoxBody<tonic::codegen::Bytes, tonic::Status>,
>;

pub(crate) struct AuthenticateResult {
    pub(crate) session_id: Uuid,
    pub(crate) session_key: OpaqueSessionKey,
    pub(crate) master_key: MasterKey,
}

#[allow(unused)]
impl LockKeeperClient {
    /// Get [`UserId`] for the authenticated client.
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Get [`AccountName`] for the authenticated client.
    pub fn account_name(&self) -> &AccountName {
        &self.account_name
    }

    /// Get [`OpaqueSessionKey`] for the authenticated client.
    pub fn session_key(&self) -> &OpaqueSessionKey {
        &self.session.session_key
    }

    pub(crate) fn tonic_client(&self) -> LockKeeperRpcClient<LockKeeperRpcClientInner> {
        self.tonic_client.clone()
    }

    /// Create a `tonic` client object and return it to the client app.
    ///
    /// The returned client should be stored as part of the [`LockKeeperClient`]
    /// state.
    pub(crate) async fn connect(
        config: &Config,
    ) -> Result<LockKeeperRpcClient<LockKeeperRpcClientInner>> {
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(config.tls_config.clone())
            .https_or_http()
            .enable_http2()
            .build();

        let client = hyper::Client::builder().http2_only(true).build(connector);
        let rpc_client = LockKeeperRpcClient::with_origin(client, config.server_uri.clone());

        Ok(rpc_client)
    }

    pub(crate) async fn authenticate(
        mut client: Option<LockKeeperRpcClient<LockKeeperRpcClientInner>>,
        account_name: &AccountName,
        password: &Password,
        config: &Config,
        request_id: Uuid,
    ) -> Result<Self> {
        // Authenticate with key server
        let mut client = match client {
            Some(client) => client,
            None => Self::connect(config).await?,
        };

        let metadata =
            RequestMetadata::new(account_name, ClientAction::Authenticate, None, request_id);
        let mut rng = StdRng::from_entropy();
        let rng_arc_mutex = Arc::new(Mutex::new(rng));
        let mut client_channel =
            Self::create_unauthenticated_channel(&mut client, &metadata).await?;
        let mut auth_result = Self::handle_authentication(
            client_channel,
            rng_arc_mutex.clone(),
            account_name,
            password,
        )
        .await?;

        // Get user ID over an authenticated channel
        let metadata = RequestMetadata::new(
            account_name,
            ClientAction::GetUserId,
            Some(&auth_result.session_id),
            request_id,
        );
        let mut authenticated_channel = Self::create_authenticated_channel(
            &mut client,
            &metadata,
            auth_result.session_key.clone(),
            rng_arc_mutex.clone(),
        )
        .await?;
        let user_id = Self::handle_get_user_id(authenticated_channel).await?;
        let session = Session {
            session_id: auth_result.session_id,
            session_key: auth_result.session_key,
        };

        // Create and return `LockKeeperClient`
        let client = LockKeeperClient {
            session,
            config: config.clone(),
            tonic_client: client,
            rng: rng_arc_mutex,
            account_name: account_name.clone(),
            user_id,
            master_key: auth_result.master_key,
        };
        Ok(client)
    }

    pub(crate) fn create_metadata(
        &self,
        action: ClientAction,
        request_id: Uuid,
    ) -> RequestMetadata {
        RequestMetadata::new(
            self.account_name(),
            action,
            Some(&self.session.session_id),
            request_id,
        )
    }

    /// Create a [`Channel<Unauthenticated>`] object for communicating with the
    /// server.
    ///
    /// The client will make the proper gRPC call here based on the
    /// [`ClientAction`]. After this gRPC call our client and server are
    /// ready to communicate back and forth to complete our cryptographic
    /// protocols.
    ///
    /// This function creates unauthenticated channels. Use
    /// `create_authenticated_channel` to create an authenticated channel.
    /// This function will return an error if the [`ClientAction`]
    /// (contained in `metadata`) requires authentication.
    pub(crate) async fn create_unauthenticated_channel(
        client: &mut LockKeeperRpcClient<LockKeeperRpcClientInner>,
        metadata: &RequestMetadata,
    ) -> Result<Channel<Unauthenticated>> {
        // Create channel to send messages to server after connection is established via
        // RPC
        let (tx, rx) = mpsc::channel(2);
        let mut stream = Request::new(ReceiverStream::new(rx));

        // Serialize metadata and set as tonic request metadata
        let _ = stream.metadata_mut().insert(METADATA, metadata.try_into()?);

        // Server returns its own channel that is uses to send responses
        let server_response = match metadata.action() {
            ClientAction::Authenticate => client.authenticate(stream).await,
            ClientAction::Register => client.register(stream).await,

            // These actions generate an error because they should be on an authenticated channel
            ClientAction::CreateStorageKey
            | ClientAction::DeleteKey
            | ClientAction::ExportSecret
            | ClientAction::ExportSigningKey
            | ClientAction::GenerateSecret
            | ClientAction::GetUserId
            | ClientAction::ImportSigningKey
            | ClientAction::Logout
            | ClientAction::RemoteGenerateSigningKey
            | ClientAction::RemoteSignBytes
            | ClientAction::RetrieveSecret
            | ClientAction::RetrieveAuditEvents
            | ClientAction::RetrieveServerEncryptedBlob
            | ClientAction::RetrieveSigningKey
            | ClientAction::RetrieveStorageKey
            | ClientAction::StoreServerEncryptedBlob => {
                return Err(LockKeeperClientError::AuthenticatedChannelNeeded)
            }

            // These actions do not require a channel
            ClientAction::CheckSession => {
                return Err(LockKeeperClientError::OperationDoesNotRequireChannel)
            }
        }?;

        let mut channel = Channel::new(tx, server_response)?;
        Ok(channel)
    }

    /// Create a [`Channel<Authenticated<StdRng>>`] object for communicating
    /// with the server.
    ///
    /// The client will make the proper gRPC call here based on the
    /// [`ClientAction`]. After this gRPC call our client and server are
    /// ready to communicate back and forth to complete our cryptographic
    /// protocols.
    ///
    /// This function creates authenticated channels. This function will return
    /// an error if the [`ClientAction`] (contained in `metadata`) does not
    /// need authentication.
    pub(crate) async fn create_authenticated_channel(
        client: &mut LockKeeperRpcClient<LockKeeperRpcClientInner>,
        metadata: &RequestMetadata,
        session_key: OpaqueSessionKey,
        rng: Arc<Mutex<StdRng>>,
    ) -> Result<Channel<Authenticated<StdRng>>> {
        // Create channel to send messages to server after connection is established via
        // RPC
        let (tx, rx) = mpsc::channel(2);
        let mut stream = Request::new(ReceiverStream::new(rx));

        // Serialize metadata and set as tonic request metadata
        let _ = stream.metadata_mut().insert(METADATA, metadata.try_into()?);

        // Server returns its own channel that is uses to send responses
        let server_response = match metadata.action() {
            ClientAction::CreateStorageKey => client.create_storage_key(stream).await,
            ClientAction::DeleteKey => client.delete_key(stream).await,
            ClientAction::ExportSecret => client.retrieve_secret(stream).await,
            ClientAction::ExportSigningKey => client.retrieve_secret(stream).await,
            ClientAction::GenerateSecret => client.generate_secret(stream).await,
            ClientAction::GetUserId => client.get_user_id(stream).await,
            ClientAction::ImportSigningKey => client.import_signing_key(stream).await,
            ClientAction::Logout => client.logout(stream).await,
            ClientAction::Register => client.register(stream).await,
            ClientAction::RemoteGenerateSigningKey => client.remote_generate(stream).await,
            ClientAction::RemoteSignBytes => client.remote_sign_bytes(stream).await,
            ClientAction::RetrieveServerEncryptedBlob => {
                client.retrieve_server_encrypted_blob(stream).await
            }
            ClientAction::RetrieveSecret => client.retrieve_secret(stream).await,
            ClientAction::RetrieveAuditEvents => client.retrieve_audit_events(stream).await,
            ClientAction::RetrieveSigningKey => client.retrieve_secret(stream).await,
            ClientAction::RetrieveStorageKey => client.retrieve_storage_key(stream).await,
            ClientAction::StoreServerEncryptedBlob => {
                client.store_server_encrypted_blob(stream).await
            }

            // These actions generate an error because they should be on an unauthenticated channel
            ClientAction::Authenticate | ClientAction::Register => {
                return Err(LockKeeperClientError::UnauthenticatedChannelNeeded)
            }

            // These actions do not require a channel
            ClientAction::CheckSession => {
                return Err(LockKeeperClientError::OperationDoesNotRequireChannel)
            }
        }?;

        let mut channel =
            Channel::new(tx, server_response)?.into_authenticated(session_key, rng.clone());
        Ok(channel)
    }

    /// Close a session.
    ///
    /// Outputs: None, if successful.
    pub(crate) async fn handle_logout(&self, request_id: Uuid) -> Result<()> {
        let metadata = self.create_metadata(ClientAction::Logout, request_id);
        let mut client_channel = Self::create_authenticated_channel(
            &mut self.tonic_client(),
            &metadata,
            self.session.session_key.clone(),
            self.rng.clone(),
        )
        .await?;
        let response: logout_server::Response = client_channel.receive().await?;
        if response.success {
            Ok(())
        } else {
            Err(LockKeeperClientError::LogoutFailed)
        }
    }

    /// Retrieve the [`lock_keeper::crypto::Encrypted<StorageKey>`] that belongs
    /// to the user specified by `user_id`
    pub(crate) async fn retrieve_storage_key(&self, request_id: Uuid) -> Result<StorageKey> {
        // Create channel to send messages to server
        let metadata = self.create_metadata(ClientAction::RetrieveStorageKey, request_id);
        let mut channel = Self::create_authenticated_channel(
            &mut self.tonic_client(),
            &metadata,
            self.session_key().clone(),
            self.rng.clone(),
        )
        .await?;

        // Get encrypted storage key from server
        let response: server::Response = channel.receive().await?;

        // Decrypt storage_key
        let storage_key = response
            .ciphertext
            .decrypt_storage_key(self.master_key.clone(), self.user_id())?;
        Ok(storage_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_gets_zeroized() -> Result<()> {
        let password_bytes = b"test";
        let password = Password(password_bytes.to_vec());
        let ptr = password.0.as_ptr();

        drop(password);

        let after_drop = unsafe { core::slice::from_raw_parts(ptr, 4) };
        assert_ne!(password_bytes, after_drop);
        Ok(())
    }
}
