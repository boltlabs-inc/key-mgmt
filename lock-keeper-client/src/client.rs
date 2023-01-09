//! Client object to interact with the key server.

use crate::{config::Config, LockKeeperClientError, Result};
use http_body::combinators::UnsyncBoxBody;
use hyper::client::HttpConnector;
use hyper_rustls::HttpsConnector;
use lock_keeper::{
    constants::METADATA,
    crypto::{MasterKey, OpaqueSessionKey, StorageKey},
    infrastructure::channel::{Authenticated, ClientChannel, Unauthenticated},
    rpc::lock_keeper_rpc_client::LockKeeperRpcClient,
    types::{
        database::user::{AccountName, UserId},
        operations::{
            logout::server as logout_server, retrieve_storage_key::server, ClientAction,
            RequestMetadata, SessionId,
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
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

/// A single session with the LockKeeper key server.
#[derive(Debug)]
pub(crate) struct Session {
    session_id: SessionId,
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
#[derive(Debug)]
#[allow(unused)]
pub struct LockKeeperClient {
    session: Session,
    config: Config,
    account_name: AccountName,
    user_id: UserId,
    master_key: MasterKey,
    tonic_client: LockKeeperRpcClient<LockKeeperRpcClientInner>,
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
    pub(crate) session_id: SessionId,
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

        let client = hyper::Client::builder().build(connector);
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

        let metadata = RequestMetadata::new(
            account_name,
            ClientAction::Authenticate,
            None,
            None,
            request_id,
        );
        let mut rng = StdRng::from_entropy();
        let rng_arc_mutex = Arc::new(Mutex::new(rng));
        let mut client_channel = Self::create_channel(&mut client, &metadata).await?;
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
            None,
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
            Some(self.user_id()),
            Some(&self.session.session_id),
            request_id,
        )
    }

    /// Helper to create the appropriate [`ClientChannel`] to send to tonic
    /// handler functions based on the client's action. This function creates
    /// unauthenticated channels. Use `create_authenticated_channel` to create
    /// an authenticated channel.
    ///
    /// This function will return an error if the [`ClientAction`] requires
    /// authentication.
    pub(crate) async fn create_channel(
        client: &mut LockKeeperRpcClient<LockKeeperRpcClientInner>,
        metadata: &RequestMetadata,
    ) -> Result<ClientChannel<Unauthenticated>> {
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
            | ClientAction::RetrieveSigningKey
            | ClientAction::RetrieveStorageKey => {
                return Err(LockKeeperClientError::AuthenticatedChannelNeeded)
            }
        }?;

        let mut channel = ClientChannel::new(tx, server_response)?;
        Ok(channel)
    }

    /// Helper to create the appropriate [`ClientChannel`] to send to tonic
    /// handler functions based on the client's action. This function creates
    /// authenticated channels. Use `create_channel` to create
    /// an unauthenticated channel.
    ///
    /// This function will return an error if the [`ClientAction`] requires
    /// an unauthenticated channel.
    pub(crate) async fn create_authenticated_channel(
        client: &mut LockKeeperRpcClient<LockKeeperRpcClientInner>,
        metadata: &RequestMetadata,
        session_key: OpaqueSessionKey,
        rng: Arc<Mutex<StdRng>>,
    ) -> Result<ClientChannel<Authenticated<StdRng>>> {
        // Create channel to send messages to server after connection is established via
        // RPC
        let (tx, rx) = mpsc::channel(2);
        let mut stream = Request::new(ReceiverStream::new(rx));

        // Serialize metadata and set as tonic request metadata
        let _ = stream.metadata_mut().insert(METADATA, metadata.try_into()?);

        // Server returns its own channel that is uses to send responses
        let server_response = match metadata.action() {
            ClientAction::CreateStorageKey => client.create_storage_key(stream).await,
            ClientAction::ExportSecret => client.retrieve_secret(stream).await,
            ClientAction::ExportSigningKey => client.retrieve_secret(stream).await,
            ClientAction::GenerateSecret => client.generate_secret(stream).await,
            ClientAction::GetUserId => client.get_user_id(stream).await,
            ClientAction::ImportSigningKey => client.import_signing_key(stream).await,
            ClientAction::Logout => client.logout(stream).await,
            ClientAction::Register => client.register(stream).await,
            ClientAction::RemoteGenerateSigningKey => client.remote_generate(stream).await,
            ClientAction::RemoteSignBytes => client.remote_sign_bytes(stream).await,
            ClientAction::RetrieveSecret => client.retrieve_secret(stream).await,
            ClientAction::RetrieveAuditEvents => client.retrieve_audit_events(stream).await,
            ClientAction::RetrieveSigningKey => client.retrieve_secret(stream).await,
            ClientAction::RetrieveStorageKey => client.retrieve_storage_key(stream).await,

            // These actions generate an error because they should be on an unauthenticated channel
            ClientAction::Authenticate | ClientAction::Register => {
                return Err(LockKeeperClientError::UnauthenticatedChannelNeeded)
            }
        }?;

        let mut channel =
            ClientChannel::new(tx, server_response)?.into_authenticated(session_key, rng.clone());
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
