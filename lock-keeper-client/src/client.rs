//! Client object to interact with the key server.

use crate::{config::Config, LockKeeperClientError, LockKeeperResponse, Result};
use http::uri::Scheme;
use http_body::combinators::UnsyncBoxBody;
use hyper::client::HttpConnector;
use hyper_rustls::HttpsConnector;
use lock_keeper::{
    constants::METADATA,
    crypto::{MasterKey, OpaqueSessionKey, StorageKey},
    infrastructure::channel::ClientChannel,
    rpc::lock_keeper_rpc_client::LockKeeperRpcClient,
    types::{
        database::user::{AccountName, UserId},
        operations::{
            retrieve_storage_key::{client, server},
            ClientAction, RequestMetadata,
        },
    },
};
use rand::{rngs::StdRng, SeedableRng};
use std::{str::FromStr, sync::Arc};
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tonic::Request;
use tracing::error;
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

/// A `LockKeeperClient` is an abstraction over client operations; that is, it
/// wraps around the state and infrastructure necessary to make requests to the
/// key server. It handles confidentiality, integrity, and authentication of
/// communication with the server.
/// A `LockKeeperClient` exists for the duration of one authenticated session,
/// during which multiple requests can be made to the server.
///
/// TODO #30: This abstraction needs a lot of design attention.
#[derive(Debug, ZeroizeOnDrop)]
#[allow(unused)]
pub struct LockKeeperClient {
    session_key: OpaqueSessionKey,
    #[zeroize(skip)]
    config: Config,
    #[zeroize(skip)]
    account_name: AccountName,
    #[zeroize(skip)]
    user_id: UserId,
    master_key: MasterKey,
    #[zeroize(skip)]
    tonic_client: LockKeeperRpcClient<LockKeeperRpcClientInner>,
    #[zeroize(skip)]
    pub(crate) rng: Arc<Mutex<StdRng>>,
}

/// Connection type used by `LockKeeperRpcClient`.
/// This would normally be `tonic::transport:Channel` but TLS makes it more
/// complicated.
type LockKeeperRpcClientInner = hyper::Client<
    HttpsConnector<HttpConnector>,
    UnsyncBoxBody<tonic::codegen::Bytes, tonic::Status>,
>;

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct AuthenticateResult {
    pub(crate) session_key: OpaqueSessionKey,
    pub(crate) master_key: MasterKey,
    #[zeroize(skip)]
    pub(crate) user_id: UserId,
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
        if config.server_uri.scheme() != Some(&Scheme::HTTPS) {
            return Err(LockKeeperClientError::HttpNotAllowed);
        }

        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(config.tls_config.clone())
            .https_only()
            .enable_http2()
            .build();

        let client = hyper::Client::builder().build(connector);
        let rpc_client = LockKeeperRpcClient::with_origin(client, config.server_uri.clone());

        Ok(rpc_client)
    }

    pub(crate) async fn authenticate(
        mut client: LockKeeperRpcClient<LockKeeperRpcClientInner>,
        account_name: &AccountName,
        password: &Password,
        config: &Config,
    ) -> Result<LockKeeperResponse<Self>> {
        let mut rng = StdRng::from_entropy();
        let metadata = RequestMetadata::new(account_name, ClientAction::Authenticate, None);
        let mut client_channel = Self::create_channel(&mut client, &metadata).await?;
        let result =
            Self::handle_authentication(&mut client_channel, &mut rng, account_name, password)
                .await;
        match result {
            Ok(mut auth_result) => {
                // TODO #186: receive User ID over authenticated channel (under session_key)
                let client = LockKeeperClient {
                    session_key: auth_result.session_key.clone(),
                    config: config.clone(),
                    tonic_client: client,
                    rng: Arc::new(Mutex::new(rng)),
                    account_name: account_name.clone(),
                    user_id: auth_result.user_id.clone(),
                    master_key: auth_result.master_key.clone(),
                };
                auth_result.zeroize();
                Ok(LockKeeperResponse::from_channel(client_channel, client))
            }
            Err(e) => {
                error!("{:?}", e);
                Err(e)
            }
        }
    }

    pub(crate) fn create_metadata(&self, action: ClientAction) -> RequestMetadata {
        RequestMetadata::new(self.account_name(), action, Some(self.user_id()))
    }

    /// Helper to create the appropriate [`ClientChannel`] to send to tonic
    /// handler functions based on the client's action.
    pub(crate) async fn create_channel(
        client: &mut LockKeeperRpcClient<LockKeeperRpcClientInner>,
        metadata: &RequestMetadata,
    ) -> Result<ClientChannel> {
        // Create channel to send messages to server after connection is established via
        // RPC
        let (tx, rx) = mpsc::channel(2);
        let mut stream = Request::new(ReceiverStream::new(rx));
        let _ = stream.metadata_mut().insert(METADATA, metadata.try_into()?);

        // Server returns its own channel that is uses to send responses
        let server_response = match metadata.action() {
            ClientAction::Authenticate => client.authenticate(stream).await,
            ClientAction::CreateStorageKey => client.create_storage_key(stream).await,
            ClientAction::Export => client.retrieve(stream).await,
            ClientAction::ExportSigningKey => client.retrieve_signing_key(stream).await,
            ClientAction::Generate => client.generate(stream).await,
            ClientAction::ImportSigningKey => client.import_signing_key(stream).await,
            ClientAction::Register => client.register(stream).await,
            ClientAction::RemoteGenerate => client.remote_generate(stream).await,
            ClientAction::RemoteSignBytes => client.remote_sign_bytes(stream).await,
            ClientAction::Retrieve => client.retrieve(stream).await,
            ClientAction::RetrieveAuditEvents => client.retrieve_audit_events(stream).await,
            ClientAction::RetrieveSigningKey => client.retrieve_signing_key(stream).await,
            ClientAction::RetrieveStorageKey => client.retrieve_storage_key(stream).await,
        }?;

        let mut channel = ClientChannel::create(tx, server_response)?;
        Ok(channel)
    }

    /// Close a session.
    ///
    /// Outputs: None, if successful.
    pub fn close(self) -> Result<LockKeeperResponse<()>> {
        todo!()
    }

    /// Retrieve the [`lock_keeper::crypto::Encrypted<StorageKey>`] that belongs
    /// to the user specified by `user_id`
    pub(crate) async fn retrieve_storage_key(&self) -> Result<StorageKey> {
        // Create channel to send messages to server
        let metadata = self.create_metadata(ClientAction::RetrieveStorageKey);
        let mut channel = Self::create_channel(&mut self.tonic_client(), &metadata).await?;

        // Send UserId to server
        let request = client::Request {
            user_id: self.user_id().clone(),
        };
        channel.send(request).await?;

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
