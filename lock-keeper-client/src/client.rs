//! Client object to interact with the key server.

use crate::LockKeeperClientError;
use http::uri::Scheme;
use http_body::combinators::UnsyncBoxBody;
use hyper::client::HttpConnector;
use hyper_rustls::HttpsConnector;
use lock_keeper::{
    config::client::Config,
    constants::{ACCOUNT_NAME, ACTION},
    crypto::{OpaqueExportKey, OpaqueSessionKey, StorageKey},
    infrastructure::channel::ClientChannel,
    rpc::lock_keeper_rpc_client::LockKeeperRpcClient,
    types::{
        database::user::{AccountName, UserId},
        operations::{
            retrieve_storage_key::{client, server},
            ClientAction,
        },
    },
};
use rand::{rngs::StdRng, SeedableRng};
use std::{str::FromStr, sync::Arc};
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{metadata::MetadataValue, Request};
use tracing::error;

// TODO: password security, e.g. memory management, etc... #54
#[derive(Debug, Default)]
pub struct Password(String);

impl ToString for Password {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl FromStr for Password {
    type Err = LockKeeperClientError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Password(s.to_string()))
    }
}

impl Password {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
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
#[derive(Debug)]
#[allow(unused)]
pub struct LockKeeperClient {
    session_key: OpaqueSessionKey,
    config: Config,
    account_name: AccountName,
    user_id: UserId,
    tonic_client: LockKeeperRpcClient<LockKeeperRpcClientInner>,
    pub(crate) rng: Arc<Mutex<StdRng>>,
    pub(crate) export_key: OpaqueExportKey,
}

/// Connection type used by `LockKeeperRpcClient`.
/// This would normally be `tonic::transport:Channel` but TLS makes it more
/// complicated.
type LockKeeperRpcClientInner = hyper::Client<
    HttpsConnector<HttpConnector>,
    UnsyncBoxBody<tonic::codegen::Bytes, tonic::Status>,
>;

pub(crate) struct AuthenticateResult {
    pub(crate) session_key: OpaqueSessionKey,
    pub(crate) export_key: OpaqueExportKey,
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
    ) -> Result<LockKeeperRpcClient<LockKeeperRpcClientInner>, LockKeeperClientError> {
        let address = config.server_location()?;

        if address.scheme() != Some(&Scheme::HTTPS) {
            return Err(LockKeeperClientError::HttpNotAllowed);
        }

        let tls_config = config.tls_config()?;

        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_only()
            .enable_http2()
            .build();

        let client = hyper::Client::builder().build(connector);
        let rpc_client = LockKeeperRpcClient::with_origin(client, address);

        Ok(rpc_client)
    }

    pub(crate) async fn authenticate(
        mut client: LockKeeperRpcClient<LockKeeperRpcClientInner>,
        account_name: &AccountName,
        password: &Password,
        config: &Config,
    ) -> Result<Self, LockKeeperClientError> {
        let mut rng = StdRng::from_entropy();

        let mut client_channel =
            Self::create_channel(&mut client, ClientAction::Authenticate, account_name).await?;
        let result =
            Self::handle_authentication(client_channel, &mut rng, account_name, password).await;
        match result {
            Ok(AuthenticateResult {
                session_key,
                export_key,
                user_id,
            }) => {
                // TODO #186: receive User ID over authenticated channel (under session_key)
                let client = LockKeeperClient {
                    session_key,
                    config: config.clone(),
                    tonic_client: client,
                    rng: Arc::new(Mutex::new(rng)),
                    account_name: account_name.clone(),
                    user_id,
                    export_key,
                };
                Ok(client)
            }
            Err(e) => {
                error!("{:?}", e);
                Err(e)
            }
        }
    }

    /// Helper to create the appropriate [`ClientChannel`] to send to tonic
    /// handler functions based on the client's action.
    pub(crate) async fn create_channel(
        client: &mut LockKeeperRpcClient<LockKeeperRpcClientInner>,
        action: ClientAction,
        account_name: &AccountName,
    ) -> Result<ClientChannel, LockKeeperClientError> {
        // Create channel to send messages to server after connection is established via
        // RPC
        let (tx, rx) = mpsc::channel(2);
        let mut stream = Request::new(ReceiverStream::new(rx));

        // Set AccountName and Action in metadata
        let account_name_val = MetadataValue::try_from(account_name.to_string())?;
        let action_val = MetadataValue::try_from(format!("{:?}", action))?;
        let _ = stream.metadata_mut().insert(ACCOUNT_NAME, account_name_val);
        let _ = stream.metadata_mut().insert(ACTION, action_val);

        // Server returns its own channel that is uses to send responses
        let server_response = match action {
            ClientAction::Authenticate => client.authenticate(stream).await,
            ClientAction::CreateStorageKey => client.create_storage_key(stream).await,
            ClientAction::Export => client.retrieve(stream).await,
            ClientAction::Generate => client.generate(stream).await,
            ClientAction::Register => client.register(stream).await,
            ClientAction::RemoteGenerate => client.remote_generate(stream).await,
            ClientAction::Retrieve => client.retrieve(stream).await,
            ClientAction::RetrieveAuditEvents => client.retrieve_audit_events(stream).await,
            ClientAction::RetrieveStorageKey => client.retrieve_storage_key(stream).await,
        }?
        .into_inner();

        let mut channel = ClientChannel::create(tx, server_response);
        Ok(channel)
    }

    /// Close a session.
    ///
    /// Outputs: None, if successful.
    pub fn close(self) -> Result<(), LockKeeperClientError> {
        todo!()
    }

    /// Retrieve the [`lock_keeper::crypto::Encrypted<StorageKey>`] that belongs
    /// to the user specified by `user_id`
    pub(crate) async fn retrieve_storage_key(&self) -> Result<StorageKey, LockKeeperClientError> {
        // Create channel to send messages to server
        let mut channel = Self::create_channel(
            &mut self.tonic_client(),
            ClientAction::RetrieveStorageKey,
            self.account_name(),
        )
        .await?;

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
            .decrypt_storage_key(self.export_key.clone(), self.user_id())?;
        Ok(storage_key)
    }
}
