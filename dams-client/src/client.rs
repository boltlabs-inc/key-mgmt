//! Client object to interact with the key server.

use crate::DamsClientError;
use dams::{
    channel::ClientChannel,
    config::client::Config,
    crypto::OpaqueSessionKey,
    dams_rpc::dams_rpc_client::DamsRpcClient,
    user::{AccountName, UserId},
    ClientAction,
};
use http::uri::Scheme;
use http_body::combinators::UnsyncBoxBody;
use hyper::client::HttpConnector;
use hyper_rustls::HttpsConnector;
use rand::{rngs::StdRng, SeedableRng};
use std::{str::FromStr, sync::Arc};
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
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
    type Err = DamsClientError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Password(s.to_string()))
    }
}

impl Password {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// A `DamsClient` is an abstraction over client operations; that is, it wraps
/// around the state and infrastructure necessary to make requests to the key
/// server. It handles confidentiality, integrity, and authentication of
/// communication with the server.
/// A `DamsClient` exists for the duration of one authenticated session, during
/// which multiple requests can be made to the server.
///
/// TODO #30: This abstraction needs a lot of design attention.
#[derive(Debug)]
#[allow(unused)]
pub struct DamsClient {
    session_key: OpaqueSessionKey,
    config: Config,
    tonic_client: DamsRpcClient<DamsRpcClientInner>,
    pub(crate) rng: Arc<Mutex<StdRng>>,
    user_id: UserId,
}

/// Connection type used by `DamsRpcClient`.
/// This would normally be `tonic::transport:Channel` but TLS makes it more
/// complicated.
type DamsRpcClientInner = hyper::Client<
    HttpsConnector<HttpConnector>,
    UnsyncBoxBody<tonic::codegen::Bytes, tonic::Status>,
>;

#[allow(unused)]
impl DamsClient {
    // Get [`UserId`] for the authenticated client.
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Create a `tonic` client object and return it to the client app.
    ///
    /// The returned client should be stored as part of the [`DamsClient`]
    /// state.
    async fn connect(
        config: &Config,
    ) -> Result<DamsRpcClient<DamsRpcClientInner>, DamsClientError> {
        let address = config.server_location()?;

        if address.scheme() != Some(&Scheme::HTTPS) {
            return Err(DamsClientError::HttpNotAllowed);
        }

        let tls_config = config.tls_config()?;

        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_only()
            .enable_http2()
            .build();

        let client = hyper::Client::builder().build(connector);
        let rpc_client = DamsRpcClient::with_origin(client, address);

        Ok(rpc_client)
    }

    /// Authenticate to the DAMS key server as a previously registered user.
    ///
    /// Output: If successful, returns a [`DamsClient`].
    pub async fn authenticated_client(
        account_name: &AccountName,
        password: &Password,
        config: &Config,
    ) -> Result<Self, DamsClientError> {
        let mut rng = StdRng::from_entropy();
        let server_location = config.server_location()?;
        let mut client = Self::connect(config).await?;
        Self::authenticate(client, account_name, password, config).await
    }

    async fn authenticate(
        mut client: DamsRpcClient<DamsRpcClientInner>,
        account_name: &AccountName,
        password: &Password,
        config: &Config,
    ) -> Result<Self, DamsClientError> {
        let mut rng = StdRng::from_entropy();

        let mut client_channel =
            Self::create_channel(&mut client, ClientAction::Authenticate).await?;
        let result =
            Self::handle_authentication(client_channel, &mut rng, account_name, password).await;
        match result {
            Ok((session_key, user_id)) => {
                // TODO #186: receive User ID over authenticated channel (under session_key)
                let client = DamsClient {
                    session_key,
                    config: config.clone(),
                    tonic_client: client,
                    rng: Arc::new(Mutex::new(rng)),
                    user_id,
                };
                Ok(client)
            }
            Err(e) => {
                error!("{:?}", e);
                Err(DamsClientError::AuthenticationFailed)
            }
        }
    }

    /// Register a new user who has not yet interacted with the service.
    ///
    /// This only needs to be called once per user; future sessions can be
    /// created with [`DamsClient::authenticated_client()`].
    ///
    /// Output: Returns Ok if successful. To perform further operations, use
    /// [`Self::authenticated_client()`].
    pub async fn register(
        account_name: &AccountName,
        password: &Password,
        config: &Config,
    ) -> Result<(), DamsClientError> {
        let mut rng = StdRng::from_entropy();
        let server_location = config.server_location()?;
        let mut client = Self::connect(config).await?;
        let mut client_channel = Self::create_channel(&mut client, ClientAction::Register).await?;
        let result =
            Self::handle_registration(client_channel, &mut rng, account_name, password).await;
        match result {
            Ok(export_key) => {
                let mut client = Self::authenticate(client, account_name, password, config).await?;

                // After authenticating we can create the storage key
                let mut client_channel =
                    Self::create_channel(&mut client.tonic_client, ClientAction::CreateStorageKey)
                        .await?;
                Self::handle_create_storage_key(client_channel, &mut rng, account_name, export_key)
                    .await;

                Ok(())
            }
            Err(e) => {
                error!("{:?}", e);
                Err(DamsClientError::RegistrationFailed)
            }
        }
    }

    /// Helper to create the appropriate [`ClientChannel`] to send to tonic
    /// handler functions based on the client's action.
    pub(crate) async fn create_channel(
        client: &mut DamsRpcClient<DamsRpcClientInner>,
        action: ClientAction,
    ) -> Result<ClientChannel, DamsClientError> {
        // Create channel to send messages to server after connection is established via
        // RPC
        let (tx, rx) = mpsc::channel(2);
        let stream = ReceiverStream::new(rx);

        // Server returns its own channel that is uses to send responses
        let server_response = match action {
            ClientAction::Register => client.register(stream).await,
            ClientAction::Authenticate => client.authenticate(stream).await,
            ClientAction::CreateStorageKey => client.create_storage_key(stream).await,
            ClientAction::Generate => client.generate(stream).await,
            ClientAction::RetrieveStorageKey => client.retrieve_storage_key(stream).await,
        }?
        .into_inner();

        let mut channel = ClientChannel::create(tx, server_response);
        Ok(channel)
    }

    /// Close a session.
    ///
    /// Outputs: None, if successful.
    pub fn close(self) -> Result<(), DamsClientError> {
        todo!()
    }

    pub(crate) fn rng(&self) -> Arc<Mutex<StdRng>> {
        self.rng.clone()
    }
}
