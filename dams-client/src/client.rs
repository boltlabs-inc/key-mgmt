//! Client object to interact with the key server.

use crate::DamsClientError;
use dams::{
    channel::ClientChannel, config::client::Config, dams_rpc::dams_rpc_client::DamsRpcClient,
    user::UserId,
};
use http::uri::Scheme;
use rand::{rngs::StdRng, SeedableRng};
use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Uri};
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
    session_key: [u8; 64],
    config: Config,
    tonic_client: DamsRpcClient<Channel>,
    rng: Arc<Mutex<StdRng>>,
}

/// Options for actions the client can take.
pub(crate) enum ClientAction {
    Register,
    Authenticate,
}

#[allow(unused)]
impl DamsClient {
    /// Create a `tonic` client object and return it to the client app.
    ///
    /// The returned client should be stored as part of the [`DamsClient`]
    /// state.
    async fn connect(address: Uri) -> Result<DamsRpcClient<Channel>, DamsClientError> {
        if address.scheme() == Some(&Scheme::HTTPS) {
            Ok(DamsRpcClient::connect(address).await?)
        } else {
            Err(DamsClientError::HttpNotAllowed)
        }
    }

    /// Authenticate to the DAMS key server as a previously registered user.
    ///
    /// Output: If successful, returns a [`DamsClient`].
    pub async fn authenticated_client(
        user_id: &UserId,
        password: &Password,
        config: &Config,
    ) -> Result<Self, DamsClientError> {
        let mut rng = StdRng::from_entropy();
        let server_location = config.server_location()?;
        let mut client = Self::connect(server_location).await?;
        Self::authenticate(client, rng, user_id, password, config).await
    }

    async fn authenticate(
        mut client: DamsRpcClient<Channel>,
        mut rng: StdRng,
        user_id: &UserId,
        password: &Password,
        config: &Config,
    ) -> Result<Self, DamsClientError> {
        let mut client_channel =
            Self::create_channel(&mut client, ClientAction::Authenticate).await?;
        let result = Self::handle_authentication(client_channel, &mut rng, user_id, password).await;
        match result {
            Ok(result) => {
                let session = DamsClient {
                    session_key: result,
                    config: config.clone(),
                    tonic_client: client,
                    rng: Arc::new(Mutex::new(rng)),
                };
                Ok(session)
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
    /// Output: If successful, returns a [`DamsClient`].
    pub async fn register(
        user_id: &UserId,
        password: &Password,
        config: &Config,
    ) -> Result<Self, DamsClientError> {
        let mut rng = StdRng::from_entropy();
        let server_location = config.server_location()?;
        let mut client = Self::connect(server_location).await?;
        let mut client_channel = Self::create_channel(&mut client, ClientAction::Register).await?;
        let result = Self::handle_registration(client_channel, &mut rng, user_id, password).await;
        match result {
            Ok(_) => Self::authenticate(client, rng, user_id, password, config).await,
            Err(e) => {
                error!("{:?}", e);
                Err(DamsClientError::RegistrationFailed)
            }
        }
    }

    /// Helper to create the appropriate [`ClientChannel`] to send to tonic
    /// handler functions based on the client's action.
    pub(crate) async fn create_channel(
        client: &mut DamsRpcClient<Channel>,
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
}
