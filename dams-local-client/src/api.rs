//! Full implementation of the public API for the DAMS local client library.
//!
//! This API is designed for use with a local client application - that is, an
//! application running directly on the device of an asset owner. The inputs
//! the asset owner provides should be passed directly to this API without being
//! sent to a separate machine.

use anyhow::anyhow;
use dams::{
    blockchain::Blockchain,
    config::{client::Config, opaque::OpaqueCipherSuite},
    crypto::KeyId,
    keys::{KeyInfo, UsePermission, UseRestriction, UserPolicySpecification},
    dams_rpc::{
        client_authenticate::Step as AuthenticateStep, client_register::Step as RegisterStep,
        dams_rpc_client::DamsRpcClient, server_authenticate::Step as ServerAuthenticateStep,
        server_register::Step as ServerRegisterStep, ClientAuthenticate, ClientAuthenticateFinish,
        ClientAuthenticateStart, ClientRegister, ClientRegisterFinish, ClientRegisterStart,
        ServerAuthenticateStart, ServerRegisterFinish, ServerRegisterStart,
    },
    transaction::{TransactionApprovalRequest, TransactionSignature},
    transport::KeyMgmtAddress,
    user::UserId,
};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use rand::{CryptoRng, RngCore};
use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_stream::{wrappers::ReceiverStream, StreamExt};
use tonic::{transport::Channel, Response, Status};
use tracing::error;

#[derive(Debug, Error)]
pub enum SessionError {
    RegistrationFailed,
    AuthenticationFailed,
    ServerConnectionFailed,
    LoginStartFailed,
    SelectAuthenticateFailed,
    SelectRegisterFailed,
    AuthStartFailed,
    RegisterStartFailed,
    AuthFinishFailed,
    RegisterFinishFailed,
}

impl Display for SessionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

// TODO: password security, e.g. memory management, etc... #54
#[derive(Debug, Default)]
pub struct Password(String);

impl ToString for Password {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl FromStr for Password {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Password(s.to_string()))
    }
}

impl Password {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Deployment details for a [`Session`].
///
/// Possible fields include: timeouts, key server IPs, PKI information,
/// preshared keys.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    client_config: Config,
    server: KeyMgmtAddress,
}

impl SessionConfig {
    pub fn new(client_config: Config, server: KeyMgmtAddress) -> Self {
        Self {
            client_config,
            server,
        }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            client_config: Config::default(),
            server: KeyMgmtAddress::from_str("keymgmt://localhost").unwrap(),
        }
    }
}

/// A `Session` is an abstraction over a
/// communication session between an asset owner and a key server
/// that provides mutual authentication, confidentiality, and integrity.
/// An open `Session` is required to interact with this API.
///
/// A session can be ended manually, or it might time out and require
/// re-authentication (that is, creation of a new [`Session`]).
///
/// Full details about the `Session`, such as the identity of the key
/// server, are described in the [`SessionConfig`].
///
/// TODO #30: This abstraction needs a lot of design attention.
#[derive(Debug)]
#[allow(unused)]
pub struct Session {
    config: SessionConfig,
    session_key: [u8; 64],
}

impl Default for Session {
    fn default() -> Self {
        Session {
            config: SessionConfig::default(),
            session_key: [0; 64],
        }
    }
}

#[allow(unused)]
impl Session {
    /// Open a new mutually authenticated session between a previously
    /// registered user and a key server described in the [`SessionConfig`].
    ///
    /// Output: If successful, returns an open [`Session`] between the specified
    /// [`UserId`] and the configured key server.
    pub async fn open<T: CryptoRng + RngCore>(
        client: &mut DamsRpcClient<Channel>,
        rng: &mut T,
        user_id: &UserId,
        password: &Password,
        config: &SessionConfig,
    ) -> Result<Self, SessionError> {
        let result = Self::authenticate(
            client,
            rng,
            user_id,
            password,
            &config.server,
            &config.client_config,
        )
        .await;
        match result {
            Ok(result) => {
                // TODO: unwrap bytes from result and put here?
                let session = Session {
                    config: config.clone(),
                    session_key: result,
                };
                Ok(session)
            }
            Err(e) => {
                error!("{:?}", e);
                Err(SessionError::AuthenticationFailed)
            }
        }
    }

    async fn authenticate<T: CryptoRng + RngCore>(
        client: &mut DamsRpcClient<Channel>,
        rng: &mut T,
        user_id: &UserId,
        password: &Password,
        server: &KeyMgmtAddress,
        config: &self::Config,
    ) -> Result<[u8; 64], Status> {
        // Create channel to send messages to server after connection is established via RPC
        let (tx, rx) = mpsc::channel(2);
        let stream = ReceiverStream::new(rx);

        // Server returns its own channel that is uses to send responses
        let mut server_response = client.authenticate(stream).await?.into_inner();

        let client_login_start_result =
            ClientLogin::<OpaqueCipherSuite>::start(rng, password.as_bytes())
                .map_err(|_| Status::aborted("LoginStartFailed"))?;

        // Send start message to server
        let client_authenticate_start_message: Vec<u8> =
            bincode::serialize(&client_login_start_result.message)
                .map_err(|_| Status::aborted("Unable to serialize client message"))?;
        let authenticate_start =
            Self::client_authenticate_start(client_authenticate_start_message, user_id);
        tx.send(authenticate_start)
            .await
            .map_err(|_| Status::aborted("Could not send message to server"))?;

        let server_authenticate_start_result = match server_response.next().await {
            Some(Ok(res)) => Self::unwrap_server_start_authenticate(res.step)?,
            Some(Err(e)) => return Err(e),
            None => return Err(Status::invalid_argument("No message received")),
        };

        let credential_response: CredentialResponse<OpaqueCipherSuite> = bincode::deserialize(
            &server_authenticate_start_result.server_authenticate_start_message[..],
        )
        .map_err(|_| Status::aborted("Unable to deserialize server message"))?;

        let client_login_finish_result = client_login_start_result
            .state
            .finish(
                password.as_bytes(),
                credential_response,
                ClientLoginFinishParameters::default(),
            )
            .map_err(|_| Status::unauthenticated("Authentication failed"))?;

        let client_login_finish_message: Vec<u8> =
            bincode::serialize(&client_login_finish_result.message)
                .map_err(|_| Status::aborted("Unable to serialize client message"))?;
        let authenticate_finish =
            Self::client_authenticate_finish(client_login_finish_message, user_id);
        tx.send(authenticate_finish)
            .await
            .expect("Handle weird error type");

        // Handle finish message
        let server_authenticate_finish_result = server_response.next().await;
        match server_authenticate_finish_result {
            Some(Ok(result)) => match result.step {
                Some(ServerAuthenticateStep::Finish(finish_response)) => {
                    Ok(client_login_finish_result.session_key.into())
                }
                Some(ServerAuthenticateStep::Start(_)) => {
                    Err(Status::invalid_argument("Message received out of order"))
                }
                None => Err(Status::invalid_argument("No message received")),
            },
            Some(Err(e)) => Err(e),
            None => Err(Status::invalid_argument("No message received")),
        }
    }

    /// Register a new user who has not yet interacted with the service and open
    /// a mutually authenticated session with the server described in the
    /// [`SessionConfig`].
    ///
    /// This only needs to be called once per user; future sessions can be
    /// created with [`Session::open()`].
    ///
    /// Output: If successful, returns an open [`Session`] between the specified
    /// [`UserId`] and the configured key server.
    pub async fn register<T: CryptoRng + RngCore>(
        client: &mut DamsRpcClient<Channel>,
        rng: &mut T,
        user_id: &UserId,
        password: &Password,
        config: &SessionConfig,
    ) -> Result<Self, SessionError> {
        let result = Self::do_register(
            client,
            rng,
            user_id,
            password,
            &config.server,
            &config.client_config,
        )
        .await;
        match result {
            Ok(_) => {
                return Self::open(client, rng, user_id, password, config).await;
            }
            Err(e) => {
                error!("{:?}", e);
                Err(SessionError::RegistrationFailed)
            }
        }
    }

    async fn do_register<T: CryptoRng + RngCore>(
        client: &mut DamsRpcClient<Channel>,
        rng: &mut T,
        user_id: &UserId,
        password: &Password,
        server: &KeyMgmtAddress,
        config: &self::Config,
    ) -> Result<Response<ServerRegisterFinish>, Status> {
        // Create channel to send messages to server after connection is established via RPC
        let (tx, rx) = mpsc::channel(2);
        let stream = ReceiverStream::new(rx);

        // Server returns its own channel that is uses to send responses
        let mut server_response = client.register(stream).await?.into_inner();

        let client_registration_start_result =
            ClientRegistration::<OpaqueCipherSuite>::start(rng, password.as_bytes())
                .map_err(|_| Status::aborted("RegistrationStart failed"))?;

        // Send start message to server
        let client_registration_start_message: Vec<u8> =
            bincode::serialize(&client_registration_start_result.message)
                .map_err(|_| Status::aborted("Unable to serialize client message"))?;
        let register_start =
            Self::client_register_start(client_registration_start_message, user_id);
        tx.send(register_start)
            .await
            .expect("Handle weird error type");

        let server_register_start_result = match server_response.next().await {
            Some(Ok(res)) => Self::unwrap_server_start_register(res.step)?,
            Some(Err(e)) => return Err(e),
            None => return Err(Status::invalid_argument("No message received")),
        };

        let server_register_start_message: RegistrationResponse<OpaqueCipherSuite> =
            bincode::deserialize(&server_register_start_result.server_register_start_message[..])
                .map_err(|_| Status::aborted("Unable to deserialize server message"))?;

        let client_finish_registration_result = client_registration_start_result
            .state
            .finish(
                rng,
                password.as_bytes(),
                server_register_start_message,
                ClientRegistrationFinishParameters::default(),
            )
            .map_err(|_| Status::aborted("RegistrationFinish failed"))?;

        let client_finish_registration_message: Vec<u8> =
            bincode::serialize(&client_finish_registration_result.message)
                .map_err(|_| Status::aborted("Unable to serialize client message"))?;
        let register_finish =
            Self::client_register_finish(client_finish_registration_message, user_id);
        tx.send(register_finish)
            .await
            .expect("Handle weird error type");

        // Handle finish message
        let server_register_finish_result = server_response.next().await;
        match server_register_finish_result {
            Some(Ok(result)) => match result.step {
                Some(ServerRegisterStep::Finish(finish_response)) => {
                    Ok(Response::new(finish_response))
                }
                Some(ServerRegisterStep::Start(_)) => {
                    Err(Status::invalid_argument("Message received out of order"))
                }
                None => Err(Status::invalid_argument("No message received")),
            },
            Some(Err(e)) => Err(e),
            None => Err(Status::invalid_argument("No message received")),
        }
    }

    /// Close a session.
    ///
    /// Outputs: None, if successful.
    pub fn close(self) -> Result<(), SessionError> {
        todo!()
    }

    // Helper functions
    fn client_register_start(message: Vec<u8>, user_id: &UserId) -> ClientRegister {
        ClientRegister {
            step: Some(RegisterStep::Start(ClientRegisterStart {
                client_register_start_message: message,
                user_id: user_id.as_bytes().to_vec(),
            })),
        }
    }

    fn client_register_finish(message: Vec<u8>, user_id: &UserId) -> ClientRegister {
        ClientRegister {
            step: Some(RegisterStep::Finish(ClientRegisterFinish {
                client_register_finish_message: message,
                user_id: user_id.as_bytes().to_vec(),
            })),
        }
    }

    fn unwrap_server_start_register(
        step: Option<ServerRegisterStep>,
    ) -> Result<ServerRegisterStart, Status> {
        match step {
            Some(ServerRegisterStep::Start(start_message)) => Ok(start_message),
            Some(ServerRegisterStep::Finish(_)) => {
                Err(Status::invalid_argument("Message received out of order"))
            }
            None => Err(Status::invalid_argument("No message received")),
        }
    }

    fn client_authenticate_start(message: Vec<u8>, user_id: &UserId) -> ClientAuthenticate {
        ClientAuthenticate {
            step: Some(AuthenticateStep::Start(ClientAuthenticateStart {
                client_authenticate_start_message: message,
                user_id: user_id.as_bytes().to_vec(),
            })),
        }
    }

    fn client_authenticate_finish(message: Vec<u8>, user_id: &UserId) -> ClientAuthenticate {
        ClientAuthenticate {
            step: Some(AuthenticateStep::Finish(ClientAuthenticateFinish {
                client_authenticate_finish_message: message,
                user_id: user_id.as_bytes().to_vec(),
            })),
        }
    }

    fn unwrap_server_start_authenticate(
        step: Option<ServerAuthenticateStep>,
    ) -> Result<ServerAuthenticateStart, Status> {
        match step {
            Some(ServerAuthenticateStep::Start(start_message)) => Ok(start_message),
            Some(ServerAuthenticateStep::Finish(_)) => {
                Err(Status::invalid_argument("Message received out of order"))
            }
            None => Err(Status::invalid_argument("No message received")),
        }
    }
}

#[derive(Debug, Error)]
#[allow(unused)]
pub enum Error {
    #[error("Session failed: {0:?}")]
    SessionFailed(#[from] SessionError),

    #[error("The request was rejected")]
    TransactionApprovalRequestFailed,
}

/// Connect to the gRPC client and return it to the client app.
///
/// The returned client should be passed to the remaining API functions.
pub async fn connect(address: String) -> Result<DamsRpcClient<Channel>, anyhow::Error> {
    DamsRpcClient::connect(address)
        .await
        .map_err(|_| anyhow!("Could not connect to server"))
}

/// Generate a new, distributed digital asset key with the given use
/// parameters for the [`UserId`], and compatible with the specified blockchain.
///
/// The [`UserId`] must be the same user who opened the [`Session`].
///
/// Output: If successful, returns the [`KeyInfo`] describing the newly created
/// key.
#[allow(unused)]
pub fn create_digital_asset_key(
    session: Session,
    user_id: UserId,
    blockchain: Blockchain,
    permission: impl UsePermission,
    restriction: impl UseRestriction,
) -> Result<KeyInfo, Error> {
    todo!()
}

/// Set an asset-owner-specified key policy for a delegated key.
///
/// User-specified policies can only be set for
/// [`SelfCustodial`](dams::keys::SelfCustodial) and
/// [`Delegated`](dams::keys::Delegated) key types. The [`KeyId`] must
/// correspond to a key owned by the [`UserId`], and the [`UserId`] must
/// match the user authenticated in the [`Session`].
///
/// Output: None, if successful.
#[allow(unused)]
pub fn set_user_key_policy(
    session: Session,
    user_id: UserId,
    key_id: KeyId,
    user_policy: UserPolicySpecification,
) -> Result<(), Error> {
    todo!()
}

/// Request a signature on a transaction from the key server.
///
/// Among the parameters in the [`TransactionApprovalRequest`], the [`KeyId`]
/// must correspond to a key owned by the [`UserId`], and the [`UserId`] must
/// match the user authenticated in the [`Session`].
///
/// Assumption: A [`TransactionApprovalRequest`] originates either with the
/// asset owner or a key fiduciary. This is cryptographically enforced with
/// an authenticated [`Session`] between the key server and one of the asset
/// owner or a key fiduciary. This request will fail if the calling party
/// is not from one of those entities.
///
/// Output: If successful, returns a [`TransactionSignature`] as specified in
/// the original [`TransactionApprovalRequest`] -- that is, over the
/// [`Transaction`](dams::transaction::Transaction), and using the key
/// corresponding to the [`KeyId`].
#[allow(unused)]
pub fn request_transaction_signature(
    session: Session,
    transaction_approval_request: TransactionApprovalRequest,
) -> Result<TransactionSignature, Error> {
    todo!()
}

/// Retrieve the public key info for all keys associated with the specified
/// user that are stored at the key server.
///
/// Implementation note: this material may be cached and retrieved from a
/// machine other than the key server.
///
/// The [`UserId`] must match the asset owner authenticated in the [`Session`].
/// This function cannot be used to retrieve keys for a different user.
///
/// Output: If successful, returns the [`KeyInfo`] for every key belonging to
/// the user.
#[allow(unused)]
pub fn retrieve_public_keys(session: Session, user_id: UserId) -> Result<Vec<KeyInfo>, Error> {
    todo!()
}

/// Retrieve the public key info for the specified key associated with the
/// user.
///
/// Implementation note: this material may be cached and retrieved from a
/// machine other than the key server.
///
/// The [`UserId`] must match the asset owner authenticated in the [`Session`],
/// and the [`KeyId`] must correspond to a key owned by the [`UserId`].
///
/// Output: If successful, returns the [`KeyInfo`] for the requested key.
#[allow(unused)]
pub fn retrieve_public_key_by_id(
    session: Session,
    user_id: UserId,
    key_id: &KeyId,
) -> Result<KeyInfo, Error> {
    todo!()
}

/// Retrieve the audit log from the key server for a specified asset owner;
/// optionally, filter for logs associated with the specified [`KeyId`].
///
/// The audit log includes context
/// about any action requested and/or taken on the digital asset key, including
/// which action was requested and by whom, the date, details about approval or
/// rejection from each key server, the policy engine, and each asset fiduciary
/// (if relevant), and any other relevant details.
///
/// The [`UserId`] must match the asset owner authenticated in the [`Session`],
/// and if specified, the [`KeyId`] must correspond to a key owned by the
/// [`UserId`].
///
/// Output: if successful, returns a [`String`] representation of the logs.
#[allow(unused)]
pub fn retrieve_audit_log(
    session: Session,
    user_id: UserId,
    key_id: Option<&KeyId>,
) -> Result<String, Error> {
    todo!()
}
