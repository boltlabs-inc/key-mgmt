//! Full implementation of the public API for the DAMS local client library.
//!
//! This API is designed for use with a local client application - that is, an
//! application running directly on the device of an asset owner. The inputs
//! the asset owner provides should be passed directly to this API without being
//! sent to a separate machine.

use crate::{
    blockchain::Blockchain,
    keys::{KeyId, KeyInfo, UsePermission, UseRestriction, UserId, UserPolicySpecification},
    offer_abort,
    transaction::{TransactionApprovalRequest, TransactionSignature},
};
use dialectic_reconnect::Backoff;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters,
};
use rand::{CryptoRng, RngCore};
use std::fmt::{Display, Formatter};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use crate::client::Config;
use crate::config::opaque::OpaqueCipherSuite;
use crate::key_mgmt::client::connect;
use crate::protocol::Party::Client;
use crate::protocol::{AuthStart, RegisterStart};
use crate::transport::KeyMgmtAddress;
use thiserror::Error;
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
            client_config: Config {
                backoff: Backoff::with_delay(Duration::from_secs(1)),
                connection_timeout: None,
                max_pending_connection_retries: 4,
                message_timeout: Duration::from_secs(60),
                max_message_length: 1024 * 16,
                max_note_length: 0,
                trust_certificate: Some(PathBuf::from("tests/gen/localhost.crt")),
            },
            server: KeyMgmtAddress::from_str("keymgmt://localhost").unwrap(),
        }
    }
}

/// A `Session` is an abstraction over a
/// communication session between an asset owner and a key server
/// that provides mutual authentication, confidentiality, and integrity.
/// An open `Session` is
/// required to interact with the [`crate::local_client`] API.
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
    /// Output: If successful, returns an open [`Session`] between the specified [`UserId`]
    /// and the configured key server.
    pub async fn open<T: CryptoRng + RngCore>(
        rng: &mut T,
        user_id: &UserId,
        password: &Password,
        config: &SessionConfig,
    ) -> Result<Self, SessionError> {
        let result = Self::authenticate(
            rng,
            user_id,
            password,
            &config.server,
            &config.client_config,
        )
        .await;
        return match result {
            Ok(result) => {
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
        };
    }

    async fn authenticate<T: CryptoRng + RngCore>(
        rng: &mut T,
        user_id: &UserId,
        password: &Password,
        server: &KeyMgmtAddress,
        config: &self::Config,
    ) -> Result<[u8; 64], anyhow::Error> {
        // Connect with the server...
        let (_session_key, chan) = connect(config, server)
            .await
            .map_err(|_| SessionError::ServerConnectionFailed)?;

        // ...and select the Authenticate session
        let chan = chan
            .choose::<3>()
            .await
            .map_err(|_| SessionError::SelectAuthenticateFailed)?;

        let client_login_start_result =
            ClientLogin::<OpaqueCipherSuite>::start(rng, password.as_bytes())
                .map_err(|_| SessionError::LoginStartFailed)?;

        let chan = chan
            .send(AuthStart::new(
                client_login_start_result.message,
                user_id.clone(),
            ))
            .await
            .map_err(|_| SessionError::AuthStartFailed)?;

        offer_abort!(in chan as Client);

        let (auth_start_received, chan) = chan
            .recv()
            .await
            .map_err(|_| SessionError::AuthStartFailed)?;

        let client_login_finish_result = client_login_start_result
            .state
            .finish(
                password.as_bytes(),
                auth_start_received,
                ClientLoginFinishParameters::default(),
            )
            .map_err(|_| SessionError::AuthenticationFailed)?;

        chan.send(client_login_finish_result.message)
            .await
            .map_err(|_| SessionError::AuthFinishFailed)?;

        Ok(client_login_finish_result.session_key.into())
    }

    /// Register a new user who has not yet interacted with the service and open
    /// a mutually authenticated session with the server described in the
    /// [`SessionConfig`].
    ///
    /// This only needs to be called once per user; future sessions can be
    /// created with [`Session::open()`].
    ///
    /// Output: If successful, returns an open [`Session`] between the specified [`UserId`]
    /// and the configured key server.
    pub async fn register<T: CryptoRng + RngCore>(
        rng: &mut T,
        user_id: &UserId,
        password: &Password,
        config: &SessionConfig,
    ) -> Result<Self, SessionError> {
        let result = Self::do_register(
            rng,
            user_id,
            password,
            &config.server,
            &config.client_config,
        )
        .await;
        match result {
            Ok(_) => {
                return Self::open(rng, user_id, password, config).await;
            }
            Err(e) => {
                error!("{:?}", e);
                Err(SessionError::RegistrationFailed)
            }
        }
    }

    async fn do_register<T: CryptoRng + RngCore>(
        rng: &mut T,
        user_id: &UserId,
        password: &Password,
        server: &KeyMgmtAddress,
        config: &self::Config,
    ) -> Result<(), anyhow::Error> {
        // Connect with the server...
        let (_session_key, chan) = connect(config, server)
            .await
            .map_err(|_| SessionError::ServerConnectionFailed)?;

        // ...and select the Register session
        let chan = chan
            .choose::<1>()
            .await
            .map_err(|_| SessionError::SelectRegisterFailed)?;

        let client_registration_start_result =
            ClientRegistration::<OpaqueCipherSuite>::start(rng, password.as_bytes())
                .map_err(|_| SessionError::RegisterStartFailed)?;

        let chan = chan
            .send(RegisterStart::new(
                client_registration_start_result.message,
                user_id.clone(),
            ))
            .await
            .map_err(|_| SessionError::RegisterStartFailed)?;

        offer_abort!(in chan as Client);

        let (register_start_received, chan) = chan
            .recv()
            .await
            .map_err(|_| SessionError::RegisterStartFailed)?;

        let client_finish_registration_result = client_registration_start_result
            .state
            .finish(
                rng,
                password.as_bytes(),
                register_start_received,
                ClientRegistrationFinishParameters::default(),
            )
            .map_err(|_| SessionError::RegisterFinishFailed)?;

        chan.send(client_finish_registration_result.message)
            .await
            .map_err(|_| SessionError::RegisterFinishFailed)?
            .close();

        Ok(())
    }

    /// Close a session.
    ///
    /// Outputs: None, if successful.
    pub fn close(self) -> Result<(), SessionError> {
        todo!()
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

/// Generate a new, distributed digital asset key with the given use
/// parameters for the [`UserId`], and compatible with the specified blockchain.
///
/// The [`UserId`] must be the same user who opened the [`Session`].
///
/// Output: If successful, returns the [`KeyInfo`] describing the newly created key.
///
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
/// [`SelfCustodial`](crate::keys::SelfCustodial) and
/// [`Delegated`](crate::keys::Delegated) key types. The [`KeyId`] must
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
/// Output: If successful, returns a [`TransactionSignature`] as specified in the
/// original [`TransactionApprovalRequest`] -- that is, over the
/// [`Transaction`](crate::transaction::Transaction), and using the key corresponding
/// to the [`KeyId`].
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
/// Output: If successful, returns the [`KeyInfo`] for every key belonging to the user.
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
