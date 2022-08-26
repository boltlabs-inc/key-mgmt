//! Full implementation of the public API for the DAMS client library.
//!
//! This API is designed for use with a local client application - that is, an
//! application running directly on the device of an asset owner. The inputs
//! the asset owner provides should be passed directly to this API without being
//! sent to a separate machine.

mod authenticate;
mod register;

use dams::{
    blockchain::Blockchain,
    channel::ClientChannel,
    config::client::Config,
    crypto::KeyId,
    dams_rpc::dams_rpc_client::DamsRpcClient,
    keys::{KeyInfo, UsePermission, UseRestriction, UserPolicySpecification},
    transaction::{TransactionApprovalRequest, TransactionSignature},
    user::UserId,
};
use rand::{CryptoRng, RngCore};
use std::str::FromStr;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use tracing::error;

use crate::error::DamsClientError;

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

/// A `DamsClient` is an abstraction over client operations. It is used
/// to hold state, common infrastructure, and a `tonic` client object.
/// Authenticating to the DAMS returns a `DamsClient`, and this object
/// must be passed to the remaining API functions.
///
/// TODO #30: This abstraction needs a lot of design attention.
#[derive(Debug)]
#[allow(unused)]
pub struct DamsClient {
    session_key: [u8; 64],
    config: Config,
    tonic_client: DamsRpcClient<Channel>,
}

/// Options for actions the client can take.
pub(crate) enum ClientAction {
    Register,
    Authenticate,
}

#[allow(unused)]
impl DamsClient {
    /// Connect to the gRPC client and return it to the client app.
    ///
    /// The returned client should be stored as part of the [`DamsClient`]
    /// state.
    async fn connect(address: String) -> Result<DamsRpcClient<Channel>, DamsClientError> {
        if address.starts_with("https:") {
            Ok(DamsRpcClient::connect(address).await?)
        } else {
            Err(DamsClientError::HttpNotAllowed)
        }
    }

    /// Open a new mutually authenticated session between a previously
    /// registered user and a key server.
    ///
    /// Output: If successful, returns a [`DamsClient`] holding a
    /// `tonic`client object, a session key, and configuration information.
    pub async fn open<T: CryptoRng + RngCore>(
        rng: &mut T,
        user_id: &UserId,
        password: &Password,
        config: &Config,
    ) -> Result<Self, DamsClientError> {
        let server_location = config.server_location.as_str();
        let mut client = Self::connect(server_location.to_string()).await?;
        Self::authenticate(client, rng, user_id, password, config).await
    }

    async fn authenticate<T: CryptoRng + RngCore>(
        mut client: DamsRpcClient<Channel>,
        rng: &mut T,
        user_id: &UserId,
        password: &Password,
        config: &Config,
    ) -> Result<Self, DamsClientError> {
        let mut client_channel =
            Self::create_channel(&mut client, ClientAction::Authenticate).await?;
        let result = authenticate::handle(client_channel, rng, user_id, password).await;
        match result {
            Ok(result) => {
                let session = DamsClient {
                    session_key: result,
                    config: config.clone(),
                    tonic_client: client,
                };
                Ok(session)
            }
            Err(e) => {
                error!("{:?}", e);
                Err(DamsClientError::AuthenticationFailed)
            }
        }
    }

    /// Register a new user who has not yet interacted with the service and open
    /// a mutually authenticated session with the server.
    ///
    /// This only needs to be called once per user; future sessions can be
    /// created with [`DamsClient::open()`].
    ///
    /// Output: If successful, returns a [`DamsClient`] holding a
    /// `tonic`client object, a session key, and configuration information.
    pub async fn register<T: CryptoRng + RngCore>(
        rng: &mut T,
        user_id: &UserId,
        password: &Password,
        config: &Config,
    ) -> Result<Self, DamsClientError> {
        let server_location = config.server_location.as_str();
        let mut client = Self::connect(server_location.to_string()).await?;
        let mut client_channel = Self::create_channel(&mut client, ClientAction::Register).await?;
        let result = register::handle(client_channel, rng, user_id, password).await;
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

/// Generate a new, distributed digital asset key with the given use
/// parameters for the [`UserId`], and compatible with the specified blockchain.
///
/// The [`UserId`] must be the same user who opened the [`DamsClient`].
///
/// Output: If successful, returns the [`KeyInfo`] describing the newly created
/// key.
///
/// TODO #172: pass a DamsClient
#[allow(unused)]
pub fn create_digital_asset_key(
    user_id: UserId,
    blockchain: Blockchain,
    permission: impl UsePermission,
    restriction: impl UseRestriction,
) -> Result<KeyInfo, DamsClientError> {
    todo!()
}

/// Set an asset-owner-specified key policy for a delegated key.
///
/// User-specified policies can only be set for
/// [`SelfCustodial`](dams::keys::SelfCustodial) and
/// [`Delegated`](dams::keys::Delegated) key types. The [`KeyId`] must
/// correspond to a key owned by the [`UserId`], and the [`UserId`] must
/// match the user authenticated in the [`DamsClient`].
///
/// Output: None, if successful.
///
/// TODO #172: pass a DamsClient
#[allow(unused)]
pub fn set_user_key_policy(
    user_id: UserId,
    key_id: KeyId,
    user_policy: UserPolicySpecification,
) -> Result<(), DamsClientError> {
    todo!()
}

/// Request a signature on a transaction from the key server.
///
/// Among the parameters in the [`TransactionApprovalRequest`], the [`KeyId`]
/// must correspond to a key owned by the [`UserId`], and the [`UserId`] must
/// match the user authenticated in the [`DamsClient`].
///
/// Assumption: A [`TransactionApprovalRequest`] originates either with the
/// asset owner or a key fiduciary. This is cryptographically enforced with
/// an authenticated [`DamsClient`] between the key server and one of the asset
/// owner or a key fiduciary. This request will fail if the calling party
/// is not from one of those entities.
///
/// Output: If successful, returns a [`TransactionSignature`] as specified in
/// the original [`TransactionApprovalRequest`] -- that is, over the
/// [`Transaction`](dams::transaction::Transaction), and using the key
/// corresponding to the [`KeyId`].
///
/// TODO #172: pass a DamsClient
#[allow(unused)]
pub fn request_transaction_signature(
    transaction_approval_request: TransactionApprovalRequest,
) -> Result<TransactionSignature, DamsClientError> {
    todo!()
}

/// Retrieve the public key info for all keys associated with the specified
/// user that are stored at the key server.
///
/// Implementation note: this material may be cached and retrieved from a
/// machine other than the key server.
///
/// The [`UserId`] must match the asset owner authenticated in the
/// [`DamsClient`]. This function cannot be used to retrieve keys for a
/// different user.
///
/// Output: If successful, returns the [`KeyInfo`] for every key belonging to
/// the user.
///
/// TODO #172: pass a DamsClient
#[allow(unused)]
pub fn retrieve_public_keys(user_id: UserId) -> Result<Vec<KeyInfo>, DamsClientError> {
    todo!()
}

/// Retrieve the public key info for the specified key associated with the
/// user.
///
/// Implementation note: this material may be cached and retrieved from a
/// machine other than the key server.
///
/// The [`UserId`] must match the asset owner authenticated in the
/// [`DamsClient`], and the [`KeyId`] must correspond to a key owned by the
/// [`UserId`].
///
/// Output: If successful, returns the [`KeyInfo`] for the requested key.
///
/// TODO #172: pass a DamsClient
#[allow(unused)]
pub fn retrieve_public_key_by_id(
    user_id: UserId,
    key_id: &KeyId,
) -> Result<KeyInfo, DamsClientError> {
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
/// The [`UserId`] must match the asset owner authenticated in the
/// [`DamsClient`], and if specified, the [`KeyId`] must correspond to a key
/// owned by the [`UserId`].
///
/// Output: if successful, returns a [`String`] representation of the logs.
///
/// TODO #172: pass a DamsClient
#[allow(unused)]
pub fn retrieve_audit_log(
    user_id: UserId,
    key_id: Option<&KeyId>,
) -> Result<String, DamsClientError> {
    todo!()
}
