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
    crypto::KeyId,
    dams_rpc::dams_rpc_client::DamsRpcClient,
    keys::{KeyInfo, UsePermission, UseRestriction, UserPolicySpecification},
    transaction::{TransactionApprovalRequest, TransactionSignature},
    user::UserId,
};
use rand::{CryptoRng, RngCore};
use std::str::FromStr;
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
}

impl Default for DamsClient {
    fn default() -> Self {
        DamsClient {
            session_key: [0; 64],
        }
    }
}

#[allow(unused)]
impl DamsClient {
    /// Open a new mutually authenticated session between a previously
    /// registered user and a key server.
    ///
    /// Output: If successful, returns an open [`DamsClient`] between the specified
    /// [`UserId`] and the configured key server.
    pub async fn open<T: CryptoRng + RngCore>(
        client: &mut DamsRpcClient<Channel>,
        rng: &mut T,
        user_id: &UserId,
        password: &Password,
    ) -> Result<Self, DamsClientError> {
        let result = Self::authenticate(client, rng, user_id, password).await;
        match result {
            Ok(result) => {
                let session = DamsClient {
                    session_key: result,
                };
                Ok(session)
            }
            Err(e) => {
                error!("{:?}", e);
                Err(DamsClientError::AuthenticationFailed)
            }
        }
    }

    async fn authenticate<T: CryptoRng + RngCore>(
        client: &mut DamsRpcClient<Channel>,
        rng: &mut T,
        user_id: &UserId,
        password: &Password,
    ) -> Result<[u8; 64], DamsClientError> {
        authenticate::handle(client, rng, user_id, password).await
    }

    /// Register a new user who has not yet interacted with the service and open
    /// a mutually authenticated session with the server.
    ///
    /// This only needs to be called once per user; future sessions can be
    /// created with [`DamsClient::open()`].
    ///
    /// Output: If successful, returns an open [`DamsClient`] between the specified
    /// [`UserId`] and the configured key server.
    pub async fn register<T: CryptoRng + RngCore>(
        client: &mut DamsRpcClient<Channel>,
        rng: &mut T,
        user_id: &UserId,
        password: &Password,
    ) -> Result<Self, DamsClientError> {
        let result = register::handle(client, rng, user_id, password).await;
        match result {
            Ok(_) => Self::open(client, rng, user_id, password).await,
            Err(e) => {
                error!("{:?}", e);
                Err(DamsClientError::RegistrationFailed)
            }
        }
    }

    /// Close a session.
    ///
    /// Outputs: None, if successful.
    pub fn close(self) -> Result<(), DamsClientError> {
        todo!()
    }
}

/// Connect to the gRPC client and return it to the client app.
///
/// The returned client should be passed to the remaining API functions.
pub async fn connect(address: String) -> Result<DamsRpcClient<Channel>, DamsClientError> {
    // TODO #174 (design, implementation): determine whether the https link
    // is secure before passing to tonic
    if address.starts_with("https:") {
        Ok(DamsRpcClient::connect(address).await?)
    } else {
        Err(DamsClientError::HttpNotAllowed)
    }
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
    session: DamsClient,
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
/// match the user authenticated in the [`Session`].
///
/// Output: None, if successful.
#[allow(unused)]
pub fn set_user_key_policy(
    session: DamsClient,
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
    session: DamsClient,
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
/// The [`UserId`] must match the asset owner authenticated in the [`Session`].
/// This function cannot be used to retrieve keys for a different user.
///
/// Output: If successful, returns the [`KeyInfo`] for every key belonging to
/// the user.
#[allow(unused)]
pub fn retrieve_public_keys(
    session: DamsClient,
    user_id: UserId,
) -> Result<Vec<KeyInfo>, DamsClientError> {
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
    session: DamsClient,
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
/// The [`UserId`] must match the asset owner authenticated in the [`Session`],
/// and if specified, the [`KeyId`] must correspond to a key owned by the
/// [`UserId`].
///
/// Output: if successful, returns a [`String`] representation of the logs.
#[allow(unused)]
pub fn retrieve_audit_log(
    session: DamsClient,
    user_id: UserId,
    key_id: Option<&KeyId>,
) -> Result<String, DamsClientError> {
    todo!()
}
