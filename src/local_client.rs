//! Full implementation of the public API for the DAMS local client library.
//!
//! This API is designed for use with a local client application - that is, an
//! application running directly on the device of an asset owner. The inputs
//! the asset owner provides should be passed directly to this API without being
//! sent to a separate machine.

use crate::{
    blockchain::Blockchain,
    keys::{KeyId, KeyInfo, UsePermission, UseRestriction, UserId, UserPolicySpecification},
    transaction::{TransactionApprovalRequest, TransactionSignature},
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionError {}

#[derive(Debug)]
pub struct Password;

/// Deployment details for a [`Session`].
///
/// Possible fields include: timeouts, key server IPs, PKI information,
/// preshared keys.
#[derive(Debug)]
pub struct SessionConfig;

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
}

#[allow(unused)]
impl Session {
    /// Open a new mutually authenticated session between a previously
    /// registered user and a key server described in the [`SessionConfig`].
    ///
    /// Returns a [`Result`] holding either an open [`Session`] if successful or a [`SessionError`] otherwise.
    pub fn open(
        user_id: UserId,
        password: Password,
        config: &SessionConfig,
    ) -> Result<Self, SessionError> {
        todo!()
    }

    /// Register a new user who has not yet interacted with the service and open
    /// a mutually authenticated session with the server described in the
    /// [`SessionConfig`].
    ///
    /// This only needs to be called once per user; future sessions can be
    /// created with [`Session::open()`].
    ///
    /// Returns a [`Result`] holding either an open [`Session`] if successful or a [`SessionError`] otherwise.
    pub fn register(
        user_id: UserId,
        password: Password,
        config: &SessionConfig,
    ) -> Result<Self, SessionError> {
        todo!()
    }

    /// Close a session.
    ///
    /// Returns a [`Result`] holding either an empty [`Ok()`] if successful or a [`SessionError`] otherwise.
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
/// Returns a [`Result`] holding either a [`KeyInfo`] object for the newly created key if successful or an [`Error`] otherwise.
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
///  Returns a [`Result`] holding either an empty [`Ok()`] if successful or an [`Error`] otherwise.
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
/// asset owner or the service provider. This is cryptographically enforced with
/// an authenticated [`Session`] between the key server and one of the asset
/// owner or a key fiduciary. This request will fail if the calling party
/// is not from one of those entities.
///
/// Returns a [`Result`] holding either a [`TransactionSignature`] object if successful or an [`Error`] otherwise.
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
/// Returns a [`Result`] holding either a vector of [`KeyInfo`] objects for this user's keys if successful or an [`Error`] otherwise.
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
/// Returns a [`Result`] holding either a [`KeyInfo`] object for the requested key if successful or an [`Error`] otherwise.
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
/// Returns a [`Result`] holding either a String representing the logs if successful or an [`Error`] otherwise.
#[allow(unused)]
pub fn retrieve_audit_log(
    session: Session,
    user_id: UserId,
    key_id: Option<&KeyId>,
) -> Result<String, Error> {
    todo!()
}
