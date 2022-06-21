//! Full implementation of the public API for the DAMS local client library.
//!

use crate::{
    keys::{KeyId, KeyInfo, UsePermission, UseRestriction, UserId, UserPolicySpecification},
    transaction::{TransactionApprovalRequest, TransactionSignature},
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionError {}

#[derive(Debug)]
pub struct Password;

/// Deployment details for a session.
///
/// Possible fields include: timeouts, key server IPs, PKI information,
/// preshared keys.
#[derive(Debug)]
pub struct SessionConfig;

/// A `Session` is an abstraction over a mutually authenticated,
/// confidential, ??
/// communication session between an asset owner and a key server
/// (specified in the [`SessionConfig`]). An open `Session` is
/// required to interact with the [`crate::localclient`] API.
///
/// A session can be ended manually, or it might time out and require
/// re-authentication (that is, creation of a new [`Session`]).
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
    pub fn register(
        user_id: UserId,
        password: Password,
        config: &SessionConfig,
    ) -> Result<Self, SessionError> {
        todo!()
    }

    /// Close a session.
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

/// Generate a new, distributed
/// [`DigitalAssetKey`](crate::keys::DigitalAssetKey) with the given use
/// parameters, and compatible with the specified blockchain.
///
/// TODO #25 (implementation): Pass the appropriate blockchain as a parameter.
#[allow(unused)]
pub fn create_digital_asset_key(
    session: Session,
    user_id: UserId,
    permission: impl UsePermission,
    restriction: impl UseRestriction,
) -> Result<KeyInfo, Error> {
    todo!()
}

/// Set an asset-owner-specified key policy for a delegated key.
///
/// User-specified policies can only be set for
/// [`SelfCustodial`](crate::keys::SelfCustodial) and
/// [`Delegated`](crate::keys::Delegated) key types.
#[allow(unused)]
pub fn set_user_key_policy(
    session: Session,
    user_id: UserId,
    key_id: KeyId,
    user_policy: UserPolicySpecification,
) -> Result<(), Error> {
    todo!()
}

/// Request approval for a transaction.
///
/// Assumption: A [`TransactionApprovalRequest`] originates either with the
/// asset owner or the service provider. This is cryptographically enforced with
/// an authenticated [`Session`] between the key server and one of the asset
/// owner or the service provider. This request will fail if the calling party
/// is not from one of those entities.
#[allow(unused)]
pub fn request_transaction_signature(
    session: Session,
    transaction_approval_request: TransactionApprovalRequest,
) -> Result<TransactionSignature, Error> {
    todo!()
}

/// Retrieve the public key info for all keys associated with the specified
/// user.
#[allow(unused)]
pub fn retrieve_public_keys(session: Session, user_id: UserId) -> Result<Vec<KeyInfo>, Error> {
    todo!()
}

/// Retrieve the public key info for the specified key associated with the user.
#[allow(unused)]
pub fn retrieve_public_key_by_id(
    session: Session,
    user_id: UserId,
    key_id: &KeyId,
) -> Result<KeyInfo, Error> {
    todo!()
}

/// Retrieve the audit log for a specified asset owner; optionally, filter for
/// logs associated with the specified [`KeyId`]. The audit log includes context
/// about any action requested and/or taken on the digital asset key, including
/// which action was requested and by whom, the date, details about approval or
/// rejection from each key server, the policy engine, and each asset fiduciary
/// (if relevant), and any other relevant details.
#[allow(unused)]
pub fn retrieve_audit_log(
    session: Session,
    user_id: UserId,
    key_id: Option<&KeyId>,
) -> Result<String, Error> {
    todo!()
}
