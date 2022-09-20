//! Full implementation of the public API for the DAMS client library.
//!
//! This API is designed for use with a local client application - that is, an
//! application running directly on the device of an asset owner. The inputs
//! the asset owner provides should be passed directly to this API without being
//! sent to a separate machine.

pub(crate) mod authenticate;
pub(crate) mod create_storage_key;
pub(crate) mod register;

pub mod arbitrary_secrets;

use crate::DamsClientError;
use dams::{
    blockchain::Blockchain,
    crypto::KeyId,
    keys::{KeyInfo, UsePermission, UseRestriction, UserPolicySpecification},
    transaction::{TransactionApprovalRequest, TransactionSignature},
    user::UserId,
};

/// Generate a new, distributed digital asset key with the given use
/// parameters for the [`UserId`], and compatible with the specified blockchain.
///
/// The [`UserId`] must be the same user who opened the [`crate::DamsClient`].
///
/// Output: If successful, returns the [`KeyInfo`] describing the newly created
/// key.
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
/// match the user authenticated in the [`crate::DamsClient`].
///
/// Output: None, if successful.
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
/// match the user authenticated in the [`crate::DamsClient`].
///
/// Assumption: A [`TransactionApprovalRequest`] originates either with the
/// asset owner or a key fiduciary. This is cryptographically enforced with
/// an authenticated [`crate::DamsClient`] between the key server and one of the
/// asset owner or a key fiduciary. This request will fail if the calling party
/// is not from one of those entities.
///
/// Output: If successful, returns a [`TransactionSignature`] as specified in
/// the original [`TransactionApprovalRequest`] -- that is, over the
/// [`Transaction`](dams::transaction::Transaction), and using the key
/// corresponding to the [`KeyId`].
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
/// [`crate::DamsClient`]. This function cannot be used to retrieve keys for a
/// different user.
///
/// Output: If successful, returns the [`KeyInfo`] for every key belonging to
/// the user.
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
/// [`crate::DamsClient`], and the [`KeyId`] must correspond to a key owned by
/// the [`UserId`].
///
/// Output: If successful, returns the [`KeyInfo`] for the requested key.
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
/// [`crate::DamsClient`], and if specified, the [`KeyId`] must correspond to a
/// key owned by the [`UserId`].
///
/// Output: if successful, returns a [`String`] representation of the logs.
#[allow(unused)]
pub fn retrieve_audit_log(
    user_id: UserId,
    key_id: Option<&KeyId>,
) -> Result<String, DamsClientError> {
    todo!()
}
