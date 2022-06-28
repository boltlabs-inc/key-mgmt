//! Full implementation of the public API for the DAMS remote client library.
//!
//! This API is designed for use with a remote client application - that is, an
//! application running the servers of a Service Provider.

use crate::blockchain::Blockchain;
use crate::{
    keys::{KeyId, KeyInfo, UseRestriction, UserId},
    transaction::{TransactionApprovalRequest, TransactionSignature},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {}

/// Generate a new, distributed, [`Passive`][crate::keys::Passive]
/// [`DigitalAssetKey`](crate::keys::DigitalAssetKey) with the given use
/// restrictions for the [`UserId`], and compatible with the specified
/// blockchain.
///
/// TODO #30 (design, implementation): Pass a session
#[allow(unused)]
pub fn create_passive_digital_asset_key(
    user_id: UserId,
    blockchain: Blockchain,
    restriction: impl UseRestriction,
) -> Result<KeyInfo, Error> {
    todo!()
}

/// Request a signature on a transaction from the key server.
///
/// Among the parameters in the [`TransactionApprovalRequest`], the [`KeyId`]
/// must correspond to a key owned by the [`UserId`].
/// The [`KeyId`] must correspond to a [`Passive`](crate::keys::Passive) or
/// [`Delegated`](crate::keys::Delegated)
/// key that have delegated signing authority to the key fiduciary authenticated
/// in the session.
///
/// Assumption: A [`TransactionApprovalRequest`] originates either with the
/// asset owner or the service provider. This is cryptographically enforced with
/// an authenticated session between the key server and one of the asset owner
/// or a key fiduciary. This request will fail if the calling party
/// is not from one of those entities.
///
/// TODO #30 (design, implementation): Pass a session
#[allow(unused)]
pub fn request_transaction_signature(
    transaction_approval_request: TransactionApprovalRequest,
) -> Result<TransactionSignature, Error> {
    todo!()
}

/// Retrieve the public key info for all keys associated with the specified
/// user from the key server.
///
/// The [`KeyId`] must correspond to a [`Passive`](crate::keys::Passive) or
/// [`Delegated`](crate::keys::Delegated) key that
/// have delegated signing authority to the key fiduciary authenticated in the
/// session. The [`KeyId`] must correspond to a key owned by the [`UserId`].
///
///
/// TODO #30 (design, implementation): Pass a session
#[allow(unused)]
pub fn retrieve_public_keys(user_id: UserId) -> Result<Vec<KeyInfo>, Error> {
    todo!()
}

/// Retrieve the public key info from the key server for the specified key
/// associated with the user.
///
/// The [`KeyId`] must correspond to a [`Passive`](crate::keys::Passive) or
/// [`Delegated`](crate::keys::Delegated) key that
/// have delegated signing authority to the key fiduciary authenticated in the
/// session. The [`KeyId`] must correspond to a key owned by the [`UserId`].
///
/// TODO #30 (design, implementation): Pass a session
#[allow(unused)]
pub fn retrieve_public_key_by_id(user_id: UserId, key_id: &KeyId) -> Result<KeyInfo, Error> {
    todo!()
}

/// Retrieve the audit log from the key server for a specified asset owner;
/// optionally, filter for logs associated with the specified [`KeyId`].
///
/// This will only retrieve logs for [`Passive`](crate::keys::Passive) and
/// [`Delegated`](crate::keys::Delegated) keys that
/// have delegated signing authority to the key fiduciary authenticated in the
/// session. If specified, the [`KeyId`] must correspond to a key owned by the
/// [`UserId`].
///
/// The audit log includes context
/// about any action requested and/or taken on the digital asset key, including
/// which action was requested and by whom, the date, details about approval or
/// rejection from each key server, the policy engine, and each asset fiduciary
/// (if relevant), and any other relevant details.
///
/// TODO #30 (design, implementation): Pass a session
#[allow(unused)]
pub fn retrieve_audit_log(user_id: UserId, key_id: Option<&KeyId>) -> Result<String, Error> {
    todo!()
}
