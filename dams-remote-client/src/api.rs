//! Full implementation of the public API for the DAMS remote client library.
//!
//! This API is designed for use with a remote client application - that is, an
//! application running on the servers of a Service Provider.

use dams::{
    blockchain::Blockchain,
    keys::{KeyId, KeyInfo, KeyMaterial, UseRestriction},
    transaction::{TransactionApprovalRequest, TransactionSignature},
    user::UserId,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {}

/// Register a passive user to the service provider authenticated in this session.
///
/// Assumption: a passive user only has [`Passive`][dams::keys::Passive] keys and has
/// not independently registered with the system, so
/// the service provider needs to call this function to indicate that they can take
/// actions on this user's behalf.
///
/// Output: none, if successful.
///
/// TODO #30 (design, implementation): Pass a session.
#[allow(unused)]
pub fn register_passive_user(user_id: UserId) -> Result<(), Error> {
    todo!()
}

/// Generate a new, distributed, [`Passive`][dams::keys::Passive]
/// digital asset key with the given use
/// restrictions for the [`UserId`], and compatible with the specified
/// blockchain. This must be called by the service provider over an
/// authenticated session.
///
/// Output: [`KeyInfo`] for the newly generated key, if successful.
///
/// TODO #30 (design, implementation): Pass a session.
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
/// The [`KeyId`] must correspond to a digital asset key in the system. If the
/// key is a [`Passive`](dams::keys::Passive) key, the caller must be the
/// service provider. If the key is a [`Delegated`](dams::keys::Delegated)
/// key, the caller must be a key fiduciary who has delegated signing authority
/// for the given key with [`KeyId`].
/// In either case, the caller must make the request over an authenticated
/// session.
///
/// Output: If successful, returns a [`TransactionSignature`] as specified in the
/// original [`TransactionApprovalRequest`] -- that is, over the
/// [`Transaction`](dams::transaction::Transaction), and using the key corresponding
/// to the [`KeyId`].
///
/// TODO #30 (design, implementation): Pass a session.
#[allow(unused)]
pub fn request_transaction_signature(
    transaction_approval_request: TransactionApprovalRequest,
) -> Result<TransactionSignature, Error> {
    todo!()
}

/// Import passive key material to the key servers.
///
/// The key must correspond to a [`Passive`][dams::keys::Passive]
/// digital asset key.
///
/// Assumption: The [`import_asset_key`] functionality is called by the service provider. This is cryptographically enforced with
/// an authenticated session between the key server and the service provider. This request will fail otherwise.
///
/// Output: If successful, returns the [`KeyInfo`] for the newly imported digital asset key.
///
/// TODO #30 (design, implementation): Pass a session.
#[allow(unused)]
pub fn import_asset_key(
    user_id: UserId,
    key_material: KeyMaterial,
    blockchain: Blockchain,
    restriction: impl UseRestriction,
) -> Result<KeyInfo, Error> {
    todo!()
}

/// Export passive key material from the key servers.
///
/// The [`KeyId`] must correspond to a [`Passive`][dams::keys::Passive]
/// digital asset key.
///
/// Assumption: The [`export_asset_key`] functionality is called by the service
/// provider. This is cryptographically enforced with an authenticated session
/// between the key server and the service provider. This request will fail otherwise.
///
/// Output: If successful, returns [`KeyMaterial`] corresponding to the requested key.
///
/// TODO #30 (design, implementation): Pass a session.
#[allow(unused)]
pub fn export_asset_key(user_id: UserId, key_id: &KeyId) -> Result<KeyMaterial, Error> {
    todo!()
}

/// Retrieve the public key info for all keys associated with the specified
/// user from the key server.
///
/// The [`KeyId`] must correspond to a digital asset key owned by the [`UserId`].
/// If the key is [`Passive`](dams::keys::Passive), the caller must be the
/// service provider.
/// If the key is [`Delegated`](dams::keys::Delegated), the caller must be a
/// key fiduciary with delegated signing authority for the key.
/// In either case, the request must be made by the caller over an authenticated
/// session.
///
/// Output: If successful, returns the [`KeyInfo`] for every key belonging to the
/// user and delegated (as described) to the caller.
///
/// TODO #30 (design, implementation): Pass a session.
#[allow(unused)]
pub fn retrieve_public_keys(user_id: UserId) -> Result<Vec<KeyInfo>, Error> {
    todo!()
}

/// Retrieve the public key info from the key server for the specified key
/// associated with the user.
///
/// The [`KeyId`] must correspond to a digital asset key owned by the [`UserId`].
/// If the key is [`Passive`](dams::keys::Passive), the caller must be the
/// service provider.
/// If the key is [`Delegated`](dams::keys::Delegated), the caller must be a
/// key fiduciary with delegated signing authority for the key.
/// In either case, the request must be made by the caller over an authenticated
/// session.
///
/// Output: If successful, returns the [`KeyInfo`] for the requested key.
///
/// TODO #30 (design, implementation): Pass a session.
#[allow(unused)]
pub fn retrieve_public_key_by_id(user_id: UserId, key_id: &KeyId) -> Result<KeyInfo, Error> {
    todo!()
}

/// Retrieve the audit log from the key server for a specified asset owner;
/// optionally, filter for logs associated with the specified [`KeyId`].
///
/// The [`KeyId`] must correspond to a digital asset key owned by the [`UserId`].
/// If the key is [`Passive`](dams::keys::Passive), the caller must be the
/// service provider.
/// If the key is [`Delegated`](dams::keys::Delegated), the caller must be a
/// key fiduciary with delegated signing authority for the key.
/// In either case, the request must be made by the caller over an authenticated
/// session.
///
/// The audit log includes context
/// about any action requested and/or taken on the digital asset key, including
/// which action was requested and by whom, the date, details about approval or
/// rejection from each key server, the policy engine, and each asset fiduciary
/// (if relevant), and any other relevant details.
///
/// Output: if successful, returns a [`String`] representation of the logs.
///
/// TODO #30 (design, implementation): Pass a session.
#[allow(unused)]
pub fn retrieve_audit_log(user_id: UserId, key_id: Option<&KeyId>) -> Result<String, Error> {
    todo!()
}
