//! These commands describe the request APIs that the [local
//! client](crate::localclient) and remote client can make to each key server.
//!
//! Some open questions: some of these requests will be made directly by the
//! client, but others will be routed via a delegated party. An early assumption
//! was that we could derive the user for each request from the authenticated
//! channel, but I'm not sure what that looks like for delegated requests.
use crate::keys::{
    Delegated, DigitalAssetKeyShare, KeyId, KeyInfo, KeyTag, UsePermission, UseRestriction,
    UserPolicySpecification,
};
use crate::transaction::{TarId, TransactionSignature, UserId};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("The requested function is not yet implemented.")]
    NotImplemented,
}

/// Register a new user with the system: run OPAQUE to generate authentication
/// material and set up an encrypted channel.
///
/// TODO: This might return some kind of Session or Channel type.
#[allow(unused)]
pub fn register_user(user_id: UserId) -> Result<(), Error> {
    Err(Error::NotImplemented)
}

/// Open an encrypted channel with an existing system user.
///
/// TODO: This might return some kind of Session or Channel type.
#[allow(unused)]
pub fn open_session(user_id: UserId) -> Result<(), Error> {
    Err(Error::NotImplemented)
}

/// Create a new [`SelfCustodial`](crate::keys::SelfCustodial)
/// digital asset key share.
///
/// This request _must_ be recieved directly from the user.
#[allow(unused)]
pub fn create_self_custodial<R>(
    user_id: UserId,
    key_tag: Option<KeyTag>,
    // blockchain
    use_restriction: R,
    user_policy: UserPolicySpecification,
) -> Result<(), Error>
where
    R: UseRestriction,
{
    Err(Error::NotImplemented)
}

/// Create a new [`Delegated`](crate::keys::Delegated) digital asset key share.
///
/// The delegation configuration and any additional user policy specification is
/// specified in [`Delegated`].
///
/// This request _must_ be recieved directly from the user.
#[allow(unused)]
pub fn create_delegated<R>(
    user_id: UserId,
    key_tag: Option<KeyTag>,
    //blockchain,
    use_restriction: R,
    delegation: Delegated,
) -> Result<(), Error>
where
    R: UseRestriction,
{
    Err(Error::NotImplemented)
}

/// Update the [`UserPolicySpecification`] for an existing key.
///
/// This request _must_ be recieved directly from the user.
#[allow(unused)]
pub fn update_policy(
    user_id: UserId,
    key_id: KeyId,
    user_policy: UserPolicySpecification,
) -> Result<(), Error> {
    Err(Error::NotImplemented)
}

/// Set of possible outcomes from a transaction approval request.
#[derive(Debug)]
pub enum SignatureOutput {
    /// Request was approved, the [`TransactionSignature`] is the result.
    Approve(TransactionSignature),
    /// Request was rejected, the [`String`] provides error context.
    Reject(String),
    /// The request has not finished processing.
    Delay,
}

/// Retrieve a signature from an existing
/// [`TransactionApprovalRequest`](crate::transaction::
/// TransactionApprovalRequest).
///
/// This request might be recieved from the user or from a delegated party; the
/// behavior will change depending on which party sent the request and the
/// [`UsePermission`] of the key.
#[allow(unused)]
pub fn transaction_signature_export(
    key_id: KeyId,
    tar_id: TarId,
) -> Result<SignatureOutput, Error> {
    Err(Error::NotImplemented)
}

/// Import an existing key share into the system. The user policy and delegation
/// specifications are described in the [`DigitalAssetKeyShare`].
///
/// This request might be recieved from the user or from a delegated party; a
/// request for a [`Delegated`] or [`SelfCustodial`](crate::keys::SelfCustodial)
/// key must come directly from the user, but a
/// [`Passive`](crate::keys::Passive) key request must come from the delegated
/// party.
#[allow(unused)]
pub fn request_key_import<P, R>(
    key_id: KeyId,
    key_tag: Option<KeyTag>,
    key_share: DigitalAssetKeyShare<P, R>,
    //blockchain,
) -> Result<(), Error>
where
    P: UsePermission,
    R: UseRestriction,
{
    Err(Error::NotImplemented)
}

/// Retrieve a list of [`KeyId`]s and [`KeyTag`]s associated with the specified
/// user.
///
/// This request might be recieved from the user or from a delegated party.
/// TODO: define behavior for which keys the delegated party can access.
#[allow(unused)]
pub fn retrieve_keys(user_id: UserId, with_public_keys: bool) -> Result<Vec<KeyInfo>, Error> {
    Err(Error::NotImplemented)
}

/// Retrieve the public [`KeyInfo`] for the specified key.
///
/// This request might be recieved from the user or from a delegated party.
/// TODO: define behavior for which keys the delegated party can access.
#[allow(unused)]
pub fn retrieve_public_key(
    user_id: UserId,
    key_id: KeyId,
    with_public_keys: bool,
) -> Result<KeyInfo, Error> {
    Err(Error::NotImplemented)
}

/// Retrieve the audit log for the user, optionally filtered
/// for the specified key.
///
/// TODO: Does this request need to be made by the user, or can a service
/// provider also request it? Does the result change based on the requester?
#[allow(unused)]
pub fn retrieve_audit_log(user_id: UserId, key_id: Option<KeyId>) -> Result<String, Error> {
    Err(Error::NotImplemented)
}
