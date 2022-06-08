//! These commands describe the request APIs that the [local client](crate::localclient)
//! and remote client can make to each key server.
//!
//! Some open questions: some of these requests will be made directly by the client, but
//! others will be routed via a delegated party. An early assumption was that we could
//! derive the user for each request from the authenticated channel, but I'm not sure what
//! that looks like for delegated requests.
//!
//!
//!

use crate::keys::{
    Delegated, DigitalAssetKeyShare, KeyId, KeyTag, UsePermission, UseRestriction,
    UserPolicySpecification,
};
use crate::transaction::{TarId, UserId};

/// Parameters for a request to create a new [`SelfCustodial`](crate::keys::SelfCustodial)
/// digital asset key share.
///
/// This request _must_ be recieved directly from the user.
#[derive(Debug)]
#[allow(unused)]
pub struct CreateSelfCustodial<R: UseRestriction> {
    key_tag: Option<KeyTag>,
    // blockchain
    use_restriction: R,
    user_policy: UserPolicySpecification,
}

/// Parameters for a request to create a new [`Delegated`](crate::keys::Delegated)
/// digital asset key share.
///
/// The delegation configuration and any additional user policy specification is
/// specified in [`Delegated`].
///
/// This request _must_ be recieved directly from the user.
#[derive(Debug)]
#[allow(unused)]
pub struct CreateDelegated<R: UseRestriction> {
    key_tag: Option<KeyTag>,
    //blockchain,
    use_restriction: R,
    delegation: Delegated,
}

/// Parameters for a request to update the [`UserPolicySpecification`] for an
/// existing key.
///
/// This request _must_ be recieved directly from the user.
#[derive(Debug)]
#[allow(unused)]
pub struct UpdatePolicy {
    key_id: KeyId,
    user_policy: UserPolicySpecification,
}

/// Parameters for a request to retrieve a signature from an existing
/// [`TransactionApprovalRequest`](crate::transaction::TransactionApprovalRequest).
///
/// This request might be recieved from the user or from a delegated party; the
/// behavior will change depending on which party sent the request and the
/// [`UsePermission`] of the key.
#[derive(Debug)]
#[allow(unused)]
pub struct TransactionSignatureExport {
    key_id: KeyId,
    tar_id: TarId,
}

/// Parameters for a request to import an existing key share into the system. The
/// user policy and delegation specifications are described in the [`DigitalAssetKeyShare`].
///
/// This request might be recieved from the user or from a delegated party; a
/// request for a [`Delegated`] or [`SelfCustodial`](crate::keys::SelfCustodial)
/// key must come directly from the user, but a [`Passive`](crate::keys::Passive)
/// key request must come from the delegated party.
#[derive(Debug)]
#[allow(unused)]
pub struct RequestKeyImport<P, R>
where
    P: UsePermission,
    R: UseRestriction,
{
    key_id: KeyId,
    key_tag: Option<KeyTag>,
    key_share: DigitalAssetKeyShare<P, R>,
    //blockchain,
}

/// Parameters for a request to retrieve a list of [`KeyId`]s and [`KeyTag`]s
/// associated with the specified user.
///
/// This request might be recieved from the user or from a delegated party.
/// TODO: define behavior for which keys the delegated party can access.
#[derive(Debug)]
#[allow(unused)]
pub struct RetrieveKeys {
    user_id: UserId,
    with_public_keys: bool,
}

/// Parameters for a request to retrieve the public [`KeyInfo`] for the specified key.
///
/// This request might be recieved from the user or from a delegated party.
/// TODO: define behavior for which keys the delegated party can access.
#[derive(Debug)]
#[allow(unused)]
pub struct RetrievePublicKey {
    user_id: UserId,
    key_id: KeyId,
    with_public_keys: bool,
}

/// Parameters for a request to retrieve the audit log for the user, optionally filtered
/// for the specified key.
///
/// TODO: Does this request need to be made by the user, or can a service provider also
/// request it? Does the result change based on the requester?
#[derive(Debug)]
#[allow(unused)]
pub struct RetrieveAuditLog {
    user_id: UserId,
    key_id: Option<KeyId>,
}
