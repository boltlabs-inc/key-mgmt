//! High-level key types, including whole keys and shares of keys, and their
//! associated information.
//!
//! Additional information includes machine- and human-readable tags for keys
//! and types describing the various allowed use permissions and restrictions in
//! the system.

use uuid::Uuid;

/// Unique identifier for a key.
#[allow(unused)]
#[derive(Debug)]
pub struct KeyId(Uuid);

/// Human-readable identifier for a key.
#[derive(Debug)]
pub struct KeyTag(String);

/// Public key portion of a digital asset key pair.
#[derive(Debug)]
pub struct DigitalAssetPublicKey;

/// Convenient grouping of the public components of a digital asset key pair.
#[derive(Debug)]
#[allow(unused)]
pub struct KeyInfo {
    key_id: KeyId,
    key_tag: Option<KeyTag>,
    public_key: DigitalAssetPublicKey,
}

/// Digital asset key, parameterized by use permissions and restrictions.
/// This represents a full key pair.
#[derive(Debug)]
#[allow(unused)]
struct DigitalAssetKey<P, R>
where
    P: UsePermission,
    R: UseRestriction,
{
    permission: P,
    restriction: R,

    key_info: KeyInfo,
}

/// A use permission is a type that defines an authorization policy for an
/// object. An authorization policy describes the degree to which the owner of
/// an object must particpate in actions involving the object; e.g. it describes
/// how much power the owner has delegated to another entity.
pub trait UsePermission {}

/// Authorization policy that requires a user to participate in any action
/// involving the associated object.
#[derive(Debug)]
struct SelfCustodial;
impl UsePermission for SelfCustodial {}

/// Authorization policy that allows a user to set a
/// [`UserPolicySpecification`], but delegates ultimate control to a specified
/// delegated party.
#[derive(Debug)]
#[allow(unused)]
struct Delegated {
    user_policy: UserPolicySpecification,
}
impl UsePermission for Delegated {}

/// Authorization policy that removes all user control over a key, passing it
/// entirely to a delegated party.
#[derive(Debug)]
struct Passive;
impl UsePermission for Passive {}

/// Specification of a user policy.
#[derive(Debug)]
pub struct UserPolicySpecification {}

/// A use restriction is a type that defines what entities have veto power over
/// the use of an object.
pub trait UseRestriction {}

/// Use restriction that assigns veto power to a set of asset fiduciaries.
#[derive(Debug)]
struct SharedControl;
impl UseRestriction for SharedControl {}

/// Use restriction that limits veto power only to the object owner; that is,
/// given a valid, authenticated request to take an action on an object, no
/// additional parties are consulted.
#[derive(Debug)]
struct Unilateral;
impl UseRestriction for Unilateral {}
