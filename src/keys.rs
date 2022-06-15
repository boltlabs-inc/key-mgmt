//! High-level key types, including whole keys and shares of keys, and their
//! associated information.
//!
//! Additional information includes machine- and human-readable tags for keys
//! and types describing the various allowed use permissions and restrictions in
//! the system.

use crate::transaction::UserId;

/// Unique identifier for a key.
#[allow(unused)]
#[derive(Debug)]
pub struct KeyId;

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
    user_id: UserId,
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

/// A use permission is a type that defines the degree to which the asset owner
/// has delegated custody of a digital asset key or key share to another entity.
///
/// TODO (design): This abstraction relies on the design of [`Delegated`] and
/// [`Passive`] key types and their capabilities, which are open design
/// questions.
pub trait UsePermission {}

/// Use permission that assigns key custody to the asset owner. This permission
/// requires an asset owner to actively participate in any action involving the
/// digital asset key by authenticating with their password. The asset owner can
/// set a [`UserPolicySpecification`] to apply additional rules and requirements
/// for digital asset key usage.

#[derive(Debug)]
#[allow(unused)]
struct SelfCustodial {
    user_policy: UserPolicySpecification,
}
impl UsePermission for SelfCustodial {}

/// Use permission that delegates signing authority to a specified
/// delegated party. The asset owner can set a [`UserPolicySpecification`] to
/// apply additional rules and requirements for digital asset key usage.
///
/// TODO (design): Defining the specification for `Delegated` use permission
/// is an open design question. See also the note on [`UsePermission`].
///
/// TODO (design, implementation): Add a field describing the designated signing
/// authority / delegated party. Figure out how to represent such an authority
/// and how many might exist.
#[derive(Debug)]
#[allow(unused)]
struct Delegated {
    user_policy: UserPolicySpecification,
}
impl UsePermission for Delegated {}

/// Use permission that refers to a digital asset key that was created by
/// the Service Provider on behalf of an asset owner, i.e., the asset owner does
/// not have a registered account with the key servers. The Service Provider has
/// custody of the key, including completel signing authority, i.e., there is
/// no [`UserPolicySpecification`] set.
///
/// TODO (design): Defining the specification for `Passive` use permission is an
/// open design question. See also the note on [`UsePermission`].
///
/// TODO (design, implementation): Add a field describing the designated signing
/// authority. Figure out how to represent such an authority and how many might
/// exist.
#[derive(Debug)]
struct Passive;
impl UsePermission for Passive {}

/// Specification of a user-set policy. This describes the set of policies that an
/// asset owner can define around use of a digital asset key that are enforced
/// by the DAMS key servers. If the key servers find that a user-set policy has
/// been violated, they can require additional validation directly from the
/// asset owner.
///
/// TODO (design): Define the concrete policies this can encompass.
#[derive(Debug)]
pub struct UserPolicySpecification {}

/// A use restriction is a type that defines what entities have veto power over
/// the use of a digital asset key.
pub trait UseRestriction {}

/// Use restriction that assigns veto power to a given set of asset fiduciaries.
///
/// Assumption: This module will be used with a DAMS instantiation that has a
/// fixed set of asset fiduciaries, configured at system setup. The asset
/// fiduciaries will not change for different keys or different users.
///
/// TODO (implementation): create a config file with appropriate details about
/// the asset fiduciaries; make a constructor for this type that instantiates
/// based on that configuration.
#[derive(Debug)]
struct SharedControl;
impl UseRestriction for SharedControl {}

/// Use restriction that does not assign veto power to a given set of asset
/// fiduciaries; that is, given a valid, authenticated request to use a digital
/// asset key, no additional parties are consulted.
#[derive(Debug)]
struct Unilateral;
impl UseRestriction for Unilateral {}
