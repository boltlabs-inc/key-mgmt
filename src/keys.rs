//! High-level key types, including whole keys and shares of keys, and their
//! associated information.
//!
//! Additional information includes machine- and human-readable tags for keys
//! and types describing the various allowed use permissions and restrictions in
//! the system.

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
/// digital asset key or key share. An authorization policy describes the degree
/// to which the asset owner has delegated custody to another entity.
///
/// TODO (design): This abstraction relies on the design of [`Delegated`] and
/// [`Passive`] key types and their capabilities, which is an open design
/// question.
pub trait UsePermission {}

/// Authorization policy that requires an asset owner to participate in any
/// action involving the digital asset key. The asset owner can set a
/// [`UserPolicySpecification`] to apply additional restrictions on digital
/// asset key usage.

#[derive(Debug)]
#[allow(unused)]
struct SelfCustodial {
    user_policy: UserPolicySpecification,
}
impl UsePermission for SelfCustodial {}

/// Authorization policy that delegates signing authority to a specified
/// delegated party. The asset owner can set a [`UserPolicySpecification`] to
/// apply additional restrictions on digital asset key usage.
///
/// TODO (design): Defining the specific authorization policy is an open design
/// question. See also the note on [`UsePermission`].
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

/// Authorization policy that refers to a digital asset key that was created
/// without active input from the asset owner. The entity with custody has
/// complete signing authority and does not get any [`UserPolicySpecification`]
/// or other custody-related input from the asset owner.
///
/// TODO (design): Defining the specific authorization policy is an open design
/// question. See also the note on [`UsePermission`].
///
/// TODO (design, implementation): Add a field describing the designated signing
/// authority. Figure out how to represent such an authority and how many might
/// exist.
#[derive(Debug)]
struct Passive;
impl UsePermission for Passive {}

/// Specification of a user policy. This describes the set of policies that an
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

/// Use restriction that assigns veto power to a set of asset fiduciaries.
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

/// Use restriction that limits veto power only to the asset owner; that is,
/// given a valid, authenticated request to use a digital asset key, no
/// additional parties are consulted.
#[derive(Debug)]
struct Unilateral;
impl UseRestriction for Unilateral {}
