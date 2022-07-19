//! Digital asset keys and descriptions.
//!
//! Includes basic key types (both standard keys and shares of keys) and identifiers
//! and modifiers describing access control and custody.

use bytes::BytesMut;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Clone, Error, Serialize, Deserialize)]
pub enum UserError {}

/// Unique ID for a user. Assumption: this will be derived from an ID generated
/// by the Service Provider.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserId(String);

impl ToString for UserId {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl FromStr for UserId {
    type Err = UserError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(UserId(s.to_string()))
    }
}

impl UserId {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Universally unique identifier for a key.
#[allow(unused)]
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyId;

/// Public key portion of a digital asset key pair.
#[derive(Debug, Serialize, Deserialize)]
pub struct DigitalAssetPublicKey;

/// Convenient grouping of the non-secret components of a digital asset key
/// pair.
#[derive(Debug, Serialize, Deserialize)]
#[allow(unused)]
pub struct KeyInfo {
    user_id: UserId,
    key_id: KeyId,
    public_key: DigitalAssetPublicKey,
}

/// Wrapper around [`BytesMut`] to represent key material external to the system.
///
/// TODO #49 (design, implementation): Define key material properly.
#[derive(Debug, Serialize, Deserialize)]
#[allow(unused)]
pub struct KeyMaterial {
    key_material: BytesMut,
}
impl Default for KeyMaterial {
    fn default() -> Self {
        Self {
            key_material: BytesMut::with_capacity(32),
        }
    }
}

/// Digital asset key, parameterized by use permissions and restrictions.
/// This represents an asymmetric key pair with a public and private component.
///
/// TODO #19: add key material from the crypto library, when it exists.
/// This should hold an asymmetric key pair.
#[derive(Debug, Serialize, Deserialize)]
#[allow(unused)]
struct DigitalAssetKey<P, R>
where
    P: UsePermission,
    R: UseRestriction,
{
    permission: P,
    restriction: R,

    key_id: KeyId,
    user_id: UserId,
}

/// A use permission is a type that defines the degree to which the asset owner
/// has delegated custody of a digital asset key or key share to another entity.
///
/// TODO #28 (design): This abstraction relies on the design of [`Delegated`]
/// and [`Passive`] key types and their capabilities, which are open design
/// questions.
pub trait UsePermission {}

/// Use permission that assigns key custody to the asset owner. This permission
/// requires an asset owner to actively participate in any action involving the
/// digital asset key by authenticating with their password. The asset owner can
/// set a [`UserPolicySpecification`] to apply additional rules and requirements
/// for digital asset key usage.

#[derive(Debug, Serialize, Deserialize)]
#[allow(unused)]
pub struct SelfCustodial {
    user_policy: UserPolicySpecification,
}
impl UsePermission for SelfCustodial {}
impl Default for SelfCustodial {
    fn default() -> Self {
        Self {
            user_policy: UserPolicySpecification,
        }
    }
}

/// Use permission that delegates signing authority to a specified
/// delegated party. The asset owner can set a [`UserPolicySpecification`] to
/// apply additional rules and requirements for digital asset key usage.
///
/// TODO #28 (design): Defining the specification for `Delegated` use permission
/// is an open design question. See also the note on [`UsePermission`].
///
/// TODO #27 (design, implementation): Add a field describing the designated
/// signing authority / delegated party. Figure out how to represent such an
/// authority and how many might exist.
#[derive(Debug, Serialize, Deserialize)]
#[allow(unused)]
pub struct Delegated {
    user_policy: UserPolicySpecification,
}
impl UsePermission for Delegated {}

/// Use permission that refers to a digital asset key that was created by
/// the Service Provider on behalf of an asset owner, i.e., the asset owner does
/// not have a registered account with the key server. The Service Provider has
/// custody of the key, including complete signing authority, i.e., there is
/// no [`UserPolicySpecification`] set.
///
/// TODO #28 (design): Defining the specification for `Passive` use permission
/// is an open design question. See also the note on [`UsePermission`].
///
/// TODO #27 (design, implementation): Add a field describing the designated
/// signing authority. Figure out how to represent such an authority and how
/// many might exist.
#[derive(Debug, Serialize, Deserialize)]
pub struct Passive;
impl UsePermission for Passive {}

/// Specification of a user-set policy. This describes the set of policies that
/// an asset owner can define around use of a digital asset key that are
/// enforced by the DAMS key server. When a user-set policy is triggered, the
/// key server can seek additional authentication or confirmation directly
/// from the asset owner.
///
/// TODO #28 (design): Define the concrete policies this can encompass.
#[derive(Debug, Serialize, Deserialize)]
pub struct UserPolicySpecification;

/// A use restriction is a type that defines what entities have veto power over
/// the use of a digital asset key.
pub trait UseRestriction {}

/// Use restriction that assigns veto power to a given set of asset fiduciaries.
///
/// Assumption: This module will be used with a DAMS instantiation that has a
/// fixed set of asset fiduciaries, configured at system setup. The asset
/// fiduciaries will not change for different keys or different users.
///
/// TODO #29 (implementation): create a config file with appropriate details
/// about the asset fiduciaries; make a constructor for this type that
/// instantiates based on that configuration.
#[derive(Debug, Serialize, Deserialize)]
pub struct SharedControl;
impl UseRestriction for SharedControl {}

/// Use restriction that does not assign veto power to a given set of asset
/// fiduciaries; that is, given a valid, authenticated request to use a digital
/// asset key, no additional parties are consulted.
#[derive(Debug, Serialize, Deserialize)]
pub struct Unilateral;
impl UseRestriction for Unilateral {}
