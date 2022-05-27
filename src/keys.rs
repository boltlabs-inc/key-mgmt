//! High-level key types, including whole keys and shares of keys, and their associated
//! information.
//! 
//! Additional information includes machine- and human-readable tags for keys and types
//! describing the various allowed use permissions and restrictions in the system.

use uuid::Uuid;

/// Unique identifier for a key.
#[allow(unused)]
struct KeyId(Uuid);

/// Human-readable identifier for a key.
pub struct KeyTag(String);

/// Digital asset key, parameterized by use permissions and restrictions.
/// This represents a "complete" key.
#[allow(unused)]
struct DigitalAssetKey<P, R>
where
    P: UsePermission,
    R: UseRestriction,
{
    permission: P,
    restriction: R,

    key_id: KeyId,
}

/// Set of authorization policies that define how a key can be accessed.
pub trait UsePermission {}

struct SelfCustodial;
impl UsePermission for SelfCustodial {}
struct Delegated;
impl UsePermission for Delegated {}
struct Passive;
impl UsePermission for Passive {}

/// Set of restriction policies that determine which parties can limit use of a key.
pub trait UseRestriction {}
struct SharedControl;
impl UseRestriction for SharedControl {}
struct Unilateral;
impl UseRestriction for Unilateral {}
