//! Blockchain abstraction.
//!
//! Includes options for types of blockchains and defines primitives based on those options.
//!

use serde::{Deserialize, Serialize};

/// Options for type of blockchain.
///
/// A blockchain option must be specified when creating or importing a digital asset key.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Blockchain {
    EVM,
}

/// Indicator trait to identify objects that represent a signature scheme.
///
/// TODO #43 (implementation, refactor): Move this definition to a crypto module and define signing operations
pub trait SignatureScheme {}

/// The ECDSA signature scheme
#[derive(Debug, Serialize, Deserialize)]
pub struct ECDSA;

impl SignatureScheme for ECDSA {}

impl Blockchain {
    /// Identify signature scheme that corresponds to each blockchain type.
    ///
    /// In particular, the blockchain accepts valid transactions that are signed under the given scheme.
    pub fn signature_scheme(&self) -> impl SignatureScheme {
        match self {
            Blockchain::EVM => ECDSA,
        }
    }
}
