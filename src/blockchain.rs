//! Blockchain abstraction
//!
//! Includes options for types of blockchains and defines primitives based on those options
//!

use serde::{Deserialize, Serialize};

/// Options for type of blockchain
///
/// A blockchain option must be specified when creating or importing a [`DigitalAssetKey`]
#[derive(Debug, Serialize, Deserialize)]
pub enum Blockchain {
    EVM,
}

/// A signature scheme that uses a specific signature algorithm
///
/// All specific signature scheme structs should implement this trait and define their signature algorithms there
pub trait SignatureScheme {}

/// The ECDSA signature scheme
#[derive(Debug, Serialize, Deserialize)]
pub struct ECDSA;

impl SignatureScheme for ECDSA {}

impl Blockchain {
    /// Identify signature scheme that corresponds to each blockchain type
    pub fn signature_scheme(&self) -> impl SignatureScheme {
        match self {
            Blockchain::EVM => ECDSA,
        }
    }
}
