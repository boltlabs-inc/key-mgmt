//! Models for data stored in the database

pub mod secrets;
pub mod user;

use std::fmt::Display;

use serde::{Deserialize, Serialize};

use crate::LockKeeperError;

/// Convenience type for serializing byte arrays as hex strings.
/// Add the `#[serde(try_from = "HexBytes", into = "HexBytes")]` attribute macro
/// above any type you'd like to serialize this way. This type should only be
/// used to serialize byte collections. It should not be used directly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct HexBytes(String);

impl Display for HexBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<T: AsRef<[u8]>> From<T> for HexBytes {
    fn from(bytes: T) -> Self {
        Self(hex::encode(bytes))
    }
}

impl TryFrom<HexBytes> for Vec<u8> {
    type Error = LockKeeperError;

    fn try_from(bytes: HexBytes) -> Result<Self, Self::Error> {
        Ok(hex::decode(bytes.0)?)
    }
}

impl<const N: usize> TryFrom<HexBytes> for [u8; N] {
    type Error = LockKeeperError;

    fn try_from(bytes: HexBytes) -> Result<Self, Self::Error> {
        let byte_array = hex::decode(bytes.0)?
            .try_into()
            // We know that we have a sequence of bytes so the only possible error is that it's the
            // wrong length
            .map_err(|_| LockKeeperError::InvalidKeyIdLength)?;
        Ok(byte_array)
    }
}
