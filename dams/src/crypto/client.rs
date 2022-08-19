//! Wrapper functions around client-side cryptography.
//!
//! Each operation in this module is part of one or more workflows.

use crate::crypto::{OpaqueExportKey, StorageKey};

use rand::{CryptoRng, RngCore};

use super::{Encrypted, Secret};

/// Create an encrypted storage key. This is part of the registration flow and
/// is executed during a registration session with the
/// server. This key should be sent to the server for storage.
///
/// This must be run by the client.
/// It takes the following steps:
/// 1. Derive a master key from the [`OpaqueExportKey`]
/// 2. Generate a new [`StorageKey`] to encrypt stored data with
/// 3. Encrypt the storage key under the master key, using an AEAD scheme
/// 4. Return the encrypted storage key
#[allow(unused)]
pub fn create_and_encrypt_storage_key(
    rng: impl CryptoRng + RngCore,
    export_key: OpaqueExportKey,
) -> Encrypted<StorageKey> {
    todo!()
}

/// Create and encrypt a new secret. This is part of the
/// generate a new secret flow.
///
/// This must be run by the client. It takes the following steps:
/// 1. Generates a new secret
/// 2. Encrypt it under the [`StorageKey`], using an AEAD scheme
#[allow(unused)]
pub fn create_and_encrypt_secret(
    rng: impl CryptoRng + RngCore,
    storage_key: StorageKey,
) -> Encrypted<Secret> {
    todo!()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn create_and_encrypt_storage_key_not_implemented() {
        let rng = rand::thread_rng();
        let _ = create_and_encrypt_storage_key(rng, OpaqueExportKey);
    }

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn create_and_encrypt_secret_not_implemented() {
        let rng = rand::thread_rng();
        let _ = create_and_encrypt_secret(rng, StorageKey);
    }
}
