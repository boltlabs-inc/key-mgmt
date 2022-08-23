//! Wrapper functions around client-side cryptography.
//!
//! Each operation in this module is part of one or more workflows.

use crate::{
    crypto::{OpaqueExportKey, StorageKey},
    user::UserId,
};

use rand::{CryptoRng, RngCore};

use super::{Encrypted, KeyId, Secret};

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
    rng: &mut (impl CryptoRng + RngCore),
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
    rng: &mut (impl CryptoRng + RngCore),
    user_id: &UserId,
    key_id: &KeyId,
    storage_key: StorageKey,
) -> Encrypted<Secret> {
    todo!()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::{test::create_test_export_key, KeyId};

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn create_and_encrypt_storage_key_not_implemented() {
        let mut rng = rand::thread_rng();
        let export_key = create_test_export_key(&mut rng);
        let _ = create_and_encrypt_storage_key(&mut rng, export_key);
    }

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn create_and_encrypt_secret_not_implemented() {
        let mut rng = rand::thread_rng();
        let _ = create_and_encrypt_secret(&mut rng, &UserId::default(), &KeyId, StorageKey);
    }
}
