//! Wrapper functions around client-side cryptography.
//!
//! Each operation in this module is part of one or more workflows.

use crate::crypto::{OpaqueExportKey, StorageKey};

use rand::{CryptoRng, RngCore};

/// Create an encrypted storage key. This is part of the registration flow and
/// is executed after completing the OPAQUE registration session with the
/// server. This key should be sent to the server for storage.
///
/// This must be run by the client.
/// It takes the following steps:
/// 1. Derive a master key from the [`OpaqueExportKey`]
/// 2. Generate a new [`StorageKey`] to encrypt stored data with
/// 3. Encrypt the storage key with the master key
/// 4. Return the encrypted storage key
///
/// TODO #113: Add encrypted storage key return type.
#[allow(unused)]
pub fn create_and_encrypt_storage_key(rng: impl CryptoRng + RngCore, export_key: OpaqueExportKey) {
    todo!()
}

/// Decrypt a storage key. This should be run as part of the subprotocol to
/// retrieve a storage key from the server.
///
/// This must be run by the client. It takes the following steps:
/// 1. Derive a master key from the [`OpaqueExportKey`]
/// 2. Decrypt the encrypted storage key using the master key
/// 3. Return the decrypted [`StorageKey`]
///
/// TODO #113: Add encrypted storage key parameter.
#[allow(unused)]
pub fn decrypt_storage_key(export_key: OpaqueExportKey) -> StorageKey {
    todo!()
}

/// Create and encrypt a new [`Secret`](super::Secret). This is part of the
/// generate a new secret flow.
///
/// This must be run by the client. It takes the following steps:
/// 1. Generates a new [`Secret`](super::Secret)
/// 2. Encrypt it under the [`StorageKey`]
///
/// TODO #113: Add encrypted secret return type.
#[allow(unused)]
pub fn create_and_encrypt_secret(rng: impl CryptoRng + RngCore, storage_key: StorageKey) {
    todo!()
}
