//! Application-specific cryptographic types and operations.
//!
//! Defines and implements keys and secret types, and the appropriate
//! transformations between them. The [`client`] submodule provides wrappers
//! around larger blocks of client-side cryptography.

use std::{marker::PhantomData, string::FromUtf8Error};

use bytes::Bytes;
use chacha20poly1305::{
    aead::{Aead, Payload},
    AeadCore, ChaCha20Poly1305, KeyInit,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::user::UserId;

pub mod client;

/// Errors that arise in the cryptography module.
///
/// Implementation note: this is not necessarily exhaustive yet - more variants
/// may be added as the module is implemented.
#[derive(Debug, Clone, Copy, Error)]
pub enum CryptoError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
}

/// The associated data used in [`Encrypted`] AEAD
/// ciphertexts and (TODO #130: HKDF) key derivations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct AssociatedData(String);

impl Default for AssociatedData {
    fn default() -> Self {
        Self(String::from("Version 0.1. "))
    }
}

impl TryFrom<Vec<u8>> for AssociatedData {
    type Error = FromUtf8Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(String::from_utf8(bytes)?))
    }
}

impl From<&AssociatedData> for Vec<u8> {
    fn from(associated_data: &AssociatedData) -> Self {
        associated_data.0.as_bytes().to_vec()
    }
}

/// A ciphertext representing an object of type `T`, encrypted under AEAD (TODO
/// #107: encryption scheme).
///
/// Implementation note: there may be additional fields in this struct or the
/// types might change.
#[allow(unused)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Encrypted<T> {
    ciphertext: Vec<u8>,
    associated_data: AssociatedData,
    nonce: chacha20poly1305::Nonce,
    original_type: PhantomData<T>,
}

/// A well-formed symmetric encryption key for the  authenticated encryption
/// with associated data (AEAD) scheme (TODO #107: specify encryption scheme).
#[derive(Debug, Clone)]
struct EncryptionKey(chacha20poly1305::Key);

#[allow(unused)]
impl EncryptionKey {
    /// Generate a new ChaCha20Poly1305 encryption key using their generation
    /// function.
    fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self(ChaCha20Poly1305::generate_key(rng))
    }
}

#[allow(unused)]
impl<T> Encrypted<T>
where
    T: From<Vec<u8>>,
    Vec<u8>: From<T>,
{
    /// Encrypt the `T` under the [`AeadKey`] with the [`AssociatedData`].
    fn encrypt(
        rng: &mut (impl CryptoRng + RngCore),
        enc_key: &EncryptionKey,
        object: T,
        associated_data: &AssociatedData,
    ) -> Result<Encrypted<T>, CryptoError> {
        // Set up cipher with key
        let cipher = ChaCha20Poly1305::new(&enc_key.0);

        // Format inputs for encryption
        let nonce = ChaCha20Poly1305::generate_nonce(rng);
        let ad_vec: Vec<u8> = associated_data.into();
        let payload = Payload {
            msg: &Vec::from(object),
            aad: &ad_vec,
        };

        // Encrypt!
        let ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok(Self {
            ciphertext,
            associated_data: associated_data.clone(),
            nonce,
            original_type: PhantomData,
        })
    }

    /// Decrypt the ciphertext to a `T`.
    ///
    /// Raises a [`CryptoError::DecryptionFailed`] if decryption fails.
    fn decrypt(self, enc_key: &EncryptionKey) -> Result<T, CryptoError> {
        // Set up cipher with key
        let cipher = ChaCha20Poly1305::new(&enc_key.0);

        // Format ciphertext and associated data
        let ad_vec: Vec<u8> = (&self.associated_data).into();
        let payload = Payload {
            msg: self.ciphertext.as_ref(),
            aad: &ad_vec,
        };

        // Decrypt!
        let plaintext = cipher
            .decrypt(&self.nonce, payload)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        Ok(plaintext.into())
    }
}

impl Encrypted<Secret> {
    /// Decrypt a secret. This should be run as part of the subprotocol to
    /// retrieve a secret from the server.
    ///
    /// This must be run by the client.
    pub fn decrypt_secret(self, _storage_key: StorageKey) -> Secret {
        todo!()
    }
}

impl Encrypted<StorageKey> {
    /// Decrypt a storage key. This should be run as part of the subprotocol to
    /// retrieve a storage key from the server.
    ///
    /// This must be run by the client. It takes the following steps:
    /// 1. Derive a master key from the [`OpaqueExportKey`]
    /// 2. Decrypt the encrypted storage key using the master key
    /// 3. Return the decrypted [`StorageKey`]
    pub fn decrypt_storage_key(self, _export_key: OpaqueExportKey) -> StorageKey {
        todo!()
    }
}

/// An export key is secure key material produced as client output from OPAQUE.
///
/// This uses standardized naming, but is _not_ directly used as an encryption
/// key in this system. Instead, the client uses it to derive a master key.
///
/// This key should not be stored or saved beyond the lifetime of a single
/// authentication session.
/// It should never be sent to the server or passed out to the local calling
/// application.
///
/// Implementation note: this will be a wrapper around `opaque_ke`'s
/// `export_key` field in the
/// [ClientRegistrationFinishResult](opaque_ke::ClientRegistrationFinishResult)
/// and corresponding registration result.
#[allow(unused)]
#[derive(Debug)]
pub struct OpaqueExportKey;

impl OpaqueExportKey {
    /// Derive a [`MasterKey`] from the export key.
    #[allow(unused)]
    fn derive_master_key(&self) -> MasterKey {
        todo!()
    }
}

/// The master key is a default-length symmetric key for an AEAD (TODO #107:
/// encryption scheme).
///
/// It is used by the client to securely encrypt their [`StorageKey`]. It should
/// not be stored or saved beyond the lifetime of a single authentication
/// session. It should never be sent to the server or passed out to the local
/// calling application.
#[allow(unused)]
#[derive(Debug)]
struct MasterKey;

#[allow(unused)]
impl MasterKey {
    /// Encrypt the given [`StorageKey`] under an AEAD scheme (TODO #107:
    /// describe).
    fn encrypt_storage_key(self, storage_key: StorageKey) -> Encrypted<StorageKey> {
        todo!()
    }
}

/// A storage key is a default-length symmetric key for (TODO #107: encryption
/// scheme) used to encrypt stored data.
///
/// It generated by the client and should never be revealed to the server or the
/// calling application.
/// It should not be stored or saved beyond the lifetime of a single
/// authentication session.
#[allow(unused)]
#[derive(Debug)]
pub struct StorageKey;

#[allow(unused)]
impl StorageKey {
    /// Generate a new 32-byte [`StorageKey`].
    fn generate() -> Self {
        todo!()
    }

    /// Encrypt the given [`Secret`] under an AEAD scheme (TODO #107:
    /// describe).
    fn encrypt_data(self, secret: &Secret) -> Encrypted<Secret> {
        todo!()
    }
}

/// Universally unique identifier for a secret.
#[allow(unused)]
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyId;

#[allow(unused)]
impl KeyId {
    /// Generate a new, random `KeyId` for the given [`UserId`].
    ///
    /// This is called by the key server.
    fn generate(rng: impl CryptoRng + RngCore, user_id: UserId) -> Self {
        todo!()
    }
}

/// An arbitrary secret.
///
/// This is generated by the client and should never be revealed to the server.
#[derive(Debug, Serialize, Deserialize)]
pub struct Secret {
    /// The actual bytes of secret material.
    material: Bytes,
    /// Additional context about the secret.
    associated_data: AssociatedData,
}

#[allow(unused)]
impl Secret {
    /// Generate a new secret of length `len`.
    fn generate(rng: impl CryptoRng + RngCore, len: u32, user_id: UserId, key_id: KeyId) -> Self {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::{rngs::ThreadRng, Rng};

    #[test]
    fn associated_data_to_vec_u8_conversion_works() {
        let test_strings = [
            "A random string to test conversion",
            "",
            "0123456789",
            "the quick brown fox jumps over the lazy dog",
            "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG",
        ];

        for test in test_strings {
            let data = AssociatedData(test.to_string());
            let data_vec: Vec<u8> = (&data).into();
            let output_data: AssociatedData = data_vec.try_into().unwrap();

            assert_eq!(data, output_data)
        }
    }

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn derive_master_key_not_implemented() {
        let _master_key = OpaqueExportKey.derive_master_key();
    }

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn encrypt_storage_key_not_implemented() {
        let _encrypted_storage_key = MasterKey.encrypt_storage_key(StorageKey);
    }

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn storage_key_generation_not_implemented() {
        let _storage_key = StorageKey::generate();
    }

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn data_encryption_not_implemented() {
        let thread_rng = rand::thread_rng();
        let user_id = UserId::default();
        let secret = Secret::generate(thread_rng, 32, user_id, KeyId);
        let _encrypted_secret = StorageKey.encrypt_data(&secret);
    }

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn secret_generation_not_implemented() {
        let thread_rng = rand::thread_rng();
        let user_id = UserId::default();
        let _secret = Secret::generate(thread_rng, 32, user_id, KeyId);
    }

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn key_id_generation_not_implemented() {
        let thread_rng = rand::thread_rng();
        let _key_id = KeyId::generate(thread_rng, UserId::default());
    }

    fn random_bytes(rng: &mut ThreadRng) -> Vec<u8> {
        Vec::from_iter(
            std::iter::repeat_with(|| rng.gen())
                .take(64)
                .collect::<Vec<u8>>(),
        )
    }

    /// Generates random bytes, encrypts them, and returns them along with the
    /// key used for encryption.
    fn encrypt_random_bytes() -> (Vec<u8>, Encrypted<Vec<u8>>, EncryptionKey) {
        let mut rng = rand::thread_rng();
        let bytes = random_bytes(&mut rng);
        let enc_key = EncryptionKey::new(&mut rng);
        let encrypted_bytes = Encrypted::encrypt(
            &mut rng,
            &enc_key,
            bytes.clone(),
            &AssociatedData::default(),
        )
        .unwrap();

        (bytes, encrypted_bytes, enc_key)
    }

    #[test]
    fn encryption_not_obviously_broken() {
        let (bytes, encrypted_bytes, _) = encrypt_random_bytes();
        assert_ne!(bytes, encrypted_bytes.ciphertext);
    }

    #[test]
    fn decryption_works() {
        let (bytes, encrypted_bytes, enc_key) = encrypt_random_bytes();
        let decrypted_bytes = encrypted_bytes.decrypt(&enc_key).unwrap();

        assert_eq!(bytes, decrypted_bytes);
    }

    #[test]
    fn decryption_fails_with_wrong_key() {
        let (_, encrypted_bytes, _) = encrypt_random_bytes();
        let wrong_key = EncryptionKey::new(&mut rand::thread_rng());

        assert!(encrypted_bytes.decrypt(&wrong_key).is_err());
    }

    #[test]
    fn decryption_fails_with_wrong_associated_data() {
        let (_, mut encrypted_bytes, enc_key) = encrypt_random_bytes();
        encrypted_bytes.associated_data = AssociatedData("Here is some incorrect data".to_string());

        assert!(encrypted_bytes.decrypt(&enc_key).is_err())
    }

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn decrypt_storage_key_not_implemented() {
        let storage_key = Encrypted {
            ciphertext: Vec::default(),
            associated_data: AssociatedData::default(),
            nonce: chacha20poly1305::Nonce::default(),
            original_type: PhantomData,
        };
        let _key = storage_key.decrypt_storage_key(OpaqueExportKey);
    }

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn decrypt_secret_not_implemented() {
        let encrypted_secret = Encrypted {
            ciphertext: Vec::default(),
            associated_data: AssociatedData::default(),
            nonce: chacha20poly1305::Nonce::default(),
            original_type: PhantomData,
        };
        let _secret = encrypted_secret.decrypt_secret(StorageKey);
    }
}
