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
use generic_array::{typenum::U32, GenericArray};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
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
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(hkdf::InvalidLength),
}

/// The associated data used in [`Encrypted`] AEAD ciphertexts and (TODO #130:
/// HKDF) key derivations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct AssociatedData(String);

impl Default for AssociatedData {
    fn default() -> Self {
        Self(String::from("Version 0.1."))
    }
}

impl TryFrom<Vec<u8>> for AssociatedData {
    type Error = FromUtf8Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(String::from_utf8(bytes)?))
    }
}

impl From<AssociatedData> for Vec<u8> {
    fn from(associated_data: AssociatedData) -> Self {
        associated_data.0.into_bytes()
    }
}

impl<'a> From<&'a AssociatedData> for &'a [u8] {
    fn from(associated_data: &'a AssociatedData) -> Self {
        associated_data.0.as_bytes()
    }
}

impl AssociatedData {
    fn new() -> Self {
        Self::default()
    }

    fn with_str(self, ad: &str) -> Self {
        AssociatedData(format!("{}\n{}", self.0, ad))
    }

    fn with_aead_parameters(self) -> Self {
        self.with_str("ChaCha20Poly1305 with 96-bit nonce.")
    }

    fn with_hkdf_parameters(self) -> Self {
        self.with_str("HMAC-based extract-and-expand key derivation function using SHA3-256")
    }
}

/// A ciphertext representing an object of type `T`, encrypted under the
/// [ChaCha20Poly1305 scheme](https://www.rfc-editor.org/rfc/rfc8439) for
/// authenticated encryption with associated data (AEAD).
///
/// As implied by the scheme name, this uses the recommended 20 rounds and a
/// standard 96-bit nonce. For more details, see the
/// [ChaCha20Poly1305 crate](https://docs.rs/chacha20poly1305/latest/chacha20poly1305/index.html).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Encrypted<T> {
    ciphertext: Vec<u8>,
    associated_data: AssociatedData,
    nonce: chacha20poly1305::Nonce,
    original_type: PhantomData<T>,
}

/// A well-formed symmetric encryption key for an AEAD scheme.
#[derive(Debug, Clone)]
struct EncryptionKey {
    key: chacha20poly1305::Key,

    #[allow(unused)]
    associated_data: AssociatedData,
}

#[allow(unused)]
impl EncryptionKey {
    /// Generate a new symmetric AEAD encryption key from scratch.
    fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self {
            key: ChaCha20Poly1305::generate_key(rng),
            associated_data: AssociatedData::new().with_aead_parameters(),
        }
    }
}

#[allow(unused)]
impl<T> Encrypted<T>
where
    T: From<Vec<u8>>,
    Vec<u8>: From<T>,
{
    /// Encrypt the `T` and authenticate the [`AssociatedData`] under the
    /// [`EncryptionKey`].
    ///
    ///
    /// Raises a [`CryptoError::EncryptionFailed`] if encryption fails.
    fn encrypt(
        rng: &mut (impl CryptoRng + RngCore),
        enc_key: &EncryptionKey,
        object: T,
        associated_data: &AssociatedData,
    ) -> Result<Encrypted<T>, CryptoError> {
        // Set up cipher with key
        let cipher = ChaCha20Poly1305::new(&enc_key.key);

        // Format plaintext and associated data
        let payload = Payload {
            msg: &Vec::from(object),
            aad: associated_data.into(),
        };

        // Encrypt!
        let nonce = ChaCha20Poly1305::generate_nonce(rng);
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
        let cipher = ChaCha20Poly1305::new(&enc_key.key);

        // Format ciphertext and associated data
        let ad_vec: Vec<u8> = self.associated_data.into();
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
pub struct OpaqueExportKey(GenericArray<u8, U32>);

impl OpaqueExportKey {
    /// Derive a [`MasterKey`] from the export key.
    #[allow(unused)]
    fn derive_master_key(&self) -> Result<MasterKey, CryptoError> {
        let hk = Hkdf::<Sha3_256>::new(None, &self.0);
        let associated_data = AssociatedData::new()
            .with_str("OPAQUE-derived Lock Keeper master key")
            .with_hkdf_parameters();

        let mut master_key_material = [0u8; 32];
        hk.expand((&associated_data).into(), &mut master_key_material)
            .map_err(CryptoError::KeyDerivationFailed)?;

        Ok(MasterKey(EncryptionKey {
            key: master_key_material.into(),
            associated_data,
        }))
    }
}

/// The master key is a default-length symmetric encryption key for an
/// AEAD scheme.
///
/// The master key is used by the client to securely encrypt their
/// [`StorageKey`]. It should not be stored or saved beyond the lifetime of a
/// single authentication session. It should never be sent to the server or
/// passed out to the local calling application.
#[allow(unused)]
#[derive(Debug)]
struct MasterKey(EncryptionKey);

#[allow(unused)]
impl MasterKey {
    /// Encrypt the given [`StorageKey`] under the [`MasterKey`] using an
    /// AEAD scheme.
    fn encrypt_storage_key(self, storage_key: StorageKey) -> Encrypted<StorageKey> {
        todo!()
    }
}

/// A storage key is a default-length symmetric encryption key for an
/// AEAD scheme. The storage key is used to encrypt stored secrets.
///
/// It is generated by the client and should never be revealed to the server or
/// the calling application.
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

    /// Encrypt the given [`Secret`] under the [`StorageKey`], using the
    /// AEAD scheme.
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
    use std::collections::HashSet;

    use super::*;
    use rand::Rng;

    #[test]
    fn associated_data_to_vec_u8_conversion_works() -> Result<(), FromUtf8Error> {
        let test_strings = [
            "A random string to test conversion",
            "",
            "0123456789",
            "the quick brown fox jumps over the lazy dog",
            "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG",
        ];

        for test in test_strings {
            let data = AssociatedData(test.to_string());

            let data_vec: Vec<u8> = data.clone().into();
            let output_data: AssociatedData = data_vec.try_into()?;

            // make sure converting to & from Vec<u8> gives the same result
            assert_eq!(data, output_data);
        }

        Ok(())
    }

    // In practice, an export key will be a pseudorandom output form OPAQUE.
    // Instead, we'll use the encryption key generation function to simulate the
    // same thing.
    pub(crate) fn export_key(rng: &mut (impl CryptoRng + RngCore)) -> OpaqueExportKey {
        OpaqueExportKey(EncryptionKey::new(rng).key)
    }

    #[test]
    fn derive_master_key_not_obviously_broken() {
        let mut rng = rand::thread_rng();
        let export_key = export_key(&mut rng);
        let master_key = export_key.derive_master_key().unwrap();

        // make sure the master key isn't the same as the export key
        assert!(master_key.0.key != export_key.0)
    }

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn encrypt_storage_key_not_implemented() {
        let mut rng = rand::thread_rng();
        let master_key = MasterKey(EncryptionKey::new(&mut rng));
        let _encrypted_storage_key = master_key.encrypt_storage_key(StorageKey);
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

    /// Generates random bytes, encrypts them, and returns them along with the
    /// key used for encryption.
    fn encrypt_random_bytes(
        rng: &mut (impl CryptoRng + RngCore),
    ) -> (Vec<u8>, Encrypted<Vec<u8>>, EncryptionKey) {
        let bytes: Vec<u8> = std::iter::repeat_with(|| rng.gen()).take(64).collect();
        let enc_key = EncryptionKey::new(rng);
        let encrypted_bytes =
            Encrypted::encrypt(rng, &enc_key, bytes.clone(), &AssociatedData::default()).unwrap();

        (bytes, encrypted_bytes, enc_key)
    }

    #[test]
    fn encryption_decryption_works() -> Result<(), CryptoError> {
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let (bytes, encrypted_bytes, enc_key) = encrypt_random_bytes(&mut rng);

            // Make sure encryption isn't obviously broken.
            assert_ne!(bytes, encrypted_bytes.ciphertext);

            // Make sure encrypted object includes the expected associated data.
            let expected_aad = AssociatedData::default();
            assert_eq!(expected_aad, encrypted_bytes.associated_data);

            let decrypted_bytes = encrypted_bytes.decrypt(&enc_key)?;
            // Make sure decryption works
            assert_eq!(bytes, decrypted_bytes);
        }

        Ok(())
    }

    #[test]
    fn encryption_produces_unique_nonces() {
        let mut rng = rand::thread_rng();
        let mut uniq = HashSet::new();

        // Create 1000 ciphertexts; pull out the nonces; make sure they're unique by
        // putting them into a set. Insert will return false if a nonce already
        // exists in the set.
        assert!((0..1000)
            .map(|_| encrypt_random_bytes(&mut rng).1.nonce)
            .all(|nonce| uniq.insert(nonce)))
    }

    #[test]
    fn decryption_fails_with_wrong_nonce() {
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let (_, mut encrypted_bytes, enc_key) = encrypt_random_bytes(&mut rng);
            encrypted_bytes.nonce = ChaCha20Poly1305::generate_nonce(&mut rng);
            assert!(encrypted_bytes.decrypt(&enc_key).is_err());
        }
    }

    #[test]
    fn decryption_fails_with_wrong_key() {
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let (_, encrypted_bytes, _) = encrypt_random_bytes(&mut rng);
            let wrong_key = EncryptionKey::new(&mut rand::thread_rng());

            assert!(encrypted_bytes.decrypt(&wrong_key).is_err());
        }
    }

    #[test]
    fn decryption_fails_with_wrong_associated_data() {
        let mut rng = rand::thread_rng();
        let (_, mut encrypted_bytes, enc_key) = encrypt_random_bytes(&mut rng);
        encrypted_bytes.associated_data = AssociatedData("Here is some incorrect data".to_string());

        assert!(encrypted_bytes.decrypt(&enc_key).is_err())
    }

    #[test]
    fn decryption_fails_with_tweaked_ciphertext() {
        let mut rng = rand::thread_rng();

        for _ in 0..100 {
            let (_, mut encrypted_bytes, enc_key) = encrypt_random_bytes(&mut rng);
            encrypted_bytes.ciphertext[0] ^= 1;
            assert!(encrypted_bytes.decrypt(&enc_key).is_err());

            let (_, mut encrypted_bytes, enc_key) = encrypt_random_bytes(&mut rng);
            let len = encrypted_bytes.ciphertext.len();
            encrypted_bytes.ciphertext[len - 1] ^= 1;
            assert!(encrypted_bytes.decrypt(&enc_key).is_err());

            let (_, mut encrypted_bytes, enc_key) = encrypt_random_bytes(&mut rng);
            encrypted_bytes.ciphertext[len / 2] ^= 1;
            assert!(encrypted_bytes.decrypt(&enc_key).is_err());
        }
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
        let _key = storage_key.decrypt_storage_key(export_key(&mut rand::thread_rng()));
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
