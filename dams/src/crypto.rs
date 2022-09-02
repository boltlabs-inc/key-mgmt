//! Application-specific cryptographic types and operations.
//!
//! Defines and implements keys and secret types, and the appropriate
//! transformations between them. Public functions here are mostly wrappers
//! around multiple low-level cryptographic steps.

use chacha20poly1305::{
    aead::{Aead, Payload},
    AeadCore, ChaCha20Poly1305, KeyInit,
};
use generic_array::{
    typenum::{U32, U64},
    GenericArray,
};
use hkdf::Hkdf;
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::{iter, marker::PhantomData};
use thiserror::Error;
use tracing::error;

use crate::user::UserId;

#[cfg(test)]
use std::convert::Infallible;

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
    #[error("RNG failed")]
    RandomNumberGeneratorFailed,
    #[error("Conversion error")]
    ConversionError,

    #[cfg(test)]
    #[error(transparent)]
    Infallible(#[from] Infallible),
}

/// The associated data used in [`Encrypted`] AEAD ciphertexts and (TODO #130:
/// HKDF) key derivations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct AssociatedData(String);

impl Default for AssociatedData {
    fn default() -> Self {
        Self(String::from("Version 0.1."))
    }
}

impl TryFrom<Vec<u8>> for AssociatedData {
    type Error = CryptoError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(
            String::from_utf8(bytes).map_err(|_| CryptoError::ConversionError)?,
        ))
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
}

/// A ciphertext representing an object of type `T`, encrypted under the
/// [ChaCha20Poly1305 scheme](https://www.rfc-editor.org/rfc/rfc8439) for
/// authenticated encryption with associated data (AEAD).
///
/// As implied by the scheme name, this uses the recommended 20 rounds and a
/// standard 96-bit nonce. For more details, see the
/// [ChaCha20Poly1305 crate](https://docs.rs/chacha20poly1305/latest/chacha20poly1305/index.html).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Encrypted<T> {
    ciphertext: Vec<u8>,
    associated_data: AssociatedData,
    nonce: chacha20poly1305::Nonce,
    original_type: PhantomData<T>,
}

/// A well-formed symmetric encryption key for an AEAD scheme.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
            associated_data: AssociatedData::new().with_str("ChaCha20Poly1305 with 96-bit nonce."),
        }
    }
}

impl<T> Encrypted<T>
where
    T: TryFrom<Vec<u8>>,
    CryptoError: From<<T as TryFrom<Vec<u8>>>::Error>,
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
    /// Raises a [`CryptoError::DecryptionFailed`] if decryption fails or
    /// [`CryptoError::ConversionError`] if the decrypted plaintext cannot be
    /// converted into `T`.
    #[allow(unused)]
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
        Ok(cipher
            .decrypt(&self.nonce, payload)
            .map_err(|_| CryptoError::DecryptionFailed)?
            .try_into()?)
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
    pub fn decrypt_storage_key(
        self,
        export_key: OpaqueExportKey,
    ) -> Result<StorageKey, CryptoError> {
        let master_key = export_key.derive_master_key()?;
        self.decrypt(&master_key.0)
    }
}

/// A session key is produced as shared output for client and server from
/// OPAQUE.
///
/// This key should not be stored or saved beyond the lifetime of a single
/// authentication session. It should not be passed out to the local calling
/// application.
#[derive(Debug, Clone)]
pub struct OpaqueSessionKey(Box<[u8; 64]>);

impl From<GenericArray<u8, U64>> for OpaqueSessionKey {
    fn from(arr: GenericArray<u8, U64>) -> Self {
        Self(Box::new(arr.into()))
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueExportKey(GenericArray<u8, U32>);

impl OpaqueExportKey {
    /// Derive a uniformly distributed secret [`MasterKey`] using the export key
    /// as input key material.
    #[allow(unused)]
    fn derive_master_key(&self) -> Result<MasterKey, CryptoError> {
        let associated_data =
            AssociatedData::new().with_str("OPAQUE-derived Lock Keeper master key");
        let mut master_key_material = [0u8; 32];

        // Derive `master_key_material` from HKDF with no salt, the
        // `OpaqueExportKey` as input key material, and the associated data as
        // extra info.
        Hkdf::<Sha3_256>::new(None, &self.0)
            .expand((&associated_data).into(), &mut master_key_material)
            // This should never cause an error because we've hardcoded the length of the master key
            // material and the export key length to both be 32, and length mismatch is the only
            // documented cause of an `expand` failure.
            .map_err(|e| {
                error!("HKDF failed unexpectedly. {:?}", e);
                CryptoError::KeyDerivationFailed(e)
            })?;

        Ok(MasterKey(EncryptionKey {
            key: master_key_material.into(),
            associated_data,
        }))
    }

    /// Create an encrypted storage key. This is part of the registration flow
    /// and is executed during a registration session with the
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
        self,
        rng: &mut (impl CryptoRng + RngCore),
        user_id: &UserId,
    ) -> Result<Encrypted<StorageKey>, CryptoError> {
        let master_key = self.derive_master_key()?;
        let storage_key = StorageKey::generate(rng);
        master_key.encrypt_storage_key(rng, storage_key, user_id)
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
#[derive(Debug, PartialEq, Eq)]
struct MasterKey(EncryptionKey);

#[allow(unused)]
impl MasterKey {
    /// Encrypt the given [`StorageKey`] under the [`MasterKey`] using an
    /// AEAD scheme.
    fn encrypt_storage_key(
        self,
        rng: &mut (impl CryptoRng + RngCore),
        storage_key: StorageKey,
        user_id: &UserId,
    ) -> Result<Encrypted<StorageKey>, CryptoError> {
        let associated_data = AssociatedData::new()
            .with_str(&user_id.to_string())
            .with_str(StorageKey::domain_separator());

        Encrypted::encrypt(rng, &self.0, storage_key, &associated_data)
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageKey(EncryptionKey);

#[allow(unused)]
impl StorageKey {
    fn domain_separator() -> &'static str {
        "storage key"
    }

    /// Generate a new 32-byte [`StorageKey`].
    fn generate<Rng: CryptoRng + RngCore>(rng: &mut Rng) -> Self {
        let associated_data = AssociatedData::new().with_str(Self::domain_separator());
        let key = Secret::generate(rng, 32, associated_data.clone());

        Self(EncryptionKey {
            key: *chacha20poly1305::Key::from_slice(&key.material),
            associated_data,
        })
    }

    /// Encrypt the given [`Secret`] under the [`StorageKey`], using the
    /// AEAD scheme.
    fn encrypt_data(
        self,
        rng: &mut (impl CryptoRng + RngCore),
        secret: Secret,
        user_id: &UserId,
        key_id: &KeyId,
    ) -> Result<Encrypted<Secret>, CryptoError> {
        let ad = AssociatedData::new()
            .with_str(&user_id.to_string())
            .with_str(key_id.as_str()?)
            .with_str("client-generated");

        Encrypted::encrypt(rng, &self.0, secret, &ad)
    }

    /// Create and encrypt a new secret. This is part of the
    /// generate a new secret flow.
    ///
    /// This must be run by the client. It takes the following steps:
    /// 1. Generates a new secret
    /// 2. Encrypt it under the [`StorageKey`], using an AEAD scheme
    #[allow(unused)]
    pub fn create_and_encrypt_secret(
        self,
        rng: &mut (impl CryptoRng + RngCore),
        user_id: &UserId,
        key_id: &KeyId,
    ) -> Encrypted<Secret> {
        todo!()
    }
}

impl From<StorageKey> for Vec<u8> {
    fn from(key: StorageKey) -> Self {
        StorageKey::domain_separator()
            .as_bytes()
            .iter()
            .copied()
            .chain::<Vec<u8>>(key.0.into())
            .collect()
    }
}

impl TryFrom<Vec<u8>> for StorageKey {
    type Error = CryptoError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let expected_domain_sep = StorageKey::domain_separator().as_bytes();
        let domain_separator = bytes
            .get(0..expected_domain_sep.len())
            .ok_or(CryptoError::ConversionError)?;
        if expected_domain_sep != domain_separator {
            return Err(CryptoError::ConversionError);
        }

        // Take off the domain separator
        let key_bytes = bytes
            .get(expected_domain_sep.len()..)
            .ok_or(CryptoError::ConversionError)?
            .to_vec();

        Ok(Self(key_bytes.try_into()?))
    }
}

impl From<EncryptionKey> for Vec<u8> {
    fn from(key: EncryptionKey) -> Self {
        // len || key || context
        iter::once(key.key.len() as u8)
            .chain(key.key)
            .chain::<Vec<u8>>(key.associated_data.into())
            .collect()
    }
}

impl TryFrom<Vec<u8>> for EncryptionKey {
    type Error = CryptoError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        // len (should always be 32) || key || context
        let len = *bytes.first().ok_or(CryptoError::ConversionError)? as usize;
        if len != 32 {
            return Err(CryptoError::ConversionError);
        }

        // len (1 byte) || material (len bytes) || context (remainder)
        let key = bytes.get(1..33).ok_or(CryptoError::ConversionError)?;
        let associated_data: Vec<u8> = bytes
            .get(len + 1..)
            .ok_or(CryptoError::ConversionError)?
            .into();

        Ok(Self {
            key: *chacha20poly1305::Key::from_slice(key),
            associated_data: associated_data.try_into()?,
        })
    }
}

/// Universally unique identifier for a secret.
#[allow(unused)]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct KeyId(Box<[u8; 32]>);

#[allow(unused)]
impl KeyId {
    /// Generate a new, random `KeyId` for the given [`UserId`].
    ///
    /// This is called by the key server.
    fn generate(
        rng: &mut (impl CryptoRng + RngCore),
        user_id: &UserId,
    ) -> Result<Self, CryptoError> {
        const RANDOM_LEN: usize = 32;
        let mut randomness = [0; RANDOM_LEN];
        rng.try_fill(&mut randomness)
            .map_err(|_| CryptoError::RandomNumberGeneratorFailed)?;
        let domain_separator = b"Lock Keeper key ID";

        let mut hasher = Sha3_256::new();
        let bytes = hasher
            .chain_update(domain_separator.len().to_be_bytes())
            .chain_update(domain_separator)
            .chain_update([user_id.len() as u8])
            .chain_update(user_id.as_bytes())
            .chain_update([RANDOM_LEN as u8])
            .chain_update(randomness)
            .finalize();

        // Truncate to 32 bytes, then convert into a 32-byte array.
        // This should never produce a ConversoinError because the lengths are
        // hard-coded.
        Ok(Self(Box::new(
            bytes
                .into_iter()
                .take(32)
                .collect::<Vec<u8>>()
                .try_into()
                .map_err(|_| CryptoError::ConversionError)?,
        )))
    }

    fn as_str(&self) -> Result<&str, CryptoError> {
        std::str::from_utf8(self.0.as_ref()).map_err(|_| CryptoError::ConversionError)
    }
}

/// An arbitrary secret.
///
/// This is generated by the client and should never be revealed to the server.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Secret {
    /// The actual bytes of secret material.
    material: Vec<u8>,
    /// Additional context about the secret.
    context: AssociatedData,
}

#[allow(unused)]
impl Secret {
    /// Generate a new secret of length `len` (in bytes).
    fn generate(rng: &mut (impl CryptoRng + RngCore), len: usize, context: AssociatedData) -> Self {
        Self {
            material: iter::repeat_with(|| rng.gen()).take(len).collect(),
            context,
        }
    }
}

impl From<Secret> for Vec<u8> {
    fn from(secret: Secret) -> Self {
        // key len || key material || context len || context
        let ad: Vec<u8> = secret.context.into();
        iter::once(secret.material.len() as u8)
            .chain(secret.material)
            .chain(iter::once(ad.len() as u8))
            .chain(ad)
            .collect()
    }
}

impl TryFrom<Vec<u8>> for Secret {
    type Error = CryptoError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        // key len (1 byte) || key material || context len (1 byte) || context
        let len = *bytes.first().ok_or(CryptoError::ConversionError)? as usize;
        let material = bytes
            .get(1..len + 1)
            .ok_or(CryptoError::ConversionError)?
            .into();
        let ad_len = *bytes.get(len + 1).ok_or(CryptoError::ConversionError)? as usize;
        let context: Vec<u8> = bytes
            .get(len + 2..)
            .ok_or(CryptoError::ConversionError)?
            .into();
        if context.len() != ad_len {
            return Err(CryptoError::ConversionError);
        }

        Ok(Self {
            material,
            context: context.try_into()?,
        })
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use crate::DamsError;

    use super::*;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    #[test]
    fn associated_data_to_vec_u8_conversion_works() -> Result<(), CryptoError> {
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

            // Make sure converting to & from Vec<u8> gives the same result
            assert_eq!(data, output_data);
        }

        Ok(())
    }

    #[test]
    fn secret_to_vec_u8_conversion_works() -> Result<(), CryptoError> {
        let mut rng = rand::thread_rng();

        for len in 0..128 {
            let associated_data =
                AssociatedData::new().with_str(&format!("a secret of length {}", len));
            let secret = Secret::generate(&mut rng, len, associated_data);

            let secret_vec: Vec<u8> = secret.clone().into();
            let output_secret: Secret = secret_vec.try_into()?;

            // Make sure converting to & from Vec<u8> gives the same result
            assert_eq!(secret, output_secret);
        }

        Ok(())
    }

    #[test]
    fn secret_parsing_handles_bad_input() {
        let empty = Vec::new();
        assert!(Secret::try_from(empty).is_err());

        let just_zero = vec![0];
        assert!(Secret::try_from(just_zero).is_err());

        let not_enough_key = vec![12, 1, 1, 1];
        assert!(Secret::try_from(not_enough_key).is_err());

        let no_context = vec![1, 1];
        assert!(Secret::try_from(no_context).is_err());

        let not_enough_context = vec![1, 1, 12, 1];
        assert!(Secret::try_from(not_enough_context).is_err());

        let too_much_context = vec![1, 1, 1, 3, 3, 3, 3];
        assert!(Secret::try_from(too_much_context).is_err());
    }

    #[test]
    fn encryption_key_to_vec_u8_conversion_works() -> Result<(), CryptoError> {
        let mut rng = rand::thread_rng();

        for _ in 0..1000 {
            let encryption_key = EncryptionKey::new(&mut rng);

            let bytes: Vec<u8> = encryption_key.clone().into();
            let output_key: EncryptionKey = bytes.try_into()?;

            assert_eq!(encryption_key, output_key);
        }

        Ok(())
    }

    #[test]
    fn storage_key_to_vec_u8_conversion_works() -> Result<(), CryptoError> {
        let mut rng = rand::thread_rng();

        for _ in 0..1000 {
            let storage_key = StorageKey::generate(&mut rng);

            let vec: Vec<u8> = storage_key.clone().into();
            let output_storage_key = vec.try_into()?;

            assert_eq!(storage_key, output_storage_key);
        }
        Ok(())
    }

    // In practice, an export key will be a pseudorandom output from OPAQUE.
    // Instead, we'll use the encryption key generation function to simulate the
    // same thing.
    fn create_test_export_key(rng: &mut (impl CryptoRng + RngCore)) -> OpaqueExportKey {
        OpaqueExportKey(EncryptionKey::new(rng).key)
    }

    #[test]
    fn derive_master_key_not_obviously_broken() {
        let mut rng = rand::thread_rng();
        let export_key = create_test_export_key(&mut rng);
        let master_key = export_key.derive_master_key().unwrap();

        // Make sure the master key isn't the same as the export key.
        assert_ne!(master_key.0.key, export_key.0);

        // Make sure the master key isn't all 0s.
        assert_ne!(master_key.0.key, [0; 32].into());

        // Make sure that using different context doesn't give the same key.
        let mut bad_mk = [0; 32];
        let bad_ad = AssociatedData::new().with_str("here is my testing context");
        Hkdf::<Sha3_256>::new(None, &export_key.0)
            .expand((&bad_ad).into(), &mut bad_mk)
            .unwrap();

        assert_ne!(master_key.0.key, bad_mk.into());
    }

    #[test]
    fn master_key_depends_on_export_key() {
        let mut rng = rand::thread_rng();
        let export1 = create_test_export_key(&mut (rng));
        let export2 = create_test_export_key(&mut (rng));

        // Different export keys...
        assert_ne!(export1, export2);
        // ...implies different master keys.
        assert_ne!(
            export1.derive_master_key().unwrap(),
            export2.derive_master_key().unwrap()
        );
    }

    #[test]
    fn storage_key_generation_produces_unique_storage_keys() {
        let mut rng = rand::thread_rng();
        let mut uniq = HashSet::new();

        assert!((0..1000)
            .map(|_| StorageKey::generate(&mut rng))
            .all(|storage_key| uniq.insert(storage_key.0)));
    }

    #[test]
    fn storage_keys_are_32_bytes() {
        let mut rng = rand::thread_rng();
        let storage_key = StorageKey::generate(&mut rng);
        assert_eq!(32, storage_key.0.key.len())
    }

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn data_encryption_not_implemented() {
        let secret = Secret {
            material: Vec::default(),
            context: AssociatedData::default(),
        };
        let mut rng = rand::thread_rng();
        let storage_key = StorageKey::generate(&mut rng);
        let user_id = UserId::new(&mut rng).unwrap();
        let key_id = KeyId::generate(&mut rng, &user_id).unwrap();
        let _encrypted_secret = storage_key.encrypt_data(&mut rng, secret, &user_id, &key_id);
    }

    #[test]
    fn secret_generation_produces_unique_secrets() {
        let mut rng = rand::thread_rng();
        let mut uniq = HashSet::new();

        // Create 1000 secrets; pull out the secret material; make sure they're unique
        // by putting them into a set. Insert will return false if a secret
        // already exists in the set.
        assert!((0..1000)
            .map(|_| Secret::generate(&mut rng, 32, AssociatedData::default()).material)
            .all(|secret| uniq.insert(secret)))
    }

    #[test]
    fn secret_generation_length_specification_works() {
        let mut rng = rand::thread_rng();
        // Make secrets of length 0 to 1000. Check that the length of the generated
        // secret matches the expected length.
        assert!((0..1000)
            .map(|len| (
                len,
                Secret::generate(&mut rng, len, AssociatedData::default())
                    .material
                    .len()
            ))
            .all(|(expected, actual)| expected == actual))
    }

    #[test]
    fn secret_associated_data_matches_expected() {
        let mut rng = rand::thread_rng();

        // in the default case
        let secret = Secret::generate(&mut rng, 32, AssociatedData::default());
        assert_eq!(secret.context, AssociatedData::default());

        // in the non-default case
        let complicated_ad = AssociatedData(
            "here is a long, complex string\nfor testing. with details!".to_string(),
        );
        let secret = Secret::generate(&mut rng, 32, complicated_ad.clone());
        assert_eq!(secret.context, complicated_ad);
    }

    #[test]
    fn key_id_generation_produces_unique_ids() -> Result<(), CryptoError> {
        let mut rng = rand::thread_rng();
        let mut uniq = HashSet::new();
        let user_id = UserId::new(&mut rng).unwrap();

        // Create 1000 key IDs; make sure they're unique
        // by putting them into a set. Insert will return false if a secret
        // already exists in the set.
        assert!((0..1000)
            .map(|_| KeyId::generate(&mut rng, &user_id).unwrap())
            .all(|key_id| uniq.insert(key_id)));

        Ok(())
    }

    #[test]
    fn key_id_generation_incorporates_user_id() {
        let mut rng = rand::thread_rng();
        let mut uniq = HashSet::new();
        let seed = b"a terrible seed for testing keys";

        // The bad RNG will produce the same randomness for every call to generate.
        // But the key IDs are still unique!
        assert!((0..1000)
            .map(|_| {
                let user_id = UserId::new(&mut rng).unwrap();
                let mut bad_rng = StdRng::from_seed(*seed);
                KeyId::generate(&mut bad_rng, &user_id).unwrap()
            })
            .all(|key_id| uniq.insert(key_id)))
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
            assert_ne!(Vec::from([0; 32]), encrypted_bytes.ciphertext);

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
    fn decrypt_secret_not_implemented() {
        let mut rng = rand::thread_rng();
        let encrypted_secret = Encrypted {
            ciphertext: Vec::default(),
            associated_data: AssociatedData::default(),
            nonce: chacha20poly1305::Nonce::default(),
            original_type: PhantomData,
        };
        let storage_key = StorageKey::generate(&mut rng);
        let _secret = encrypted_secret.decrypt_secret(storage_key);
    }

    #[test]
    fn storage_key_encryption_works() -> Result<(), DamsError> {
        let mut rng = rand::thread_rng();
        let export_key = create_test_export_key(&mut rng);
        let user_id = UserId::new(&mut rng)?;

        // Set up matching RNGs to check behavior of the utility function.
        let seed = b"not-random seed for convenience!";
        let mut rng = StdRng::from_seed(*seed);
        let mut rng_copy = StdRng::from_seed(*seed);

        // Encrypt the storage key
        let master_key = export_key.derive_master_key()?;
        let storage_key = StorageKey::generate(&mut rng);
        let encrypted_key =
            master_key.encrypt_storage_key(&mut rng, storage_key.clone(), &user_id)?;

        // Make sure the utility function gives the same result when encrypting the
        // storage key
        let utility_encrypted_key = export_key
            .clone()
            .create_and_encrypt_storage_key(&mut rng_copy, &user_id)?;
        assert_eq!(utility_encrypted_key, encrypted_key);

        // Decrypt the storage key and check that it worked
        let decrypted_key = encrypted_key.decrypt_storage_key(export_key)?;
        assert_eq!(storage_key, decrypted_key);

        Ok(())
    }

    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn create_and_encrypt_secret_not_implemented() {
        let mut rng = rand::thread_rng();
        let storage_key = StorageKey::generate(&mut rng);
        // TODO #134: use proper gen function
        let key_id = KeyId(Box::new([0; 32]));
        let _ = storage_key.create_and_encrypt_secret(&mut rng, &UserId::default(), &key_id);
    }
}
