//! Application-specific cryptographic types and operations.
//!
//! Defines and implements keys and secret types, and the appropriate
//! transformations between them. Public functions here are mostly wrappers
//! around multiple low-level cryptographic steps.

use crate::LockKeeperError;
use generic_array::{typenum::U64, GenericArray};
use hkdf::{hmac::digest::Output, Hkdf};
use k256::sha2::Sha512;
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::{array::IntoIter, convert::TryFrom};
use tracing::error;
use zeroize::ZeroizeOnDrop;

use crate::types::database::user::UserId;

mod arbitrary_secret;
mod generic;
mod signing_key;

pub use arbitrary_secret::Secret;
use generic::{AssociatedData, EncryptionKey};
pub use generic::{CryptoError, Encrypted};
pub use signing_key::{
    Export, Import, PlaceholderEncryptedSigningKeyPair, Signable, SignableBytes, Signature,
    SigningKeyPair, SigningPublicKey,
};

/// A session key is produced as shared output for client and server from
/// OPAQUE.
///
/// This key should not be stored or saved beyond the lifetime of a single
/// authentication session. It should not be passed out to the local calling
/// application.
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct OpaqueSessionKey(Box<[u8; 64]>);

impl From<GenericArray<u8, U64>> for OpaqueSessionKey {
    fn from(arr: GenericArray<u8, U64>) -> Self {
        Self(Box::new(arr.into()))
    }
}

/// The master key is a default-length symmetric encryption key for an
/// AEAD scheme.
///
/// The master key is used by the client to securely encrypt their
/// [`StorageKey`]. It should not be stored or saved beyond the lifetime of a
/// single authentication session. It should never be sent to the server or
/// passed out to the local calling application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterKey(EncryptionKey);

impl MasterKey {
    /// Derive a uniformly distributed secret [`MasterKey`] using the export key
    /// as input key material.
    ///
    /// # Arguments
    ///
    /// * `export_key` - the export_key as returned by opaque-ke library,
    /// which has type [`Output<Sha512>`]
    pub fn derive_master_key(export_key: Output<Sha512>) -> Result<Self, LockKeeperError> {
        let context = AssociatedData::new().with_str("OPAQUE-derived Lock Keeper master key");
        let mut master_key_material = [0u8; 32];

        // Derive `master_key_material` from HKDF with no salt, the
        // export_key as input key material, and the associated data as
        // extra info.
        Hkdf::<Sha3_256>::new(None, export_key.as_ref())
            .expand((&context).into(), &mut master_key_material)
            // This should never cause an error because we've hardcoded the length of the master key
            // material and the export key length to both be 32, and length mismatch is the only
            // documented cause of an `expand` failure.
            .map_err(|e| {
                error!("HKDF failed unexpectedly. {:?}", e);
                CryptoError::KeyDerivationFailed(e)
            })?;

        Ok(Self(EncryptionKey::from_bytes(
            master_key_material,
            context,
        )))
    }

    /// Create an encrypted storage key. This is part of the registration flow
    /// and is executed during a registration session with the
    /// server. This key should be sent to the server for storage.
    ///
    /// This must be run by the client.
    /// It takes the following steps:
    /// 1. Generate a new [`StorageKey`] to encrypt stored data with
    /// 2. Derive the decryption key from the master key,
    ///    using the associated data
    /// 3. Encrypt the storage key under the encryption key,
    ///    using an AEAD scheme
    /// 4. Return the encrypted storage key
    pub fn create_and_encrypt_storage_key(
        self,
        rng: &mut (impl CryptoRng + RngCore),
        user_id: &UserId,
    ) -> Result<Encrypted<StorageKey>, LockKeeperError> {
        let storage_key = StorageKey::generate(rng);
        Ok(self.encrypt_storage_key(rng, storage_key, user_id)?)
    }

    /// Encrypt the given [`StorageKey`] under a derivation from the
    /// [`MasterKey`] using an AEAD scheme.
    fn encrypt_storage_key(
        self,
        rng: &mut (impl CryptoRng + RngCore),
        storage_key: StorageKey,
        user_id: &UserId,
    ) -> Result<Encrypted<StorageKey>, CryptoError> {
        let associated_data = AssociatedData::new()
            .with_bytes(user_id.clone())
            .with_str(StorageKey::domain_separator());

        let key = self.derive_key(associated_data.clone())?;
        Encrypted::encrypt(rng, &key, storage_key, &associated_data)
    }

    /// Derive a new key from [`MasterKey`] using [`AssociatedData`] as the
    /// domain separator. [`MasterKey`] should not be used directly to
    /// encrypt something, instead use this method to derive a key for
    /// a specific use-case using a domain separator.
    fn derive_key(self, context: AssociatedData) -> Result<EncryptionKey, CryptoError> {
        let mut key_material = [0u8; 32];

        // Derive `key_material` from HKDF with no salt, the
        // `MasterKey` as input key material, and the associated data as
        // extra info.
        Hkdf::<Sha3_256>::new(None, self.0.into_bytes().as_ref())
            .expand((&context).into(), &mut key_material)
            // This should never cause an error because we've hardcoded the length of the key
            // material and the master key length to both be 32, and length mismatch is the only
            // documented cause of an `expand` failure.
            .map_err(|e| {
                error!("HKDF failed unexpectedly. {:?}", e);
                CryptoError::KeyDerivationFailed(e)
            })?;

        Ok(EncryptionKey::from_bytes(key_material, context))
    }
}

/// A storage key is a default-length symmetric encryption key for an
/// AEAD scheme. The storage key is used to encrypt stored secrets and signing
/// keys.
///
/// It is generated by the client and should never be revealed to the server or
/// the calling application.
/// It should not be stored or saved beyond the lifetime of a single
/// authentication session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageKey(EncryptionKey);

impl StorageKey {
    fn domain_separator() -> &'static str {
        "storage key"
    }

    /// Generate a new 32-byte [`StorageKey`].
    fn generate<Rng: CryptoRng + RngCore>(rng: &mut Rng) -> Self {
        Self(EncryptionKey::new(rng))
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

impl Encrypted<StorageKey> {
    /// Decrypt a storage key. This should be run as part of the subprotocol to
    /// retrieve a storage key from the server.
    ///
    /// This must be run by the client. It takes the following steps:
    /// 1. Derive the decryption key from the master key using
    ///    the associated data
    /// 2. Decrypt the encrypted storage key using the decryption key
    /// 3. Return the decrypted [`StorageKey`]
    pub fn decrypt_storage_key(
        self,
        master_key: MasterKey,
        user_id: &UserId,
    ) -> Result<StorageKey, LockKeeperError> {
        // Check that the associated data is correct.
        let expected_aad = AssociatedData::new()
            .with_bytes(user_id.clone())
            .with_str(StorageKey::domain_separator());
        if self.associated_data != expected_aad {
            return Err(CryptoError::DecryptionFailed.into());
        }

        let decryption_key = master_key.derive_key(self.associated_data.clone())?;
        let decrypted = self.decrypt(&decryption_key)?;
        Ok(decrypted)
    }
}

/// Universally unique identifier for a stored secret or signing key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct KeyId(Box<[u8; 32]>);

impl IntoIterator for KeyId {
    type Item = u8;
    type IntoIter = IntoIter<u8, 32>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl KeyId {
    /// Generate a new, random `KeyId` for the given [`UserId`].
    ///
    /// This is called by the key server.
    pub fn generate(
        rng: &mut (impl CryptoRng + RngCore),
        user_id: &UserId,
    ) -> Result<Self, LockKeeperError> {
        const RANDOM_LEN: usize = 32;
        let mut randomness = [0; RANDOM_LEN];
        rng.try_fill(&mut randomness)
            .map_err(|_| CryptoError::RandomNumberGeneratorFailed)?;
        let domain_separator = b"Lock Keeper key ID";

        let hasher = Sha3_256::new();
        let bytes = hasher
            .chain_update(domain_separator.len().to_be_bytes())
            .chain_update(domain_separator)
            .chain_update([user_id.len() as u8])
            .chain_update(user_id.as_bytes())
            .chain_update([RANDOM_LEN as u8])
            .chain_update(randomness)
            .finalize();

        // Truncate to 32 bytes, then convert into a 32-byte array.
        // This should never produce a `ConversionError` because the lengths are
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

    // Returns a slice of the contained bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &*self.0
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use crate::LockKeeperError;

    use super::*;
    use rand::{rngs::StdRng, Rng, SeedableRng};

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
    // We'll use random bytes for the test key.
    fn create_test_export_key(rng: &mut (impl CryptoRng + RngCore)) -> [u8; 64] {
        let mut key = [0_u8; 64];
        rng.try_fill(&mut key)
            .expect("Failed to generate random key");

        key
    }

    #[test]
    fn derive_master_key_not_obviously_broken() {
        let mut rng = rand::thread_rng();
        let export_key = create_test_export_key(&mut rng);
        let master_key = MasterKey::derive_master_key(export_key.into()).unwrap();

        // Make sure the master key isn't all 0s.
        let zero_key = EncryptionKey::from_bytes([0; 32], master_key.0.context().clone());
        assert_ne!(master_key.0, zero_key);

        // Make sure that using different context doesn't give the same key.
        let mut bad_mk = [0; 32];
        let bad_ad = AssociatedData::new().with_str("here is my testing context");
        Hkdf::<Sha3_256>::new(None, export_key.as_ref())
            .expand((&bad_ad).into(), &mut bad_mk)
            .unwrap();
        let wrong_context_key = EncryptionKey::from_bytes(bad_mk, master_key.0.context().clone());

        assert_ne!(master_key.0, wrong_context_key);
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
            MasterKey::derive_master_key(export1.into()).unwrap(),
            MasterKey::derive_master_key(export2.into()).unwrap()
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
        assert_eq!(32, storage_key.0.len())
    }

    #[test]
    fn key_id_generation_produces_unique_ids() -> Result<(), CryptoError> {
        let mut rng = rand::thread_rng();
        let mut uniq = HashSet::new();
        let user_id = UserId::new(&mut rng).unwrap();

        // Create 1000 key IDs; make sure they're unique
        // by putting them into a set. Insert will return false if a key id
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

    #[test]
    fn storage_key_encryption_works() -> Result<(), LockKeeperError> {
        let mut rng = rand::thread_rng();
        let export_key = create_test_export_key(&mut rng);
        let user_id = UserId::new(&mut rng)?;

        // Set up matching RNGs to check behavior of the utility function.
        let seed = b"not-random seed for convenience!";
        let mut rng = StdRng::from_seed(*seed);
        let mut rng_copy = StdRng::from_seed(*seed);

        // Encrypt the storage key
        let master_key = MasterKey::derive_master_key(export_key.into())?;
        let storage_key = StorageKey::generate(&mut rng);

        let encrypted_key =
            master_key
                .clone()
                .encrypt_storage_key(&mut rng, storage_key.clone(), &user_id)?;

        // Make sure the utility function gives the same result when encrypting the
        // storage key
        let utility_encrypted_key = master_key
            .clone()
            .create_and_encrypt_storage_key(&mut rng_copy, &user_id)?;
        assert_eq!(utility_encrypted_key, encrypted_key);

        // Decrypt the storage key and check that it worked
        let decrypted_key = encrypted_key.decrypt_storage_key(master_key, &user_id)?;
        assert_eq!(storage_key, decrypted_key);

        Ok(())
    }

    #[test]
    fn storage_key_retrieval_requires_correct_aad() -> Result<(), LockKeeperError> {
        let mut rng = rand::thread_rng();
        let export_key = create_test_export_key(&mut rng);
        let user_id = UserId::new(&mut rng)?;

        let master_key = MasterKey::derive_master_key(export_key.into())?;
        let storage_key = StorageKey::generate(&mut rng);

        let bad_aad = AssociatedData::new()
            .with_bytes(user_id.clone())
            .with_str(StorageKey::domain_separator())
            .with_str("some other content that makes this incorrect");

        let encrypted_storage_key =
            Encrypted::encrypt(&mut rng, &master_key.0, storage_key, &bad_aad)?;
        assert!(encrypted_storage_key
            .decrypt_storage_key(master_key, &user_id)
            .is_err());

        Ok(())
    }

    #[test]
    fn storage_key_requires_correct_encrypted_blob() -> Result<(), LockKeeperError> {
        let mut rng = rand::thread_rng();

        // Set up correct parameters to encrypt a storage key.
        let user_id = UserId::new(&mut rng)?;
        let export_key = create_test_export_key(&mut rng);
        let aad = AssociatedData::new()
            .with_bytes(user_id.clone())
            .with_str(StorageKey::domain_separator());

        // Encrypt any old key (and make sure it's decryptable in general)
        let fake_key = EncryptionKey::new(&mut rng);
        let encrypted_fake_key = Encrypted::encrypt(
            &mut rng,
            &MasterKey::derive_master_key(export_key.into())?.0,
            fake_key,
            &aad,
        )?;
        assert!(encrypted_fake_key
            .clone()
            .decrypt(&MasterKey::derive_master_key(export_key.into())?.0)
            .is_ok());

        // Serialize the fake key, and pretend it's a storage key when you deserialize.
        let fake_storage_key: Encrypted<StorageKey> =
            serde_json::from_str(&serde_json::to_string(&encrypted_fake_key).unwrap()).unwrap();

        // Decryption must fail.
        assert!(fake_storage_key
            .decrypt_storage_key(MasterKey::derive_master_key(export_key.into())?, &user_id)
            .is_err());

        Ok(())
    }

    #[test]
    fn opaque_session_key_gets_zeroized() -> Result<(), LockKeeperError> {
        let key = [1_u8; 64];
        let opaque_session_key = OpaqueSessionKey(key.into());
        let ptr = opaque_session_key.0.as_ptr();

        drop(opaque_session_key);

        let after_drop = unsafe { core::slice::from_raw_parts(ptr, 64) };
        assert_ne!(key, after_drop);
        Ok(())
    }

    #[test]
    fn opaque_export_key_gets_zeroized() -> Result<(), LockKeeperError> {
        let key = [1_u8; 64];
        let opaque_export_key = OpaqueExportKey(key.into());
        let ptr = opaque_export_key.0.as_ptr();

        drop(opaque_export_key);

        let after_drop = unsafe { core::slice::from_raw_parts(ptr, 64) };
        assert_ne!(key, after_drop);
        Ok(())
    }
}
