//! Application-specific cryptographic types and operations.
//!
//! Defines and implements keys and secret types, and the appropriate
//! transformations between them. Public functions here are mostly wrappers
//! around multiple low-level cryptographic steps.

use crate::{types::database::HexBytes, LockKeeperError};
use generic_array::{typenum::U64, GenericArray};
use hkdf::{hmac::digest::Output, Hkdf};
use k256::sha2::Sha512;
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::{
    array::{IntoIter, TryFromSliceError},
    convert::TryFrom,
    fmt::Debug,
};
use tracing::error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::types::database::account::UserId;

mod arbitrary_secret;
mod data_blob;
mod generic;
pub mod sharding;
mod cryptor;
mod cryptor_key;
mod data_blob;
mod generic;
mod signing_key;
mod signing_private_key;
mod storage_key;

use crate::rpc::Message;
pub use arbitrary_secret::Secret;
pub use cryptor_key::CryptorKey;
pub use data_blob::DataBlob;
use generic::{AssociatedData, EncryptionKey};
pub use generic::{CryptoError, Encrypted};
pub use signing_key::{
    Import, Signable, SignableBytes, Signature, SigningKeyPair, SigningPublicKey,
};
pub use signing_private_key::{RecoverableSignature, SigningPrivateKey};
#[cfg(test)]
use storage_key::test::create_test_export_key;
pub use storage_key::{RemoteStorageKey, StorageKey};

/// A session key is produced as shared output for client and server from
/// OPAQUE.
///
/// This key should not be stored or saved beyond the lifetime of a single
/// authentication session. It should not be passed out to the local calling
/// application.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct OpaqueSessionKey(EncryptionKey);

impl TryFrom<GenericArray<u8, U64>> for OpaqueSessionKey {
    type Error = LockKeeperError;

    fn try_from(arr: GenericArray<u8, U64>) -> Result<Self, Self::Error> {
        let context = AssociatedData::new().with_str(Self::domain_separator());
        Ok(Self(EncryptionKey::from_bytes(
            arr[..32]
                .try_into()
                .map_err(|_| LockKeeperError::Crypto(CryptoError::ConversionError))?,
            context,
        )))
    }
}

impl OpaqueSessionKey {
    /// Encrypt the given [`Message`] under the [`OpaqueSessionKey`] using an
    /// AEAD scheme.
    pub fn encrypt(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        message: Message,
    ) -> Result<Encrypted<Message>, CryptoError> {
        Encrypted::encrypt(rng, &self.0, message, &AssociatedData::new())
    }

    fn context(&self) -> &AssociatedData {
        &self.0.context
    }

    pub(crate) fn domain_separator() -> &'static str {
        "OPAQUE-derived Lock Keeper session key"
    }
}

impl TryFrom<OpaqueSessionKey> for Vec<u8> {
    type Error = CryptoError;

    fn try_from(key: OpaqueSessionKey) -> Result<Self, Self::Error> {
        let bytes = Vec::<u8>::try_from(key.0.to_owned())?;
        Ok(OpaqueSessionKey::domain_separator()
            .as_bytes()
            .iter()
            .copied()
            .chain(bytes)
            .collect())
    }
}

impl TryFrom<Vec<u8>> for OpaqueSessionKey {
    type Error = CryptoError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let expected_domain_sep = OpaqueSessionKey::domain_separator().as_bytes();
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

impl Encrypted<OpaqueSessionKey> {
    /// Decrypt a session key server-side.
    pub fn decrypt_session_key(
        self,
        remote_storage_key: &RemoteStorageKey,
    ) -> Result<OpaqueSessionKey, LockKeeperError> {
        let decrypted = self.decrypt_inner(&remote_storage_key.0)?;
        Ok(decrypted)
    }
}

/// The master key is a default-length symmetric encryption key for an
/// AEAD scheme.
///
/// The master key is used by the client to securely encrypt their
/// [`StorageKey`]. It should not be stored or saved beyond the lifetime of a
/// single authentication session. It should never be sent to the server or
/// passed out to the local calling application.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
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
    /// 2. Derive the decryption key from the master key, using the associated
    ///    data
    /// 3. Encrypt the storage key under the encryption key, using an AEAD
    ///    scheme
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
        Hkdf::<Sha3_256>::new(None, self.0.clone().into_bytes().as_ref())
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

impl Encrypted<Message> {
    pub fn decrypt_message(
        self,
        session_key: &OpaqueSessionKey,
    ) -> Result<Message, LockKeeperError> {
        let decrypted = self.decrypt_inner(&session_key.0)?;
        Ok(decrypted)
    }

    /// Translates an [`Encrypted<Message>`] to a [`Message`] in order to be
    /// sent through an authenticated channel.
    pub fn try_into_message(self) -> Result<Message, LockKeeperError> {
        let content = serde_json::to_vec(&self)?;

        Ok(Message { content })
    }

    /// Translates a [`Message`] received through an authenticated channel to an
    /// [`Encrypted<Message>`].
    pub fn try_from_message(message: Message) -> Result<Self, LockKeeperError> {
        Ok(serde_json::from_slice(&message.content)?)
    }
}

impl From<Vec<u8>> for Message {
    fn from(value: Vec<u8>) -> Self {
        Message { content: value }
    }
}

impl From<Message> for Vec<u8> {
    fn from(message: Message) -> Self {
        message.content
    }
}

/// Universally unique identifier for a stored secret or signing key.
/// Wrapped in a `Box` to avoid stack overflows during heavy traffic.
/// [KeyId]s are created by implementors of our DataStore trait. So we expose
/// the internal as pub.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "HexBytes", into = "HexBytes")]
pub struct KeyId(Box<[u8; 32]>);

impl IntoIterator for KeyId {
    type Item = u8;
    type IntoIter = IntoIter<u8, 32>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl TryFrom<&[u8]> for KeyId {
    type Error = TryFromSliceError;

    fn try_from(id: &[u8]) -> Result<Self, Self::Error> {
        Ok(KeyId(Box::new(<[u8; 32]>::try_from(id)?)))
    }
}

impl AsRef<[u8]> for KeyId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
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
        let user_id_length =
            u8::try_from(user_id.len()).map_err(|_| CryptoError::CannotEncodeDataLength)?;
        let random_len =
            u8::try_from(RANDOM_LEN).map_err(|_| CryptoError::CannotEncodeDataLength)?;

        let bytes = hasher
            .chain_update(domain_separator.len().to_be_bytes())
            .chain_update(domain_separator)
            .chain_update([user_id_length])
            .chain_update(user_id.as_bytes())
            .chain_update([random_len])
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

impl Debug for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = hex::encode(*self.0);
        f.debug_tuple("KeyId").field(&hex).finish()
    }
}

impl TryFrom<HexBytes> for KeyId {
    type Error = LockKeeperError;

    fn try_from(bytes: HexBytes) -> Result<Self, Self::Error> {
        Ok(KeyId(Box::new(bytes.try_into()?)))
    }
}

/// Raw material for an exported signing key.
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Export {
    pub key_material: Vec<u8>,
    #[zeroize(skip)]
    pub context: Vec<u8>,
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use crate::{
        types::operations::{get_user_id, ConvertMessage},
        LockKeeperError,
    };

    use super::*;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    // In practice, a session key will be a pseudorandom output from OPAQUE.
    // We'll use random bytes for the test key.
    pub(crate) fn create_test_session_key(
        rng: &mut (impl CryptoRng + RngCore),
    ) -> OpaqueSessionKey {
        let mut key = [0_u8; 64];
        rng.try_fill(&mut key)
            .expect("Failed to generate random key");

        OpaqueSessionKey::try_from(GenericArray::from(key)).expect("Failed to create Session Key")
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
    fn message_encryption_works() -> Result<(), LockKeeperError> {
        let mut rng = rand::thread_rng();
        let session_key = create_test_session_key(&mut rng);
        let user_id = UserId::new(&mut rng)?;

        // Set up matching RNGs to check behavior of the utility function.
        let seed = b"not-random seed for convenience!";
        let mut rng = StdRng::from_seed(*seed);

        // Encrypt a message
        let message = get_user_id::server::Response {
            user_id: user_id.clone(),
        }
        .to_message();
        let expected_message = get_user_id::server::Response { user_id };
        let encrypted_message = session_key.encrypt(&mut rng, message?)?;

        // Decrypt the message and check that it worked
        let decrypted_message = get_user_id::server::Response::from_message(
            encrypted_message.decrypt_message(&session_key)?,
        )?;
        assert_eq!(expected_message.user_id, decrypted_message.user_id);

        Ok(())
    }

    #[test]
    fn encrypted_message_to_message_and_back_conversion_works() -> Result<(), LockKeeperError> {
        let mut rng = rand::thread_rng();
        let session_key = create_test_session_key(&mut rng);
        let user_id = UserId::new(&mut rng)?;

        // Set up matching RNGs to check behavior of the utility function.
        let seed = b"not-random seed for convenience!";
        let mut rng = StdRng::from_seed(*seed);

        // Encrypt a message
        let message = get_user_id::server::Response { user_id }.to_message()?;
        let encrypted_message = session_key.encrypt(&mut rng, message)?;

        let result_to_message = encrypted_message.clone().try_into_message();
        assert!(result_to_message.is_ok());

        let result_from_message =
            Encrypted::<Message>::try_from_message(result_to_message.unwrap());
        assert!(result_from_message.is_ok());

        assert_eq!(encrypted_message, result_from_message.unwrap());

        Ok(())
    }

    #[test]
    fn session_key_to_vec_u8_conversion_works() -> Result<(), LockKeeperError> {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let session_key = create_test_session_key(&mut rng);

            let vec: Vec<u8> = session_key.clone().try_into()?;
            let output_session_key = vec.try_into()?;

            assert_eq!(session_key, output_session_key);
        }
        Ok(())
    }
}
