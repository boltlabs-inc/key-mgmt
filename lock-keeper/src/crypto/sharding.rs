use crate::crypto::{CryptoError, SigningPrivateKey, SigningPublicKey};
use aes_gcm::{aead::Aead, AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use k256::Scalar;
use rand::{rngs::OsRng, CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Formatter},
    ops::Deref,
};
use vsss_rs::{combine_shares, shamir};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// KMS Seal Key used for encryption and decryption.
///
/// It is currently a 256-bit value.
pub const SEAL_KEY_LENGTH: usize = 32;
// Note: These no longer need to be constants. In the future we will allow
// the caller to select these values dynamically.
pub const NUM_SHARDS: usize = 3;
pub const SHARD_THRESHOLD: usize = 3;

/// KMS Seal Key used for encryption and decryption.
///
/// We implement `Debug` and `Clone` because enclave codes relies on it.
#[derive(Clone, Eq, PartialEq, ZeroizeOnDrop)]
pub struct SealKey {
    /// Our seal key is represented as a [`SEAL_KEY_LENGTH`] byte array.
    material: [u8; SEAL_KEY_LENGTH],
}

impl SealKey {
    pub const fn new(seal_key: [u8; SEAL_KEY_LENGTH]) -> Self {
        Self { material: seal_key }
    }

    /// Convert key into a format that [`aes_gcm`] understands.
    fn as_aes256gcm(&self) -> &Key<Aes256Gcm> {
        self.material().into()
    }

    pub fn material(&self) -> &[u8] {
        &self.material
    }
}

impl Debug for SealKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealKey")
            .field("material", &"REDACTED")
            .finish()
    }
}

impl TryFrom<Vec<u8>> for SealKey {
    type Error = CryptoError;

    fn try_from(material: Vec<u8>) -> Result<Self, Self::Error> {
        let length = material.len();
        let material = <[u8; SEAL_KEY_LENGTH]>::try_from(material)
            .map_err(|_| CryptoError::IncorrectSealKeySize(length))?;
        Ok(SealKey::new(material))
    }
}

impl SigningPrivateKey {
    /// Given a [`SigningPrivateKey`] shard and encrypt it using the `seal_key`.
    ///
    /// Note: `self` (`SigningPrivateKey`) will be zeroized as this value is
    /// dropped.
    pub fn shard_key_and_encrypt(
        self,
        seal_key: &SealKey,
    ) -> Result<Vec<EncryptedShard>, CryptoError> {
        let shards = shamir::split_secret::<Scalar, u8, Vec<u8>>(
            SHARD_THRESHOLD,
            NUM_SHARDS,
            *self.as_nonzero_scalar().deref(),
            &mut OsRng,
        )
        .map_err(|e| CryptoError::ShardingFailed(e.to_string()))?;

        // Encrypt shards. (`shards` consumed by `UnencryptedShard` constructor, so
        // no need to zeroize this value.)
        shards
            .into_iter()
            .map(|shard| UnencryptedShard::new(shard).encrypt_shard(seal_key))
            .collect()
    }

    /// Rebuild the [`SigningPrivateKey`] from its encrypted shards using the
    /// specified `seal_key`.
    ///
    /// 1) Decrypt each shard with the given `seal_key`.
    /// 2) Rebuild key from decrypted shards.
    pub fn rebuild_key_from_encrypted_shards(
        encrypted_shards: Vec<EncryptedShard>,
        seal_key: &SealKey,
    ) -> Result<Self, CryptoError> {
        let unencrypted_shards: Vec<UnencryptedShard> = encrypted_shards
            .into_iter()
            .map(|shard| shard.decrypt_shard(seal_key))
            .collect::<Result<_, _>>()?;

        Self::rebuild_key_from_shards(unencrypted_shards)
    }

    /// Combine a vector of unencrypted shards into a `SigningPrivateKey`.
    fn rebuild_key_from_shards(
        shards: Vec<UnencryptedShard>,
    ) -> Result<SigningPrivateKey, CryptoError> {
        // Put shards in the format `combine_shares` expects.
        let shards: Vec<Vec<u8>> = shards.into_iter().map(|shard| shard.material).collect();
        let results = combine_shares(&shards);

        // We no longer need the unencrypted shards. Zeroize them.
        shards.into_iter().for_each(|mut shard| shard.zeroize());

        let scalar: Scalar =
            results.map_err(|e| CryptoError::CombineShardsFailed(e.to_string()))?;

        // Safe unwrap, we just handled the none case.
        SigningPrivateKey::from_bytes(scalar.to_bytes().as_slice())
    }
}

/// An unecrypted shard. Handle with care!
///
/// This type does not implement `ZeroizeOnDrop` as the `material` must taken
/// to rebuild the original signing key. You must call zeroize yourself.
#[derive(Zeroize, Eq, PartialEq, Clone)]
pub struct UnencryptedShard {
    material: Vec<u8>,
}

impl UnencryptedShard {
    /// New [`UnencryptedShard`] takes ownership of data to avoid copy/clone.
    fn new(material: Vec<u8>) -> Self {
        UnencryptedShard { material }
    }

    fn encrypt_shard(mut self, seal_key: &SealKey) -> Result<EncryptedShard, CryptoError> {
        let nonce: Nonce<_> = Aes256Gcm::generate_nonce(&mut OsRng);
        let cipher = Aes256Gcm::new(seal_key.as_aes256gcm());

        // Encrypt shard, zeroize unecrypted shard regardless of the results of encrypt.
        let result = cipher.encrypt(&nonce, self.material.as_slice());
        self.material.zeroize();
        let encrypted = result.map_err(|e| CryptoError::ShardEncryptionFailed(e.to_string()))?;

        Ok(EncryptedShard { encrypted, nonce })
    }
}

impl Debug for UnencryptedShard {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnencryptedShard")
            .field("material", &"REDACTED")
            .finish()
    }
}

/// Maestro key pair made up of a `public_key` and `encrypted_shards`.
/// The shards represent the private key that has been sharded, those
/// shards are then encrypted by a seal key.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ShardedSigningKeyPair {
    public_key: SigningPublicKey,
    encrypted_shards: Vec<EncryptedShard>,
}

impl ShardedSigningKeyPair {
    /// This function generates a new random `[SigningPrivateKey]` using the
    /// given `rng`. Then, it shards the private key component and encrypts
    /// those shards with the given `seal_key`.
    pub fn create_and_encrypt(
        seal_key: &SealKey,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<ShardedSigningKeyPair, CryptoError> {
        let key_pair = SigningPrivateKey::generate(rng);

        let key_data = ShardedSigningKeyPair {
            public_key: key_pair.public_key(),
            encrypted_shards: key_pair.shard_key_and_encrypt(seal_key)?,
        };
        Ok(key_data)
    }

    /// Get a reference to the public key.
    pub fn public_key(&self) -> &SigningPublicKey {
        &self.public_key
    }

    /// Get a reference to the encrypted shards.
    pub fn shards(&self) -> &[EncryptedShard] {
        &self.encrypted_shards
    }

    /// Take the shards from this `[ShardedSigningKeyPair]`.
    pub fn into_shards(self) -> Vec<EncryptedShard> {
        self.encrypted_shards
    }

    /// Convert the `[ShardedSigningKeyPair]` into its constituent parts.
    pub fn into_parts(self) -> (SigningPublicKey, Vec<EncryptedShard>) {
        (self.public_key, self.encrypted_shards)
    }
}

/// A shard that has been encrypted with a given seal key. The same key must be
/// used for decryption.
///
/// This type includes the nonce used for encryption.
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedShard {
    /// Encrypted material for this shard.
    encrypted: Vec<u8>,
    // Nonce used to encrypt this shard.
    nonce: Nonce<<Aes256Gcm as AeadCore>::NonceSize>,
}

impl EncryptedShard {
    fn decrypt_shard(self, seal_key: &SealKey) -> Result<UnencryptedShard, CryptoError> {
        let cipher = Aes256Gcm::new(seal_key.as_aes256gcm());

        let decrypted = cipher
            .decrypt(&self.nonce, self.encrypted.as_slice())
            .map_err(|e| CryptoError::ShardDecryptionFailed(e.to_string()))?;
        Ok(UnencryptedShard::new(decrypted))
    }
}

impl Debug for EncryptedShard {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedShard")
            .field("encrypted", &"REDACTED")
            .field("nonce", &"REDACTED")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::{
        sharding::{SealKey, UnencryptedShard, NUM_SHARDS},
        SigningPrivateKey,
    };
    use rand::{rngs::OsRng, Rng};

    /// Hardcoded testing seal key for testing.
    const TESTING_SEAL_KEY: SealKey = SealKey::new([
        249, 95, 53, 174, 82, 104, 71, 122, 147, 115, 101, 210, 113, 233, 22, 31, 46, 191, 19, 167,
        45, 199, 77, 215, 193, 41, 153, 197, 10, 193, 255, 145,
    ]);

    const TESTING_SEAL_KEY_2: SealKey = SealKey::new([
        255, 38, 23, 174, 56, 104, 71, 122, 147, 115, 101, 210, 113, 233, 22, 31, 46, 191, 19, 167,
        45, 199, 77, 215, 193, 41, 153, 197, 10, 193, 255, 42,
    ]);

    /// Create a random [`UnencryptedShard`].
    fn random_shard() -> UnencryptedShard {
        let rng = &mut OsRng;
        // Create buffer to fill (length chosen arbitrarily).
        let mut material: [u8; 128] = [0; 128];
        rng.fill(&mut material);
        UnencryptedShard::new(material.to_vec())
    }

    #[test]
    fn shard_roundtrip_works() {
        let shard = random_shard();
        // Make clone shard for comparison.
        let shard_copy = shard.clone();

        let encrypted = shard.encrypt_shard(&TESTING_SEAL_KEY).unwrap();
        let decrypted = encrypted.decrypt_shard(&TESTING_SEAL_KEY).unwrap();
        assert_eq!(shard_copy, decrypted, "Shards should be equal.");
    }

    #[test]
    fn can_only_decrypt_shard_with_correct_seal_key() {
        let shard = random_shard();
        let encrypted = shard.encrypt_shard(&TESTING_SEAL_KEY).unwrap();

        // Try decrypting with different seal key.
        assert!(
            encrypted.decrypt_shard(&TESTING_SEAL_KEY_2).is_err(),
            "Decrypting with wrong seal key should fail."
        );
    }

    #[test]
    fn encrypt_and_shard_key_works() {
        let private_key = SigningPrivateKey::generate(&mut OsRng);
        let encrypted = private_key
            .shard_key_and_encrypt(&TESTING_SEAL_KEY)
            .unwrap();
        assert_eq!(encrypted.len(), NUM_SHARDS, "Unexpected number of shards");
    }

    #[test]
    fn key_roundtrip_works() {
        let private_key = SigningPrivateKey::generate(&mut OsRng);
        let encrypted = private_key
            .clone()
            .shard_key_and_encrypt(&TESTING_SEAL_KEY)
            .unwrap();
        let private_key2 =
            SigningPrivateKey::rebuild_key_from_encrypted_shards(encrypted, &TESTING_SEAL_KEY)
                .unwrap();
        assert_eq!(
            private_key, private_key2,
            "Keys look is different after sharding and reconstruction"
        );
    }

    #[test]
    fn key_roundtrip_works_only_with_correct_seal_key() {
        let private_key = SigningPrivateKey::generate(&mut OsRng);
        let encrypted = private_key
            .shard_key_and_encrypt(&TESTING_SEAL_KEY)
            .unwrap();

        // Try decrypting with different seal key.
        assert!(
            SigningPrivateKey::rebuild_key_from_encrypted_shards(encrypted, &TESTING_SEAL_KEY_2)
                .is_err(),
            "Decrypting with wrong seal key should fail."
        );
    }
}
