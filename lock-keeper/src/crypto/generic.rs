use chacha20poly1305::{
    aead::{Aead, Payload},
    AeadCore, ChaCha20Poly1305, KeyInit,
};
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::{iter, marker::PhantomData};
use thiserror::Error;

#[cfg(test)]
use std::convert::Infallible;

/// Errors that arise in the cryptography module.
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
    #[error("Signature did not verify")]
    VerificationFailed,

    #[cfg(test)]
    #[error(transparent)]
    Infallible(#[from] Infallible),
}

/// The associated data used in [`Encrypted`] AEAD ciphertexts and
/// key derivations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(super) struct AssociatedData(Vec<u8>);

impl Default for AssociatedData {
    fn default() -> Self {
        Self(b"Version 0.2.".to_vec())
    }
}

impl TryFrom<Vec<u8>> for AssociatedData {
    type Error = CryptoError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(bytes))
    }
}

impl From<AssociatedData> for Vec<u8> {
    fn from(associated_data: AssociatedData) -> Self {
        associated_data.0
    }
}

impl<'a> From<&'a AssociatedData> for &'a [u8] {
    fn from(associated_data: &'a AssociatedData) -> Self {
        associated_data.0.as_ref()
    }
}

impl AssociatedData {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn with_str(self, ad: &str) -> Self {
        self.with_bytes(ad.bytes())
    }

    pub(super) fn with_bytes(self, ad: impl IntoIterator<Item = u8>) -> Self {
        AssociatedData(self.0.into_iter().chain(ad.into_iter()).collect())
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
    pub(super) associated_data: AssociatedData,
    nonce: chacha20poly1305::Nonce,
    original_type: PhantomData<T>,
}

/// A well-formed symmetric encryption key for an AEAD scheme.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct EncryptionKey {
    key: chacha20poly1305::Key,

    #[allow(unused)]
    context: AssociatedData,
}

impl EncryptionKey {
    /// Generate a new symmetric AEAD encryption key from scratch.
    pub(super) fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self {
            key: ChaCha20Poly1305::generate_key(rng),
            context: AssociatedData::new().with_str("ChaCha20Poly1305 with 96-bit nonce."),
        }
    }

    // Use the given bytes as a symmetric AEAD encryption key.
    pub(super) fn from_bytes(key_material: [u8; 32], context: AssociatedData) -> Self {
        Self {
            key: key_material.into(),
            context,
        }
    }

    // WARNING: this generates a copy from the key,
    // and should only be used to derive another key from this key using a KDF.
    // This should explicitly stay pub(super) to avoid abuse.
    pub(super) fn into_bytes(self) -> [u8; 32] {
        self.key.into()
    }
}

#[cfg(test)]
impl EncryptionKey {
    // Get the length of the key. This should always return 32.
    pub fn len(&self) -> usize {
        self.key.len()
    }

    /// Get the context for this key
    pub(super) fn context(&self) -> &AssociatedData {
        &self.context
    }
}

impl From<EncryptionKey> for Vec<u8> {
    fn from(key: EncryptionKey) -> Self {
        // len || key || context
        iter::once(key.key.len() as u8)
            .chain(key.key)
            .chain::<Vec<u8>>(key.context.into())
            .collect()
    }
}

impl TryFrom<Vec<u8>> for EncryptionKey {
    type Error = CryptoError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        // len (should always be 32) || key (32 bytes) || context (remainder)
        let len = *bytes.first().ok_or(CryptoError::ConversionError)? as usize;
        if len != 32 {
            return Err(CryptoError::ConversionError);
        }

        let key_offset = len + 1;
        let key = bytes
            .get(1..key_offset)
            .ok_or(CryptoError::ConversionError)?;
        let context: Vec<u8> = bytes
            .get(key_offset..)
            .ok_or(CryptoError::ConversionError)?
            .into();

        Ok(Self {
            key: *chacha20poly1305::Key::from_slice(key),
            context: context.try_into()?,
        })
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
    pub(super) fn encrypt(
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
    pub(super) fn decrypt(self, enc_key: &EncryptionKey) -> Result<T, CryptoError> {
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

/// A generic secret.
///
/// This type isn't public -- it holds generic secret material and associated
/// data, but does not enforce any properties on the key material.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub(super) struct Secret {
    /// The actual bytes of secret material.
    material: Vec<u8>,
    /// Additional context about the secret.
    context: AssociatedData,
}

impl Secret {
    /// Generate a new secret of length `len` (in bytes).
    pub(super) fn generate(
        rng: &mut (impl CryptoRng + RngCore),
        len: usize,
        context: AssociatedData,
    ) -> Self {
        Self {
            material: iter::repeat_with(|| rng.gen()).take(len).collect(),
            context,
        }
    }

    /// Create a new secret from its constituent parts.
    /// This is unchecked; use with care.
    pub(super) fn from_parts(secret_material: &[u8], context: &AssociatedData) -> Self {
        Self {
            material: secret_material.to_vec(),
            context: context.clone(),
        }
    }

    /// Retrieve the context for this secret.
    ///
    /// This is currently only used in testing, but it is fine to make it
    /// publicly accessible if necessary.
    #[cfg(test)]
    pub(super) fn context(&self) -> &AssociatedData {
        &self.context
    }

    /// Retrieve key material.
    ///
    /// Return a reference to the underlying bytes of the secret. This should
    /// only be used to print the secret.
    pub(super) fn get_material(&self) -> &[u8] {
        &self.material
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
        let key_offset = 1 + *bytes.first().ok_or(CryptoError::ConversionError)? as usize;
        let material = bytes
            .get(1..key_offset)
            .ok_or(CryptoError::ConversionError)?
            .into();

        let context_len = *bytes.get(key_offset).ok_or(CryptoError::ConversionError)? as usize;
        let context_offset = key_offset + 1;
        let context: Vec<u8> = bytes
            .get(context_offset..)
            .ok_or(CryptoError::ConversionError)?
            .into();
        if context.len() != context_len {
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

    use super::*;
    use rand::Rng;

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
            let data = AssociatedData(test.as_bytes().to_vec());

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
            let context = AssociatedData::new().with_str(&format!("a secret of length {}", len));
            let secret = Secret::generate(&mut rng, len, context);

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
    fn encryption_keys_are_32_bytes() {
        let mut rng = rand::thread_rng();
        let key = EncryptionKey::new(&mut rng);
        assert_eq!(32, key.len());
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
        let complicated_ad = AssociatedData::new()
            .with_str("here is a long, complex string\nfor testing. with details!");
        let secret = Secret::generate(&mut rng, 32, complicated_ad.clone());
        assert_eq!(secret.context, complicated_ad);
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
        encrypted_bytes.associated_data =
            AssociatedData::new().with_str("Here is some incorrect data");

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
}
