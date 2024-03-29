use std::path::PathBuf;

use chacha20poly1305::{
    aead::{Aead, Payload},
    AeadCore, ChaCha20Poly1305, KeyInit,
};
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::{iter, marker::PhantomData};
use thiserror::Error;

use k256::ecdsa;
use std::{convert::Infallible, mem::size_of};
use tracing::instrument;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Errors that arise in the cryptography module.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Length of data too large for our integer data type.
    #[error("Encryption/Decryption failed due to data length.")]
    CannotEncodeDataLength,
    #[error("Failed to combine shards into key: {0}")]
    CombineShardsFailed(String),
    #[error("Conversion error")]
    ConversionError,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error(transparent)]
    FromBase64(#[from] base64::DecodeError),
    #[error(transparent)]
    FromBincode(#[from] bincode::Error),
    #[error("Invalid encryption key")]
    InvalidEncryptionKey,
    #[error("Sensitive info check failed")]
    SensitiveInfoCheckFailed,

    /// The `impl<T> Encrypted<T>` has some trait bounds for converting a
    /// `TryFrom::Error` associated type into a CryptoError.
    /// Rust automatically implements `TryFrom<T, Error=Infallible>` when
    /// `From<T>` is implemented. This variant ensures `impl
    /// From<CryptoError> for Infallible` holds true in this case.
    #[error(transparent)]
    Infallible(#[from] Infallible),
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(hkdf::InvalidLength),
    #[error("Failed to convert scalar to non-zero scalar.")]
    NonZeroScalarConversion,
    #[error("RNG failed")]
    RandomNumberGeneratorFailed,
    #[error("Incorrect size for seal key: {0}.")]
    IncorrectSealKeySize(usize),
    #[error("Signature generation failed: {0}")]
    Signature(#[from] ecdsa::signature::Error),
    #[error("Failed to decrypt shard: {0}")]
    ShardDecryptionFailed(String),
    #[error("Failed to encrypt shard: {0}")]
    ShardEncryptionFailed(String),
    #[error("Failed split key into shards: {0}")]
    ShardingFailed(String),
    #[error("Signature did not verify")]
    VerificationFailed,

    /// IO error specific to file IO failing. Allows us to include the file that
    /// failed as part of the error.
    #[error("File IO error. Cause: {0}. On file: {1}")]
    FileIo(std::io::Error, PathBuf),
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
        AssociatedData(self.0.into_iter().chain(ad).collect())
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
    pub(super) ciphertext: Vec<u8>,
    pub(super) associated_data: AssociatedData,
    pub(super) nonce: chacha20poly1305::Nonce,
    pub(super) original_type: PhantomData<T>,
}

/// A well-formed symmetric encryption key for an AEAD scheme.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Zeroize, ZeroizeOnDrop)]
pub(super) struct EncryptionKey {
    key: Box<chacha20poly1305::Key>,

    #[allow(unused)]
    #[zeroize(skip)]
    pub(super) context: AssociatedData,
}

impl EncryptionKey {
    pub(super) fn domain_separator() -> &'static str {
        "ChaCha20Poly1305 with 96-bit nonce."
    }

    /// Generate a new symmetric AEAD encryption key from scratch.
    pub(super) fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self {
            key: Box::new(ChaCha20Poly1305::generate_key(rng)),
            context: AssociatedData::new().with_str(Self::domain_separator()),
        }
    }

    // Use the given bytes as a symmetric AEAD encryption key.
    pub(super) fn from_bytes(key_material: [u8; 32], context: AssociatedData) -> Self {
        Self {
            key: Box::new(key_material.into()),
            context,
        }
    }

    // WARNING: this generates a copy from the key,
    // and should only be used to derive another key from this key using a KDF.
    // This should explicitly stay pub(super) to avoid abuse.
    pub(super) fn into_bytes(self) -> [u8; 32] {
        (*self.key).into()
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

impl TryFrom<EncryptionKey> for Vec<u8> {
    type Error = CryptoError;

    fn try_from(key: EncryptionKey) -> Result<Self, Self::Error> {
        // len || key || context
        let key_length =
            u8::try_from(key.key.len()).map_err(|_| CryptoError::CannotEncodeDataLength)?;
        let associated_data = Vec::<u8>::from(key.context.to_owned());

        let bytes = iter::once(key_length)
            .chain(*key.key)
            .chain(associated_data)
            .collect();
        Ok(bytes)
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
            key: Box::from(*chacha20poly1305::Key::from_slice(key)),
            context: context.try_into()?,
        })
    }
}

impl<T> Encrypted<T>
where
    // These bounds cover both the `encrypt` and `decrypt` methods.
    // This ensures that the user can only encrypt types than can also be decrypted.

    // These two bounds state:
    // "A Vec<u8> can be converted into our T via TryFrom...
    T: TryFrom<Vec<u8>>,
    // ...where the associated Error type of the TryFrom can be converted into a CryptoError via
    // From"
    CryptoError: From<<T as TryFrom<Vec<u8>>>::Error>,

    // These two bounds state:
    // "Our T can be converted into a Vec<u8> via TryFrom...
    Vec<u8>: TryFrom<T>,
    // ...where the associated Error type of the TryFrom can be converted into a CryptoError via
    // From"
    CryptoError: From<<Vec<u8> as TryFrom<T>>::Error>,
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
            msg: &Vec::try_from(object)?,
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
    pub(super) fn decrypt_inner(self, enc_key: &EncryptionKey) -> Result<T, CryptoError> {
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
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub(super) struct Secret {
    /// The actual bytes of secret material.
    material: Vec<u8>,
    /// Additional context about the secret.
    #[zeroize(skip)]
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
    pub(super) fn from_parts(secret_material: Vec<u8>, context: AssociatedData) -> Self {
        Self {
            material: secret_material,
            context,
        }
    }

    /// Retrieve the context for this secret.
    ///
    /// This is currently only used in testing, but it is fine to make it
    /// publicly accessible if necessary.
    pub(super) fn context(&self) -> &AssociatedData {
        &self.context
    }

    /// Retrieve key material.
    ///
    /// Return a reference to the underlying bytes of the secret. This should
    /// only be used to print the secret.
    pub(super) fn borrow_material(&self) -> &[u8] {
        &self.material
    }
}

impl TryFrom<Secret> for Vec<u8> {
    type Error = CryptoError;

    fn try_from(secret: Secret) -> Result<Self, Self::Error> {
        // key len || key material || context len || context
        let ad: Vec<u8> = secret.context.to_owned().into();
        let secret_length = u16::try_from(secret.material.len())
            .map_err(|_| CryptoError::CannotEncodeDataLength)?;
        let ad_length = u16::try_from(ad.len()).map_err(|_| CryptoError::CannotEncodeDataLength)?;

        let bytes = secret_length
            .to_be_bytes()
            .into_iter()
            .chain(secret.material.to_owned())
            .chain(ad_length.to_be_bytes())
            .chain(ad)
            .collect();
        Ok(bytes)
    }
}

impl TryFrom<Vec<u8>> for Secret {
    type Error = CryptoError;

    #[instrument(skip_all)]
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        // key len (2 bytes) || key material || context len (2 byte) || context
        let mut parse = ParseBytes::new(bytes);

        let data_length = parse.take_bytes_as_u16()?;
        let material = parse.take_bytes(data_length as usize)?.to_vec();
        let context_length = parse.take_bytes_as_u16()?;
        let context: Vec<u8> = parse.take_rest()?.to_vec();

        if context.len() != context_length as usize {
            return Err(CryptoError::ConversionError);
        }

        Ok(Self {
            material,
            context: context.try_into()?,
        })
    }
}

/// Helper type for parsing byte array into integers and slices.
#[derive(ZeroizeOnDrop)]
pub(super) struct ParseBytes {
    bytes: Vec<u8>,
    offset: usize,
}

impl ParseBytes {
    pub fn new(bytes: Vec<u8>) -> ParseBytes {
        ParseBytes { bytes, offset: 0 }
    }

    /// Take next `n` bytes from array.
    pub fn take_bytes(&mut self, n: usize) -> Result<&[u8], CryptoError> {
        let slice = &self
            .bytes
            .get(self.offset..self.offset + n)
            .ok_or(CryptoError::ConversionError)?;
        self.offset += n;
        Ok(slice)
    }

    /// Take next two bytes and convert them into a u16.
    pub fn take_bytes_as_u16(&mut self) -> Result<u16, CryptoError> {
        let &[f, s] = self.take_bytes(size_of::<u16>())? else {
            return Err(CryptoError::ConversionError);
        };
        Ok(u16::from_be_bytes([f, s]))
    }

    /// Take the rest of the bytes from the array.
    pub fn take_rest(&mut self) -> Result<&[u8], CryptoError> {
        self.bytes
            .get(self.offset..)
            .ok_or(CryptoError::ConversionError)
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use super::*;
    use crate::LockKeeperError;
    use rand::Rng;

    #[test]
    fn parse_bytes_works() -> Result<(), CryptoError> {
        let mut bytes = ParseBytes::new(vec![0, 5, 6, 7, 8, 9, 10, 11]);

        // We encoded 5 as 2 bytes in our vec. Ensure this matches.
        let n = bytes.take_bytes_as_u16()?;
        assert_eq!(n, 5);

        // Take `n` bytes.
        assert_eq!(bytes.take_bytes(n as usize)?, &[6, 7, 8, 9, 10]);

        assert_eq!(bytes.take_rest()?, &[11]);
        Ok(())
    }

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
            let context = AssociatedData::new().with_str(&format!("a secret of length {len}"));
            let secret = Secret::generate(&mut rng, len, context);

            let secret_vec: Vec<u8> = secret.clone().try_into()?;
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

            let bytes: Vec<u8> = encryption_key.clone().try_into()?;
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
            .map(
                |_| Secret::generate(&mut rng, 32, AssociatedData::default())
                    .material
                    .to_owned()
            )
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

    /// A struct wrapped around a byte vector to add ZeroizeOnDrop
    #[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
    struct RandomBytes(Vec<u8>);

    impl From<RandomBytes> for Vec<u8> {
        fn from(bytes: RandomBytes) -> Self {
            bytes.0.clone()
        }
    }

    impl TryFrom<Vec<u8>> for RandomBytes {
        type Error = CryptoError;
        fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
            Ok(Self(bytes))
        }
    }

    /// Generates random bytes, encrypts them, and returns them along with the
    /// key used for encryption.
    fn encrypt_random_bytes(
        rng: &mut (impl CryptoRng + RngCore),
    ) -> (RandomBytes, Encrypted<RandomBytes>, EncryptionKey) {
        let bytes: RandomBytes =
            RandomBytes(std::iter::repeat_with(|| rng.gen()).take(64).collect());
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
            assert_ne!(bytes, RandomBytes(encrypted_bytes.ciphertext.clone()));
            assert_ne!(Vec::from([0; 32]), encrypted_bytes.ciphertext);

            // Make sure encrypted object includes the expected associated data.
            let expected_aad = AssociatedData::default();
            assert_eq!(expected_aad, encrypted_bytes.associated_data);

            let decrypted_bytes = encrypted_bytes.decrypt_inner(&enc_key)?;
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
            assert!(encrypted_bytes.decrypt_inner(&enc_key).is_err());
        }
    }

    #[test]
    fn decryption_fails_with_wrong_key() {
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let (_, encrypted_bytes, _) = encrypt_random_bytes(&mut rng);
            let wrong_key = EncryptionKey::new(&mut rand::thread_rng());

            assert!(encrypted_bytes.decrypt_inner(&wrong_key).is_err());
        }
    }

    #[test]
    fn decryption_fails_with_wrong_associated_data() {
        let mut rng = rand::thread_rng();
        let (_, mut encrypted_bytes, enc_key) = encrypt_random_bytes(&mut rng);
        encrypted_bytes.associated_data =
            AssociatedData::new().with_str("Here is some incorrect data");

        assert!(encrypted_bytes.decrypt_inner(&enc_key).is_err())
    }

    #[test]
    fn decryption_fails_with_tweaked_ciphertext() {
        let mut rng = rand::thread_rng();

        for _ in 0..100 {
            let (_, mut encrypted_bytes, enc_key) = encrypt_random_bytes(&mut rng);
            encrypted_bytes.ciphertext[0] ^= 1;
            assert!(encrypted_bytes.decrypt_inner(&enc_key).is_err());

            let (_, mut encrypted_bytes, enc_key) = encrypt_random_bytes(&mut rng);
            let len = encrypted_bytes.ciphertext.len();
            encrypted_bytes.ciphertext[len - 1] ^= 1;
            assert!(encrypted_bytes.decrypt_inner(&enc_key).is_err());

            let (_, mut encrypted_bytes, enc_key) = encrypt_random_bytes(&mut rng);
            encrypted_bytes.ciphertext[len / 2] ^= 1;
            assert!(encrypted_bytes.decrypt_inner(&enc_key).is_err());
        }
    }

    #[test]
    fn encryption_key_gets_zeroized() -> Result<(), LockKeeperError> {
        let key_bytes = [1; 32];
        let key = EncryptionKey::from_bytes(key_bytes, AssociatedData::default());
        let ptr = key.key.as_ptr();

        drop(key);

        let after_drop = unsafe { core::slice::from_raw_parts(ptr, 32) };
        assert_ne!(key_bytes, after_drop);
        Ok(())
    }
}
