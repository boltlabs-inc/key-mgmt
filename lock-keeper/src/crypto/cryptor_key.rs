//! This defines [`CryptorKey`], which can be used to securely encrypt
//! data.

use super::CryptoError;

use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

use rand::{CryptoRng, RngCore};
use std::{iter, path::Path};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The [`CryptorKey`] type is a default-length symmetric encryption key
/// for an AEAD scheme. It can be used to securely encrypt data.
///
/// Note: we don't implement the Copy trait.
/// This is because implementing Copy could potentially lead to multiple copies
/// of the key in memory, which increases the chances of the key being leaked or
/// exposed.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CryptorKey {
    pub(super) key_material: Box<chacha20poly1305::Key>,
}

/// An implementation of the `std::fmt::Display` trait for `CryptorKey`
impl std::fmt::Display for CryptorKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {

        if cfg!(debug_assertions) {
            // this is a Debug build AND display sensitive info is ENABLED

            write!(
                f,
                "\n---Cryptor key begin---\n\n\
                \
                \tKey: 0x{key:02x?}\n\
                \tKey length: {key_len}\n\
                \
                \n---Cryptor key end---\n",
                key = self.key_material,
                key_len = self.key_material.len(),
            )

        } else {

            write!(
                f,
                "\n---Cryptor key begin---\n\n\
                \t{}\n\
                \n---Cryptor key end---\n",
                &CryptorKey::REDACTED_INFO
            )
        }

    }
}

/// An implementation of the `std::fmt::Debug` trait for `CryptorKey`
impl std::fmt::Debug for CryptorKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {

        let key_length = self.key_material.len();

        let key_material_hex = self
            .key_material
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join(" ");

        if cfg!(debug_assertions) {
            // this is a Debug build, so we can display sensitive info

            f.debug_struct("CryptorKey")
            .field("key_material", &key_material_hex)
            .field("key_length", &key_length)
            .finish()

        } else {

            write!(f, "CryptorKey {}", &CryptorKey::REDACTED_INFO)
        }
    }
}

impl CryptorKey {

    // sensitive info handling
    const REDACTED_INFO: &str = "REDACTED";

    /// Length of the encryption key in `bytes`
    const CRYPTOR_KEY_LENGTH: usize = 32;

    /// Generate a new symmetric AEAD encryption key from scratch.
    pub fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self {
            key_material: Box::new(ChaCha20Poly1305::generate_key(rng)),
        }
    }

    /// Returns the [`CryptorKey`] stored in a file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, CryptoError> {

        // read key from a file
        let bytes = std::fs::read(&path)
            .map_err(|e| CryptoError::FileIo(e, path.as_ref().to_path_buf()))?;

        Self::from_bytes(&bytes)
    }

    /// Returns the [`CryptorKey`] key based on key material in the caller's
    /// byte array.
    pub fn from_bytes(cryptor_key: &[u8]) -> Result<Self, CryptoError> {

        if cryptor_key.len() != CryptorKey::CRYPTOR_KEY_LENGTH {
            return Err(CryptoError::InvalidEncryptionKey);
        }

        // fixed size array initialized to zeros
        let mut key_bytes = [0; CryptorKey::CRYPTOR_KEY_LENGTH];
        // copy caller's key material
        key_bytes.copy_from_slice(cryptor_key);

        // return a new instance of CryptorKey
        Ok(Self {
            key_material: Box::new(key_bytes.into()),
        })
    }

    /// WARNING: this generates a copy of the key,
    /// and should only be used to derive another key from this key using a KDF.
    /// This should explicitly stay pub(super) to avoid abuse.
    #[allow(dead_code)]
    pub(super) fn into_bytes(self) -> [u8; CryptorKey::CRYPTOR_KEY_LENGTH] {
        (*self.key_material).into()
    }
}

/// Implementation of the `TryFrom` trait for converting from `CryptorKey` to
/// `Vec<u8>`
impl TryFrom<CryptorKey> for Vec<u8> {
    type Error = CryptoError;

    fn try_from(key: CryptorKey) -> Result<Self, Self::Error> {
        // len || key || context
        let key_length = u8::try_from(key.key_material.len())
            .map_err(|_| CryptoError::CannotEncodeDataLength)?;

        let bytes = iter::once(key_length).chain(*key.key_material).collect();
        Ok(bytes)
    }
}

/// Implementation of the `TryFrom` trait for converting from `Vec<u8>` to
/// `CryptorKey`
impl TryFrom<Vec<u8>> for CryptorKey {
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
        let _context: Vec<u8> = bytes
            .get(key_offset..)
            .ok_or(CryptoError::ConversionError)?
            .into();

        Ok(Self {
            key_material: Box::from(*chacha20poly1305::Key::from_slice(key)),
        })
    }
}

/// Tests...
#[cfg(test)]
pub(super) mod test {

    use super::*;
    use std::{fs, fs::File, io::Write};

    const CRYPTOR_KEY_FILENAME: &str = "temp_encryption_key.bin";

    /// Test the correctness of the sensitive information handling.
    /// 
    ///     In the Release build: sensitive info is expected to be REDACTED
    ///     In the Debug build: sensitive info can be displayed
    #[test]
    fn cryptor_key_sensitive_info_handling_on_debug_and_display() {
        let mut rng = rand::thread_rng();
        
        let encryption_key = CryptorKey::new(&mut rng);

        // create formatted strings for Debug and Display traits
        let debug_format_cryptor_key = format!("{:?}", encryption_key);
        let display_format_cryptor_key = format!("{}", encryption_key);

        println!("\nCryptor key debug:{:?}", debug_format_cryptor_key);
        println!("\nCryptor key display:{}", display_format_cryptor_key);

        // Calculate the expected state of redacted info based on the build type.
        //  False for the Debug build, True for the Release build.
        let should_be_redacted = !cfg!(debug_assertions);

        // check if output contains the redacted tag.
        let is_debug_redacted = debug_format_cryptor_key.contains(&CryptorKey::REDACTED_INFO);
        let is_display_redacted = display_format_cryptor_key.contains(&CryptorKey::REDACTED_INFO);

        // check if the redacted tag is applied correctly for Debug and Display traits.
        assert_eq!(is_debug_redacted, should_be_redacted,
                    "Unexpected debug output: {}",
                    if should_be_redacted { "Found UN-REDACTED info!!!" } else { "Found REDACTED info." });

        assert_eq!(is_display_redacted, should_be_redacted,
                    "Unexpected display output: {}",
                    if should_be_redacted { "Found UN-REDACTED info!!!" } else { "Found REDACTED info." });
    }

    /// Test the conversion from bytes to struct
    #[test]
    fn cryptor_key_from_bytes() -> Result<(), CryptoError> {
        let mut rng = rand::thread_rng();

        let encryption_key = CryptorKey::new(&mut rng);
        // clone the key bytes
        let encryption_key_bytes = encryption_key.key_material.clone();

        // use the cloned key bytes to create a new key
        let encryption_key_from_bytes =
            CryptorKey::from_bytes(&encryption_key_bytes)?;

        println!(
            "\nEncryption key: 0x{key:02x?}\n\
            Key length: {key_len}\n\
            \
            \nConverted encryption key:\n{converted_key}\n",
            key = encryption_key_bytes,
            key_len = encryption_key_bytes.len(),
            converted_key = encryption_key_from_bytes,
        );

        // compare the original key and the newly created key from the original key
        // bytes
        assert_eq!(encryption_key, encryption_key_from_bytes,);

        Ok(())
    }

    /// Test the conversion from struct to bytes
    #[test]
    fn cryptor_key_to_bytes() -> Result<(), CryptoError> {
        let mut rng = rand::thread_rng();

        let encryption_key = CryptorKey::new(&mut rng);

        println!("\nEncryption key:\n{key}", key = encryption_key);

        // clone here before we lose ownership
        let encryption_key_clone = encryption_key.clone();

        // convert the key to bytes
        let encryption_key_bytes = encryption_key.into_bytes();

        // create a new key from the converted bytes
        let new_encryption_key = CryptorKey::from_bytes(&encryption_key_bytes)?;

        println!("\nConverted encryption key:\n{key}", key = new_encryption_key);

        // compare the original key and the newly created key from the original key
        // bytes
        assert_eq!(encryption_key_clone, new_encryption_key);

        Ok(())
    }

    /// Test the conversion from bytes to struct when the length is wrong.
    #[test]
    fn key_from_bytes_wrong_length_fails() -> Result<(), CryptoError> {
        let mut rng = rand::thread_rng();

        let encryption_key = CryptorKey::new(&mut rng);
        let encryption_key_bytes = encryption_key.key_material.clone();

        println!(
            "\nEncryption key: 0x{key:02x?}\n\
            Key length: {key_len}",
            key = encryption_key_bytes,
            key_len = encryption_key_bytes.len(),
        );

        let new_encryption_key_from_bytes =
            CryptorKey::from_bytes(&encryption_key_bytes[..31]);

        println!(
            "\nConverted encryption key:\n{:02x?}\n\n",
            new_encryption_key_from_bytes
        );

        assert_eq!(
            new_encryption_key_from_bytes
                .unwrap_err()
                .to_string(),
            CryptoError::InvalidEncryptionKey.to_string()
        );

        Ok(())
    }

    /// Test reading a key from a file.
    #[test]
    fn key_from_file() -> Result<(), CryptoError> {
        // call the test helper function
        let result = key_from_file_helper();

        // Always try to delete the file, even if key_from_file_helper()
        // encountered an error.
        match fs::remove_file(CRYPTOR_KEY_FILENAME) {
            Ok(()) => (),
            Err(e) => println!("Failed to remove a temp key file: {}", e),
        }

        // Now handle the result of key_from_file_helper()
        match result {
            Ok(()) => (),
            Err(e) => println!("Test failed: {}", e),
        }

        Ok(())
    }

    /// Helper function, so we can handle read from file failures correctly.
    fn key_from_file_helper() -> Result<(), CryptoError> {
        const KEY_FILENAME: &str = "temp_encryption_key.bin";

        let mut rng = rand::thread_rng();

        let encryption_key = CryptorKey::new(&mut rng);

        // create a temp file to store the key
        let mut encryption_key_file = File::create(KEY_FILENAME)
            .expect("Failed to create a temp key file.");

        // clone it for later, before we lose ownership
        let encryption_key_original = encryption_key.clone();

        encryption_key_file
            .write_all(&encryption_key.into_bytes())
            .expect("Failed to write to a temp key file.");

        // read the key from a file
        let encryption_key_from_file = CryptorKey::from_file(KEY_FILENAME)?;

        println!("\nEncryption key:\n{key}", key = encryption_key_original);
        println!("\nEncryption key from a file:\n{key_from_file}",
            key_from_file = encryption_key_from_file
        );

        // make sure that key read from the file *is* the same as the original key
        if encryption_key_original != encryption_key_from_file {
            return Err(CryptoError::InvalidEncryptionKey);
        }

        Ok(())
    }

}
