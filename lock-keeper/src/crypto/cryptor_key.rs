//! This defines [`CryptorKey`] type, which is an encryption key that can be used to securely encrypt/decrypt
//! data.

use super::CryptoError;

use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

use rand::{CryptoRng, RngCore};
use std::{path::Path};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::infrastructure::sensitive_info::SensitiveInfoConfig;

/// The [`CryptorKey`] type is a default-length symmetric encryption key
/// for an AEAD scheme. It can be used to securely encrypt data.
///
/// Note: we don't implement the Copy trait.
/// This is because implementing Copy could potentially lead to multiple copies
/// of the key in memory, which increases the chances of the key being leaked or
/// exposed.
#[derive(Clone, Eq, Zeroize, ZeroizeOnDrop)]
pub struct CryptorKey {
    pub(super) key_material: Box<chacha20poly1305::Key>,
    config: SensitiveInfoConfig,
}

/// An implementation of the `std::fmt::Display` trait for [`CryptorKey`]
impl std::fmt::Display for CryptorKey {

    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {

        if cfg!(debug_assertions) && !self.config.is_redacted() {

            // this is a Debug build *AND* redacted flag is FALSE
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
            
            // this is a Release build *OR* redacted flag is TRUE
            write!(
                f,

                "\n---Cryptor key begin---\n\n\
                \t{redacted}\n\
                \n---Cryptor key end---\n",

                redacted=self.config.clone().redacted_label(),
            )
        }
    }
}

/// An implementation of the `std::fmt::Debug` trait for [`CryptorKey`]
impl std::fmt::Debug for CryptorKey {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {

        if cfg!(debug_assertions) && !self.config.is_redacted() {
            // this is a Debug build *AND* redacted flag is FALSE
            f.debug_struct("CryptorKey")
            .field("key_material", &self.key_material)
            .finish()

        } else {

            // this is a Release build *OR* redacted flag is TRUE
            write!(f, "CryptorKey {}", self.config.clone().redacted_label())
        }
    }
}

/// Implement the `PartialEq` trait for the [`CryptorKey`] type.
impl PartialEq for CryptorKey {

    /// Determines if two [`CryptorKey`] instances are equal.
    ///
    /// This function compares the `key_material` fields of two [`CryptorKey`] instances.
    /// It does not compare the `config` fields because the `config` field does not affect the functional equivalence of two [`CryptorKey`] instances.
    ///
    /// # Arguments
    ///
    /// * `other` - The other [`CryptorKey`] instance to compare with.
    ///
    /// # Returns
    ///
    /// Returns `true` if the `data` and `context` fields are equal between the two [`CryptorKey`] instances, 
    /// Otherwise returns `false`.
    fn eq(&self, other: &Self) -> bool {

        // Don't compare the config fields
        self.key_material == other.key_material
    }
}


/// Implementation for [`CryptorKey`]
impl CryptorKey {

    /// Length of the encryption key in `bytes`
    const CRYPTOR_KEY_LENGTH: usize = 32;

    /// Constructs a new instance of the [`CryptorKey`] type.
    ///
    /// # Arguments
    ///
    /// * `rng` - A mutable reference to an object implementing both the `CryptoRng` and `RngCore` traits. 
    ///           This is used to generate the cryptographic key for the ChaCha20Poly1305 algorithm.
    ///
    /// # Returns
    ///
    /// Returns a new instance of the [`CryptorKey`] type with a fresh cryptographic key generated via the provided random number generator (`rng`) and a new [`SensitiveInfoConfig`] object.
    ///
    /// A [`CryptorKey`] is generated uniformly at random. It is a 32-byte pseudorandom key for use in the [ChaCha20Poly1305 scheme](https://www.rfc-editor.org/rfc/rfc8439) for
    /// authenticated encryption with associated data (AEAD).
    pub fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self {

        Self {
            key_material: Box::new(ChaCha20Poly1305::generate_key(rng)),
            config: SensitiveInfoConfig::new(true),
        }
    }

    /// Returns the [`CryptorKey`] stored in a file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, CryptoError> {

        // read key from a file
        let mut key_bytes = std::fs::read(&path)
            .map_err(|e| CryptoError::FileIo(e, path.as_ref().to_path_buf()))?;

        let cryptor_key = Self::from_bytes(&key_bytes);
        key_bytes.zeroize();

        cryptor_key
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

        Ok(Self {
            key_material: Box::new(key_bytes.into()),
            config: SensitiveInfoConfig::new(true),
        })
    }

    /// Converts [`CryptorKey`] to a byte array.
    pub fn into_bytes(self) -> [u8; CryptorKey::CRYPTOR_KEY_LENGTH] {

        (*self.key_material).into()
    }
}

/// Tests...
#[cfg(test)]
pub(super) mod test {

    use super::*;
    use std::{fs, fs::File, io::Write};
    use crate::infrastructure::sensitive_info::sensitive_info_check;    

    const CRYPTOR_KEY_FILENAME: &str = "temp_encryption_key.bin";

    /// Test the correctness of the sensitive information handling.
    #[test]
    fn cryptor_key_sensitive_info_handling_on_debug_and_display() {

        let mut rng = rand::thread_rng();
        let mut encryption_key = CryptorKey::new(&mut rng);

        // sensitive information should be redacted by default, let's test...
        sensitive_info_check(&encryption_key, &encryption_key.config).unwrap();

        // unredact sensitive information, and test
        encryption_key.config.unredact();
        sensitive_info_check(&encryption_key, &encryption_key.config).unwrap();
    }

    /// Test the conversion from bytes to struct
    #[test]
    fn cryptor_key_from_bytes() -> Result<(), CryptoError> {

        let mut rng = rand::thread_rng();

        let encryption_key = CryptorKey::new(&mut rng);

        // use the cloned key bytes to create a new key
        let encryption_key_bytes = encryption_key.key_material.clone();        
        let mut encryption_key_from_bytes = CryptorKey::from_bytes(&encryption_key_bytes)?;
        // allow sensitive info to be shown
        encryption_key_from_bytes.config.unredact();

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

    /// Test the conversion from bytes to struct when the length is wrong.
    #[test]
    fn key_from_bytes_wrong_length_fails() -> Result<(), CryptoError> {

        // test conversion with a key byte array that is TOO SHORT
        let number_of_key_bytes = CryptorKey::CRYPTOR_KEY_LENGTH-1;
        let key_bytes = vec![0xab; number_of_key_bytes];

        let new_encryption_key_from_bytes = CryptorKey::from_bytes(&key_bytes);

        println!(
            "\nConvert encryption key using {number_of_key_bytes} bytes:\n{new_encryption_key_from_bytes:x?}\n\n",
            number_of_key_bytes=number_of_key_bytes,
            new_encryption_key_from_bytes=new_encryption_key_from_bytes,
        );

        // make sure we have an invalid key error
        assert_eq!(
            new_encryption_key_from_bytes
                .unwrap_err()
                .to_string(),
            CryptoError::InvalidEncryptionKey.to_string()
        );

        // test conversion with a key byte array that is TOO LONG
        let number_of_key_bytes = CryptorKey::CRYPTOR_KEY_LENGTH+1;
        let key_bytes = vec![0xab; number_of_key_bytes];

        let new_encryption_key_from_bytes =
            CryptorKey::from_bytes(&key_bytes);

        println!(
            "\nConvert encryption key using {number_of_key_bytes} bytes:\n{new_encryption_key_from_bytes:02x?}\n\n",
            number_of_key_bytes=number_of_key_bytes,
            new_encryption_key_from_bytes=new_encryption_key_from_bytes,
        );

        // make sure we have an invalid key error
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

        // Use a helper function to write/read the key to/from a file.
        // That way we can clean up the temp file in success and failure cases.
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
        let mut encryption_key_original = encryption_key.clone();

        encryption_key_file
            .write_all(&encryption_key.into_bytes())
            .expect("Failed to write to a temp key file.");

        // read the key from a file
        let mut encryption_key_from_file = CryptorKey::from_file(KEY_FILENAME)?;

        // allow sensitive info to be shown
        encryption_key_from_file.config.unredact();
        encryption_key_original.config.unredact();

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
