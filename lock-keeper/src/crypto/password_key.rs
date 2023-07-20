//! This defines [`PasswordKey`], which can be used to securely encrypt
//! `Password`

use super::CryptoError;

use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

use rand::{CryptoRng, RngCore};
use std::{iter, path::Path};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The [`PasswordKey`] type is a default-length symmetric encryption key
/// for an AEAD scheme. It can be used to securely encrypt passwords.
///
/// Note: we don't implement the Copy trait.
/// This is because implementing Copy could potentially lead to multiple copies
/// of the key in memory, which increases the chances of the key being leaked or
/// exposed.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PasswordKey {
    pub(super) key_material: Box<chacha20poly1305::Key>,
}

/// An implementation of the `std::fmt::Display` trait for `PasswordKey`
impl std::fmt::Display for PasswordKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "\n---Password Key begin---\n\n\
            \
            \tKey: 0x{key:02x?}\n\
            \tKey length: {key_len}\n\
            \
            \n---Password Key end---\n",
            key = self.key_material,
            key_len = self.key_material.len(),
        )
    }
}

impl PasswordKey {
    /// Length of the password encryption key in `bytes`
    const PASSWORD_KEY_LENGTH: usize = 32;

    /// Generate a new symmetric AEAD encryption key from scratch.
    pub(super) fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self {
            key_material: Box::new(ChaCha20Poly1305::generate_key(rng)),
        }
    }

    /// Generate a new 32-byte [`PasswordKey`].
    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self::new(rng)
    }

    /// Returns the [`PasswordKey`] stored in a file.
    pub fn read_from_file(path: impl AsRef<Path>) -> Result<Self, CryptoError> {
        let bytes = std::fs::read(&path)
            .map_err(|e| CryptoError::FileIo(e, path.as_ref().to_path_buf()))?;

        Self::from_bytes(&bytes)
    }

    /// Returns the [`PasswordKey`] key based on key material in the caller's
    /// byte array.
    fn from_bytes(key_material: &[u8]) -> Result<Self, CryptoError> {
        if key_material.len() != PasswordKey::PASSWORD_KEY_LENGTH {
            return Err(CryptoError::InvalidPasswordKey);
        }

        let mut array = [0; PasswordKey::PASSWORD_KEY_LENGTH];
        array.copy_from_slice(key_material);

        Ok(Self {
            key_material: Box::new(array.into()),
        })
    }

    /// WARNING: this generates a copy of the key,
    /// and should only be used to derive another key from this key using a KDF.
    /// This should explicitly stay pub(super) to avoid abuse.
    #[allow(dead_code)]
    pub(super) fn into_bytes(self) -> [u8; PasswordKey::PASSWORD_KEY_LENGTH] {
        (*self.key_material).into()
    }
}

/// Implementation of the `TryFrom` trait for converting from `PasswordKey` to
/// `Vec<u8>`
impl TryFrom<PasswordKey> for Vec<u8> {
    type Error = CryptoError;

    fn try_from(key: PasswordKey) -> Result<Self, Self::Error> {
        // len || key || context
        let key_length = u8::try_from(key.key_material.len())
            .map_err(|_| CryptoError::CannotEncodeDataLength)?;

        let bytes = iter::once(key_length).chain(*key.key_material).collect();
        Ok(bytes)
    }
}

/// Implementation of the `TryFrom` trait for converting from `Vec<u8>` to
/// `PasswordKey`
impl TryFrom<Vec<u8>> for PasswordKey {
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

/// Test...
#[cfg(test)]
pub(super) mod test {

    use super::*;
    use std::{fs, fs::File, io::Write};

    const PASSWORD_KEY_FILENAME: &str = "temp_password_encryption_key.bin";

    #[test]
    fn password_key_from_bytes() -> Result<(), CryptoError> {
        let mut rng = rand::thread_rng();

        let password_encryption_key = PasswordKey::generate(&mut rng);
        // clone the key bytes
        let password_encryption_key_bytes = password_encryption_key.key_material.clone();

        // use the cloned key bytes to create a new key
        let password_encryption_key_from_bytes =
            PasswordKey::from_bytes(&password_encryption_key_bytes)?;

        println!(
            "\nPassword encryption key: 0x{key:02x?}\n\
            Key length: {key_len}\n\
            \
            \nConverted password encryption key:\n{converted_key}\n",
            key = password_encryption_key_bytes,
            key_len = password_encryption_key_bytes.len(),
            converted_key = password_encryption_key_from_bytes,
        );

        // compare the original key and the newly created key from the original key
        // bytes
        assert_eq!(password_encryption_key, password_encryption_key_from_bytes,);

        Ok(())
    }

    #[test]
    fn password_key_to_bytes() -> Result<(), CryptoError> {
        let mut rng = rand::thread_rng();

        let password_encryption_key = PasswordKey::generate(&mut rng);

        println!(
            "\nPassword encryption key:\n{key}",
            key = password_encryption_key
        );

        // clone here before we lose ownership
        let password_encryption_key_clone = password_encryption_key.clone();

        // convert the key to bytes
        let password_encryption_key_bytes = password_encryption_key.into_bytes();

        // create a new key from the converted bytes
        let new_password_encryption_key = PasswordKey::from_bytes(&password_encryption_key_bytes)?;

        println!(
            "\nConverted password encryption key:\n{key}",
            key = new_password_encryption_key
        );

        // compare the original key and the newly created key from the original key
        // bytes
        assert_eq!(password_encryption_key_clone, new_password_encryption_key);

        Ok(())
    }

    #[test]
    fn password_key_from_bytes_wrong_length_fails() -> Result<(), CryptoError> {
        let mut rng = rand::thread_rng();

        let password_encryption_key = PasswordKey::generate(&mut rng);
        let password_encryption_key_bytes = password_encryption_key.key_material.clone();

        println!(
            "\nPassword encryption key: 0x{key:02x?}\n\
            Key length: {key_len}",
            key = password_encryption_key_bytes,
            key_len = password_encryption_key_bytes.len(),
        );

        let password_new_encryption_key_from_bytes =
            PasswordKey::from_bytes(&password_encryption_key_bytes[..31]);

        println!(
            "\nConverted password encryption key:\n{:02x?}\n\n",
            password_new_encryption_key_from_bytes
        );

        assert_eq!(
            password_new_encryption_key_from_bytes
                .unwrap_err()
                .to_string(),
            CryptoError::InvalidPasswordKey.to_string()
        );

        Ok(())
    }

    fn password_key_from_file_helper() -> Result<(), CryptoError> {
        const PASSWORD_KEY_FILENAME: &str = "temp_password_encryption_key.bin";

        let mut rng = rand::thread_rng();

        let password_encryption_key = PasswordKey::generate(&mut rng);

        // create a temp file to store the password key
        let mut password_encryption_key_file = File::create(PASSWORD_KEY_FILENAME)
            .expect("Failed to create a temp password key file.");

        // clone it for later, before we lose ownership
        let password_encryption_key_original = password_encryption_key.clone();

        password_encryption_key_file
            .write_all(&password_encryption_key.into_bytes())
            .expect("Failed to write to a temp password key file.");

        // read the key from a file
        let password_encryption_key_from_file = PasswordKey::read_from_file(PASSWORD_KEY_FILENAME)?;

        println!(
            "\nPassword encryption key:\n{key}",
            key = password_encryption_key_original
        );
        println!(
            "\nPassword encryption key from a file:\n{key_from_file}",
            key_from_file = password_encryption_key_from_file
        );

        // make sure that password key readm from the file *is* the same as the original
        // password key
        if password_encryption_key_original != password_encryption_key_from_file {
            return Err(CryptoError::InvalidPasswordKey);
        }

        Ok(())
    }

    #[test]
    fn password_key_from_file() -> Result<(), CryptoError> {
        // call the test helper function
        let result = password_key_from_file_helper();

        // Always try to delete the file, even if password_key_from_file_helper()
        // encountered an error.
        match fs::remove_file(PASSWORD_KEY_FILENAME) {
            Ok(()) => (),
            Err(e) => println!("Failed to remove a temp password key file: {}", e),
        }

        // Now handle the result of password_key_from_file_helper()
        match result {
            Ok(()) => (),
            Err(e) => println!("Test failed: {}", e),
        }

        Ok(())
    }
}
