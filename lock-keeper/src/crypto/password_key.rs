//////
/// 
/// This module defines a [`PasswordKey`], which can be used to securely encrypt passwords.
///

use super::{
    generic::{AssociatedData, EncryptionKey},
};
use crate::{
    LockKeeperError,
};
use rand::{CryptoRng, RngCore};
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

//////
/// 
/// The [`PasswordKey`] is a default-length symmetric encryption key
/// for an AEAD scheme. It can be used to securely encrypt passwords.
/// 
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct PasswordKey(pub(super) EncryptionKey);

impl PasswordKey {

    //////
    /// 
    /// Generate a new 32-byte [`PasswordKey`].
    /// 
    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Self {

        Self(EncryptionKey::new(rng))
    }

    //////
    /// 
    /// Returns the [`PasswordKey`] stored in a file.
    /// 
    /// 
    pub fn read_from_file(path: impl AsRef<Path>) -> Result<Self, LockKeeperError> {

        let bytes = std::fs::read(&path)
            .map_err(|e| LockKeeperError::FileIo(e, path.as_ref().to_path_buf()))?;
        
        Self::from_bytes(&bytes)
    }

    //////
    /// 
    /// Returns the [`PasswordKey`] key found in the byte array.
    /// 
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LockKeeperError> {

        let key = EncryptionKey::from_bytes(

            bytes
                .try_into()
                .map_err(|_| LockKeeperError::InvalidPasswordKey)?,

            AssociatedData::new().with_str(EncryptionKey::domain_separator()),
        );

        Ok(Self(key))
    }
}

//////
/// 
/// Test...
/// 

#[cfg(test)]
pub(super) mod test {

    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::fs;

    #[test]
    fn password_key_from_bytes() -> Result<(), LockKeeperError> {

        let mut rng = rand::thread_rng();

        let password_encryption_key = PasswordKey::generate(&mut rng);
        let password_encryption_key_bytes = password_encryption_key.0.clone().into_bytes();
        
        println!("\nPassword encryption key is...\n{:02x?}\n\n", password_encryption_key_bytes);                
        
        let password_encryption_key_from_bytes = PasswordKey::from_bytes(&password_encryption_key_bytes[..])?;

        println!("\nConverted password encryption key is...\n{:02x?}\n\n", password_encryption_key_bytes);                

        assert_eq!(password_encryption_key.0, password_encryption_key_from_bytes.0);
        
        Ok(())
    }

    #[test]
    fn password_key_from_bytes_fails_wrong_length() -> Result<(), LockKeeperError> {

        let mut rng = rand::thread_rng();

        let password_encryption_key = PasswordKey::generate(&mut rng);
        let password_encryption_key_bytes = password_encryption_key.0.clone().into_bytes();

        println!("\nPassword encryption key is...\n{:02x?}\n\n", password_encryption_key_bytes);                

        let password_new_encryption_key_from_bytes = PasswordKey::from_bytes(&password_encryption_key_bytes[..31]);

        println!("\nConverted password encryption key is...\n{:02x?}\n\n", password_new_encryption_key_from_bytes);                

        assert_eq!(
            password_new_encryption_key_from_bytes.unwrap_err().to_string(),
            LockKeeperError::InvalidPasswordKey.to_string()
        );

        Ok(())
    }

    #[test]
    fn password_key_from_file() -> Result<(), LockKeeperError> {

        const PASSWORD_KEY_FILENAME: &str = "temp_password_encryption_key.bin"; 

        let mut rng = rand::thread_rng();

        let password_encryption_key = PasswordKey::generate(&mut rng);

        // create a temp file to store the password key
        let mut password_encryption_key_file = File::create(PASSWORD_KEY_FILENAME).expect("Failed to create a temp password key file.");

        let password_encryption_key_bytes = password_encryption_key.0.clone().into_bytes();
        password_encryption_key_file.write_all(&password_encryption_key_bytes).expect("Failed to write to a temp password key file.");

        println!("\nPassword encryption key is...\n{:02x?}\n\n", password_encryption_key_bytes);                

        let password_encryption_key_from_file = PasswordKey::read_from_file(PASSWORD_KEY_FILENAME).unwrap();
        let password_encryption_key_from_file_bytes = password_encryption_key_from_file.0.clone().into_bytes();

        println!("\nPassword encryption key from a file is...\n{:02x?}\n\n", password_encryption_key_from_file_bytes);                

        // clean up by deleting the temp password key file
        fs::remove_file(PASSWORD_KEY_FILENAME).expect("Failed to remove a temp password key file.");

        // make sure that password key in the file is the same as the original password key
        assert_eq!(password_encryption_key_from_file_bytes, password_encryption_key_bytes);
        
        Ok(())
    }

}

