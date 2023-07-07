//////
/// 
/// This module defines [`Password`] type.
///

use crate::LockKeeperError;

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    convert::TryFrom,
};
use zeroize::ZeroizeOnDrop;

use crate::crypto::{
    generic::{self, AssociatedData, CryptoError},
    Encrypted, PasswordKey,
};

use super::Export;

//////
/// 
/// The [`Password`] type.
/// 

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Password(pub(super) generic::Password);

impl std::fmt::Debug for Password {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let password_debug = format!("{:#?}", self.0);
        write!(f, "{}", password_debug)
    }
}

impl TryFrom<Password> for Vec<u8> {
    type Error = CryptoError;

    fn try_from(password: Password) -> Result<Self, Self::Error> {
        password.0.to_owned().try_into()
    }
}

impl TryFrom<Vec<u8>> for Password {

    type Error = CryptoError;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Password(value.try_into()?))
    }
}

impl Encrypted<Password> {

    //////
    /// 
    /// Decrypt a password using the provided key and account name.
    ///
    /// # Arguments
    ///
    /// * `password_encryption_key` - The key used to encrypt the password.
    /// * `key_server_name` - The key server associated with the password.
    ///
    /// # Returns
    ///
    /// * A newly created `Self` instance containing the decrypted password.
    /// * Returns an error of type `LockKeeperError` if the encryption process fails.
    /// 
    fn decrypt_password(

        self, 
        password_encryption_key: &PasswordKey,
        key_server_name: Vec<u8>,        

    ) -> Result<Password, LockKeeperError> {

        let expected_associated_data = AssociatedData::new().with_bytes(key_server_name);        

        if self.associated_data != expected_associated_data{
            return Err(CryptoError::DecryptionFailed.into());
        }

        let decrypted_password = self.decrypt_inner(&password_encryption_key.0)?;
        
        Ok(decrypted_password)
    }
}

impl Password {

    //////
    /// 
    /// Encrypt a password using the provided key and account name.
    ///
    /// # Arguments
    ///
    /// * `rng` - A mutable reference to the random number generator.
    /// * `password_encryption_key` - The plaintext password to import.
    /// * `password_key` - The key used to encrypt the password.
    /// * `key_server_name` - The key server associated with the password.
    ///
    /// # Returns
    ///
    /// * A tuple containing the newly created `Self` instance and the encrypted representation.
    /// * Returns an error of type `LockKeeperError` if the encryption process fails.
    /// 
    pub fn encrypt(

        rng: &mut (impl CryptoRng + RngCore),
        password_plaintext: &[u8],
        password_encryption_key: &PasswordKey,
        key_server_name: Vec<u8>,        

    ) -> Result<(Self, Encrypted<Self>), LockKeeperError> {

        let context = AssociatedData::new().with_bytes(key_server_name);

        match generic::Password::from_parts(password_plaintext.to_vec(), context.clone()) {

            Some(password) => {
                let password_plaintext = Password(password);
                Ok((
                    password_plaintext.clone(),
                    Encrypted::encrypt(rng, &password_encryption_key.0, password_plaintext, &context)?,
                ))
            }

            None => Err(LockKeeperError::InvalidPassword)
        }
    }

    //////
    /// 
    /// Retrieve the context for the Password.
    ///
    fn context(&self) -> &AssociatedData {

        self.0.context()
    }
}

impl From<Password> for Export {

    fn from(password: Password) -> Self {
        Self {
            key_material: password.0.borrow_material().into(),
            context: password.context().clone().into(),
        }
    }
}

impl TryFrom<Export> for Password {

    type Error = LockKeeperError;

    fn try_from(export: Export) -> Result<Self, Self::Error> {
        
        let context = export.context.clone().try_into()?;
        
        match generic::Password::from_parts(export.key_material.clone(), context) {
            Some(password) => {
                Ok(Password(password))                
            }
            None => Err(LockKeeperError::InvalidPassword)
        }
    }
}

//////
/// 
/// Test...
/// 

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;

    //////
    /// 
    /// Converts a password between `Password` and `Vec<u8>` representations and verifies the conversion.
    ///
    /// # Errors
    ///
    /// Returns a `LockKeeperError` if there is an error during encryption or conversion.
    ///
    #[test]
    fn password_vec_u8_conversion() -> Result<(), LockKeeperError> {

        let mut rng = rand::thread_rng();

        // generate a random 32-byte password
        let password_plaintext: [u8; 32] = rng.gen();   

        // generate a password encryption key
        let password_key = PasswordKey::generate(&mut rng);
        
        const KEY_SERVER_NAME: &str = "test_key_server_1";        

        // encrypt the password
        let (password, _) = Password::encrypt(
            &mut rng,
            &password_plaintext,
            &password_key,
            KEY_SERVER_NAME.as_bytes().to_vec()
        )?;

        println!("\nOriginal plaintext password is...\n{:02x?}\n\n", password);        

        // convert Password to Vec<u8>
        let password_vec: Vec<u8> = password.clone().try_into()?;

        // convert Vec<u8> to Password
        let password_from_vec: Password = password_vec.try_into()?;
        println!("\nConverted plaintext password is...\n{:02x?}\n\n", password_from_vec);

        // compare the original and converted Passwords
        assert_eq!(password, password_from_vec);

        Ok(())
    }

    //////
    /// 
    /// Encrypts and decrypts a password, verifying the consistency of the encryption process.
    ///
    /// # Errors
    ///
    /// * Returns a `LockKeeperError` if there is an error during encryption, decryption, or verification.
    ///
    #[test]
    fn password_encrypt_decrypt() -> Result<(), LockKeeperError> {

        let mut rng = rand::thread_rng();

        const KEY_SERVER_NAME: &str = "test_key_server_1";                

        // generate a random 32-byte password
        let password_plaintext: [u8; 32] = rng.gen();        

        // generate a password encryption key        
        let password_key = PasswordKey::generate(&mut rng);

        // encrypt the password
        let (password_plaintext, password_encrypted) = Password::encrypt(
            &mut rng,
            &password_plaintext,
            &password_key,
            KEY_SERVER_NAME.as_bytes().to_vec(),
        )?;

        println!("\nKey server name is...\n{} (hex encoded: {})", KEY_SERVER_NAME, hex::encode(KEY_SERVER_NAME.to_string()));
        println!("\nPlaintext password is...\n{:02x?}\n\nencrypted password is...\n{:#x?}", password_plaintext, password_encrypted);

        // make sure the decrypted password instance matches the plaintext password instance
        let password_decrypted = password_encrypted.decrypt_password(&password_key, KEY_SERVER_NAME.as_bytes().to_vec())?;
        println!("\nPlaintext password is...\n{:x?}\n\ndecrypted password is...\n{:x?}", password_plaintext, password_decrypted);

        assert_eq!(password_plaintext, password_decrypted);

        Ok(())
    }
}
