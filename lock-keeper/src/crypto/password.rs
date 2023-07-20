//! This defines type [`Password`] and its related types.

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use tracing::instrument;
use zeroize::ZeroizeOnDrop;

use crate::crypto::{
    generic::{CryptoError, ParseBytes},
    PasswordKey,
};

use chacha20poly1305::{
    aead::{Aead, Payload},
    AeadCore, ChaCha20Poly1305, KeyInit,
};

/// The [`Password`] type.
/// A password contains password `material` and `context` data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Password {
    /// The actual bytes of password material.
    material: Vec<u8>,
    /// Additional context about the password.
    #[zeroize(skip)]
    context: PasswordContext,
}

/// An implementation of the `std::fmt::Display` trait for `Password`.
impl std::fmt::Display for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let material_hex = self
            .material
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join(" ");

        write!(
            f,
            "\n---Password begin---\n\n\
            \
            \tmaterial: 0x[{material}]\n\
            \tmaterial length: {material_len}\n\
            {context}\n\
            \
            \n---Password end---\n",
            material = material_hex,
            material_len = self.material.len(),
            context = self.context,
        )
    }
}

/// Implementation of the `TryFrom` trait for converting from `Password` to
/// `Vec<u8>`
impl TryFrom<Password> for Vec<u8> {
    type Error = CryptoError;

    fn try_from(password: Password) -> Result<Self, Self::Error> {
        // Output byte array format:
        // password len (2 bytes) || password material || context len (2 bytes) ||
        // context data

        let context: Vec<u8> = password.context.to_owned().into();

        let password_length = u16::try_from(password.material.len())
            .map_err(|_| CryptoError::CannotEncodeDataLength)?;

        let context_length =
            u16::try_from(context.len()).map_err(|_| CryptoError::CannotEncodeDataLength)?;

        let bytes = password_length
            .to_be_bytes()
            .into_iter()
            .chain(password.material.to_owned())
            .chain(context_length.to_be_bytes())
            .chain(context)
            .collect();

        Ok(bytes)
    }
}

/// Implementation of the `TryFrom` trait for converting from `Vec<u8>` to
/// `Password`
impl TryFrom<Vec<u8>> for Password {
    type Error = CryptoError;

    #[instrument(skip_all)]
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        // Input byte array format:
        // password len (2 bytes) || password material || context len (2 bytes) ||
        // context data

        // we'll be parsing the byte array, and creating an instance of Password type
        let mut parse = ParseBytes::new(bytes);

        let password_length = parse.take_bytes_as_u16()?;
        let password_material = parse.take_bytes(password_length as usize)?.to_vec();

        let context_length = parse.take_bytes_as_u16()?;
        let context: Vec<u8> = parse.take_rest()?.to_vec();

        // make sure that the length of the context matches the parsed length
        if context.len() != context_length as usize {
            return Err(CryptoError::ConversionError);
        }

        // create and return a new Password instance from the parsed password and
        // context
        Ok(Self {
            material: password_material,
            context: context.try_into()?,
        })
    }
}

impl Password {
    /// Encrypt a `Password` using the provided encryption key.
    ///
    /// # Arguments
    ///
    /// * `rng` - A mutable reference to the random number generator.
    /// * `password_encryption_key` - The key used to encrypt the password.
    ///
    /// # Returns
    ///
    /// * A new instance of the `EncryptedPassword`
    /// * Returns an error of type `CryptoError` if the encryption process
    ///   fails.
    pub fn encrypt(
        self,
        rng: &mut (impl CryptoRng + RngCore),
        password_encryption_key: &PasswordKey,
    ) -> Result<EncryptedPassword, CryptoError> {
        // setup cipher... create a new instance of ChaCha20Poly1305 with key
        let cipher = ChaCha20Poly1305::new(&password_encryption_key.key_material);

        // Convert PasswordContext to a Vec<u8>
        let context_bytes: Vec<u8> = self.context.clone().into();

        // Format plaintext and associated data
        let payload = Payload {
            msg: &self.material,
            aad: &context_bytes,
        };

        // Generate nonce and encrypt the payload
        let nonce = ChaCha20Poly1305::generate_nonce(rng);
        let encrypted_password = cipher
            .encrypt(&nonce, payload)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok(EncryptedPassword {
            ciphertext: encrypted_password,
            context: self.context.clone(),
            nonce,
        })
    }

    /// Retrieve the context for this password.
    #[allow(dead_code)]
    fn context(&self) -> &PasswordContext {
        &self.context
    }
}

/// The context (a.k.a. associated data) used in [`Password`]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct PasswordContext {
    key_server_name: Vec<u8>,
}

/// An implementation of the `std::fmt::Display` trait for `PasswordContext`.
impl std::fmt::Display for PasswordContext {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let key_server_name_hex = self
            .key_server_name
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join(" ");

        write!(
            f,
            "\n\nPassword context:\n\
            \tkey server name: 0x[{key_server_name}[\n\
            \tkey server name length: {key_server_name_len}\n",
            key_server_name = key_server_name_hex,
            key_server_name_len = self.key_server_name.len(),
        )
    }
}
impl PasswordContext {
    /// `PasswordContext` generic constructor.
    /// A type parameter is bounded by the AsRef<[u8]> trait.
    /// This trait is implemented by types that can be referenced as a byte
    /// slice, e.g. `&str`, `Vec<u8>`
    ///
    /// Example usage:
    ///
    ///
    /// From string slices...
    /// ```ignore
    ///     let context = PasswordContext::new("my_key_server");
    /// ```
    ///
    /// From `Vec<u8>`...
    /// ```ignore
    ///     let key_server_name = "my_key_server".as_bytes().to_vec();
    ///     let context = PasswordContext::new(key_server_name);
    /// ```
    #[allow(dead_code)]
    fn new<T: AsRef<[u8]>>(key_server_name: T) -> Self {
        PasswordContext {
            // use as_ref method to get a byte slice from the parameter,
            // then convert the byte slice to a Vec<u8> with the to_vec method
            key_server_name: key_server_name.as_ref().to_vec(),
        }
    }
}

/// Conversion from `Vec<u8>` to PasswordContext
impl TryFrom<Vec<u8>> for PasswordContext {
    type Error = CryptoError;

    fn try_from(data_bytes: Vec<u8>) -> Result<Self, Self::Error> {
        // Create a new PasswordContext using the byte data
        Ok(PasswordContext {
            key_server_name: data_bytes,
        })
    }
}

/// Conversion from PasswordContext to `Vec<u8>`
impl From<PasswordContext> for Vec<u8> {
    fn from(password_context: PasswordContext) -> Self {
        password_context.key_server_name
    }
}

/// The [`EncryptedPassword`] type.
/// An encrypted password contains `ciphertext`, `context` and `nonce`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EncryptedPassword {
    ciphertext: Vec<u8>,
    context: PasswordContext,
    nonce: chacha20poly1305::Nonce,
}

/// An implementation of the `std::fmt::Display` trait for `EncryptedPassword`
impl std::fmt::Display for EncryptedPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let ciphertext_hex = self
            .ciphertext
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join(" ");

        write!(
            f,
            "\n---Encrypted Password begin---\n\n\
            \
            \tciphertext: 0x[{ciphertext}]\n\
            \tciphertext length: {ciphertext_len}\n\
            \tcontext: {context}\n\
            \tnonce: {nonce:02x?}\n\
            \tnonce length: {nonce_len}\n
            \
            \n---Encrypted Password end---\n",
            ciphertext = ciphertext_hex,
            ciphertext_len = self.ciphertext.len(),
            context = self.context,
            nonce = self.nonce,
            nonce_len = self.nonce.len(),
        )
    }
}

impl EncryptedPassword {
    /// Decrypt a `Password` using the provided key.
    ///
    /// # Arguments
    ///
    /// * `password_key` - The key used to decrypt the password.
    ///
    /// # Returns
    ///
    /// * A newly created `Password` instance containing the decrypted password.
    /// * Returns an error of type `CryptoError` if the decryption process
    ///   fails.
    pub fn decrypt(self, password_key: &PasswordKey) -> Result<Password, CryptoError> {
        // setup cipher... create a new instance of ChaCha20Poly1305 with key
        let cipher = ChaCha20Poly1305::new(&password_key.key_material);

        // Convert PasswordContext to a Vec<u8>
        let context_bytes: Vec<u8> = self.context.clone().into();

        // Format ciphertext and associated data
        let payload = Payload {
            msg: &self.ciphertext,
            aad: &context_bytes,
        };

        // Decrypt
        let plaintext_password = cipher
            .decrypt(&self.nonce, payload)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        // Return the decrypted password
        Ok(Password {
            material: plaintext_password,
            context: self.context,
        })
    }
}

/// Test...
#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;

    const KEY_SERVER_NAME: &str = "test_key_server_1";

    /// Converts a password between `Password` and `Vec<u8>` representations and
    /// verifies the conversion.
    ///
    /// # Errors
    ///
    /// Returns a `CryptoError` if there is an error during encryption or
    /// conversion.
    #[test]
    fn password_vec_u8_conversion() -> Result<(), CryptoError> {
        let mut rng = rand::thread_rng();

        // generate a random 32-byte password
        let password_plaintext: [u8; 32] = rng.gen();

        // create a Password instance
        let password = Password {
            material: password_plaintext.to_vec(),
            context: PasswordContext {
                key_server_name: KEY_SERVER_NAME.as_bytes().to_vec(),
            },
        };

        // convert Password to Vec<u8>
        let password_vec: Vec<u8> = password.clone().try_into()?;

        // convert Vec<u8> back to Password
        let password_from_vec: Password = password_vec.try_into()?;

        println!(
            "\nOriginal raw plaintext password: 0x{password:02x?}",
            password = password_plaintext
        );
        println!(
            "Original raw plaintext password length: {password_len}",
            password_len = password_plaintext.len()
        );

        println!("\nOriginal password: {password}", password = password);
        println!(
            "\nConverted password: {password}",
            password = password_from_vec
        );

        // compare the original and converted Password
        assert_eq!(password, password_from_vec);

        Ok(())
    }

    /// Encrypts and decrypts a password, verifying the consistency of the
    /// encryption process.
    ///
    /// # Errors
    ///
    /// * Returns a `CryptoError` if there is an error during encryption,
    ///   decryption, or verification.
    #[test]
    fn password_encrypt_decrypt() -> Result<(), CryptoError> {
        let mut rng = rand::thread_rng();

        // generate a random 32-byte password
        let password_material: [u8; 32] = rng.gen();

        // generate a password encryption key
        let password_encryption_key = PasswordKey::generate(&mut rng);

        let plaintext_password = Password {
            material: password_material.to_vec(),
            context: PasswordContext {
                key_server_name: KEY_SERVER_NAME.as_bytes().to_vec(),
            },
        };

        // clone, so we can use it later
        let original_password = plaintext_password.clone();

        // encrypt the password
        let encrypted_password = plaintext_password.encrypt(&mut rng, &password_encryption_key)?;

        println!(
            "\nKey server name:\n{} (hex encoded: {})",
            KEY_SERVER_NAME,
            hex::encode(KEY_SERVER_NAME)
        );
        println!(
            "\nPlaintext password:{password:02x?}\
            \nPlaintext password length: {password_len}\
            \n\nEncrypted password:\n{encrypted_password}",
            password = password_material,
            password_len = password_material.len(),
            encrypted_password = encrypted_password,
        );

        // decrypt the password
        let decrypted_password = encrypted_password.decrypt(&password_encryption_key)?;

        println!(
            "\nPlaintext password: {password:02x?}\
            \nPlaintext password length: {password_len}\
            \n\nDecrypted password:\n{decrypted_password}",
            password = password_material,
            password_len = password_material.len(),
            decrypted_password = decrypted_password,
        );

        // make sure the decrypted password matches the original password
        assert_eq!(original_password, decrypted_password);

        Ok(())
    }

    /// Encrypts and decrypts a password, verifying the consistency of the
    /// context data.
    ///
    /// # Errors
    ///
    /// * Returns a `CryptoError` if there is an error during encryption,
    ///   decryption, or verification.
    #[test]
    fn password_context_data_fails() -> Result<(), CryptoError> {
        let mut rng = rand::thread_rng();

        // generate a random 32-byte password
        let password_material: [u8; 32] = rng.gen();

        // generate a password encryption key
        let password_encryption_key = PasswordKey::generate(&mut rng);

        // create a new instance of Password
        let plaintext_password = Password {
            material: password_material.to_vec(),
            context: PasswordContext {
                key_server_name: KEY_SERVER_NAME.as_bytes().to_vec(),
            },
        };

        // encrypt the password
        let mut encrypted_password =
            plaintext_password.encrypt(&mut rng, &password_encryption_key)?;

        println!(
            "\nEncrypted password:{encrypted_password}",
            encrypted_password = encrypted_password
        );

        // modify the context aka associated data
        encrypted_password
            .context
            .key_server_name
            .extend_from_slice("__baaaaaad__".as_bytes());

        println!(
            "\nCorrupt encrypted password :{encrypted_password}",
            encrypted_password = encrypted_password
        );

        // try to decrypt the password with corrupt context
        let decrypted_password = encrypted_password.decrypt(&password_encryption_key);

        // make sure we generated the expected error
        assert_eq!(
            decrypted_password.unwrap_err().to_string(),
            CryptoError::DecryptionFailed.to_string()
        );

        Ok(())
    }
}
