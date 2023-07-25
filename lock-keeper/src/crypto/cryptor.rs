//! This defines data types related to the Cryptor.

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use tracing::instrument;
use zeroize::ZeroizeOnDrop;

use crate::crypto::{
    generic::{CryptoError, ParseBytes},
    CryptorKey,
};

use chacha20poly1305::{
    aead::{Aead, Payload},
    AeadCore, ChaCha20Poly1305, KeyInit,
};

/// The [`Encryptor`] type.
/// It contains `data` and `context` to be encrypted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Encryptor {
    /// The actual bytes of data to be encrypted.
    data: Vec<u8>,
    /// Additional context about the data.
    #[zeroize(skip)]
    context: CryptorContext,
}

/// An implementation of the `std::fmt::Display` trait for `Encryptor`.
impl std::fmt::Display for Encryptor {

    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {

        if cfg!(debug_assertions) {
            // this is a Debug build, so we can display sensitive info

            let data_hex = self
                .data
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<String>>()
                .join(" ");

            write!(
                f,
                "\n---Encryptor begin---\n\n\
                \
                \tdata: 0x[{data}]\n\
                \tdata length: {data_len}\n\
                {context}\n\
                \
                \n---Encryptor end---\n",
                data = data_hex,
                data_len = self.data.len(),
                context = self.context,
            )

        } else {

            write!(
                f,
                "\n---Encryptor begin---\n\n\
                \t{}\n\
                \n---Encryptor end---\n",

                &Encryptor::REDACTED_INFO
            )
        }
    }
}

/// An implementation of the `std::fmt::Debug` trait for `Encryptor`
impl std::fmt::Debug for Encryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {

        if cfg!(debug_assertions) {
            // this is a Debug build, so we can display sensitive info

            f.debug_struct("Encryptor")
            .field("data", &self.data)
            .finish()

        } else {

            write!(f, "Encryptor {}", &Encryptor::REDACTED_INFO)
        }
    }
}


/// Implementation of the `TryFrom` trait for converting from `Encryptor` to
/// `Vec<u8>`
impl TryFrom<Encryptor> for Vec<u8> {

    type Error = CryptoError;

    fn try_from(encryptor: Encryptor) -> Result<Self, Self::Error> {

        // Output byte array format:
        // data len (2 bytes) || data || context len (2 bytes) ||
        // context data

        let context: Vec<u8> = encryptor.context.to_owned().into();

        let data_length = u16::try_from(encryptor.data.len())
            .map_err(|_| CryptoError::CannotEncodeDataLength)?;

        let context_length =
            u16::try_from(context.len()).map_err(|_| CryptoError::CannotEncodeDataLength)?;

        let bytes = data_length
            .to_be_bytes()
            .into_iter()
            .chain(encryptor.data.to_owned())
            .chain(context_length.to_be_bytes())
            .chain(context)
            .collect();

        Ok(bytes)
    }
}

/// Implementation of the `TryFrom` trait for converting from `Vec<u8>` to
/// `Encryptor`
impl TryFrom<Vec<u8>> for Encryptor {

    type Error = CryptoError;

    #[instrument(skip_all)]
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {

        // Input byte array format:
        // data len (2 bytes) || data || context len (2 bytes) ||
        // context data

        // we'll be parsing the byte array, and creating an instance of Encryptor type
        let mut parse = ParseBytes::new(bytes);

        let data_length = parse.take_bytes_as_u16()?;
        let data = parse.take_bytes(data_length as usize)?.to_vec();

        let context_length = parse.take_bytes_as_u16()?;
        let context: Vec<u8> = parse.take_rest()?.to_vec();

        // make sure that the length of the context matches the parsed length
        if context.len() != context_length as usize {
            return Err(CryptoError::ConversionError);
        }

        // create and return a new Encryptor instance from the parsed data and
        // context
        Ok(Self {
            data: data,
            context: context.try_into()?,
        })
    }
}

impl Encryptor {

    // sensitive info handling
    const REDACTED_INFO: &str = "REDACTED";

    /// Encrypt data using the provided encryption key.
    ///
    /// # Arguments
    ///
    /// * `rng` - A mutable reference to the random number generator.
    /// * `encryption_key` - The key used to encrypt data.
    ///
    /// # Returns
    ///
    /// * A new instance of the `Encryptor`
    /// * Returns an error of type `CryptoError` if the encryption process
    ///   fails.
    pub fn encrypt(
        self,
        rng: &mut (impl CryptoRng + RngCore),
        encryption_key: &CryptorKey,
    ) -> Result<Decryptor, CryptoError> {

        // setup cipher... create a new instance of ChaCha20Poly1305 with key
        let cipher = ChaCha20Poly1305::new(&encryption_key.key_material);

        // Convert context to a Vec<u8>
        let context_bytes: Vec<u8> = self.context.clone().into();

        // Format plaintext and associated data
        let payload = Payload {
            msg: &self.data,
            aad: &context_bytes,
        };

        // Generate nonce and encrypt the payload
        let nonce = ChaCha20Poly1305::generate_nonce(rng);
        let encrypted_data = cipher
            .encrypt(&nonce, payload)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok(Decryptor {
            ciphertext: encrypted_data,
            context: self.context.clone(),
            nonce,
        })
    }

    /// Retrieve the context for this Encryptor
    #[allow(dead_code)]
    fn context(&self) -> &CryptorContext {
        &self.context
    }
}

/// The context (a.k.a. associated data).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct CryptorContext {
    key_server_name: Vec<u8>,
}

/// An implementation of the `std::fmt::Display` trait for `CryptorContext`.
impl std::fmt::Display for CryptorContext {

    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {

        let key_server_name_hex = self
            .key_server_name
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join(" ");

        write!(
            f,
            "\n\nContext:\n\
            \tkey server name: 0x[{key_server_name}]\n\
            \tkey server name length: {key_server_name_len}\n",
            key_server_name = key_server_name_hex,
            key_server_name_len = self.key_server_name.len(),
        )
    }
}
impl CryptorContext {
    /// `CryptorContext` generic constructor.
    /// A type parameter is bounded by the AsRef<[u8]> trait.
    /// This trait is implemented by types that can be referenced as a byte
    /// slice, e.g. `&str`, `Vec<u8>`
    ///
    /// Example usage:
    ///
    ///
    /// From string slices...
    /// ```ignore
    ///     let context = CryptorContext::new("my_key_server");
    /// ```
    ///
    /// From `Vec<u8>`...
    /// ```ignore
    ///     let key_server_name = "my_key_server".as_bytes().to_vec();
    ///     let context = CryptorContext::new(key_server_name);
    /// ```
    #[allow(dead_code)]
    fn new<T: AsRef<[u8]>>(key_server_name: T) -> Self {
        CryptorContext {
            // use as_ref method to get a byte slice from the parameter,
            // then convert the byte slice to a Vec<u8> with the to_vec method
            key_server_name: key_server_name.as_ref().to_vec(),
        }
    }
}

/// Conversion from `Vec<u8>` to CryptorContext
impl TryFrom<Vec<u8>> for CryptorContext {
    type Error = CryptoError;

    fn try_from(data_bytes: Vec<u8>) -> Result<Self, Self::Error> {
        // Create a new CryptorContext using the byte data
        Ok(CryptorContext {
            key_server_name: data_bytes,
        })
    }
}

/// Conversion from CryptorContext to `Vec<u8>`
impl From<CryptorContext> for Vec<u8> {
    fn from(context: CryptorContext) -> Self {
        context.key_server_name
    }
}

/// The [`Decryptor`] type.
/// It contains `ciphertext`, `context` and `nonce`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Decryptor {
    ciphertext: Vec<u8>,
    context: CryptorContext,
    nonce: chacha20poly1305::Nonce,
}

/// An implementation of the `std::fmt::Display` trait for `Decryptor`
impl std::fmt::Display for Decryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let ciphertext_hex = self
            .ciphertext
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join(" ");

        write!(
            f,
            "\n---Encrypted data begin---\n\n\
            \
            \tciphertext: 0x[{ciphertext}]\n\
            \tciphertext length: {ciphertext_len}\n\
            \tcontext: {context}\n\
            \tnonce: {nonce:02x?}\n\
            \tnonce length: {nonce_len}\n
            \
            \n---Encrypted data end---\n",
            ciphertext = ciphertext_hex,
            ciphertext_len = self.ciphertext.len(),
            context = self.context,
            nonce = self.nonce,
            nonce_len = self.nonce.len(),
        )
    }
}

impl Decryptor {
    /// Decrypt data using the provided key.
    ///
    /// # Arguments
    ///
    /// * `decryption_key` - The key used to decrypt the data.
    ///
    /// # Returns
    ///
    /// * A newly created `Encryptor` instance containing the decrypted data.
    /// * Returns an error of type `CryptoError` if the decryption process
    ///   fails.
    pub fn decrypt(self, decryption_key: &CryptorKey) -> Result<Encryptor, CryptoError> {

        // setup cipher... create a new instance of ChaCha20Poly1305 with key
        let cipher = ChaCha20Poly1305::new(&decryption_key.key_material);

        // Convert context to a Vec<u8>
        let context_bytes: Vec<u8> = self.context.clone().into();

        // Format ciphertext and associated data
        let payload = Payload {
            msg: &self.ciphertext,
            aad: &context_bytes,
        };

        // Decrypt
        let plaintext_data = cipher
            .decrypt(&self.nonce, payload)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        // Return the decrypted data
        Ok(Encryptor {
            data: plaintext_data,
            context: self.context,
        })
    }
}

/// Tests...
#[cfg(test)]
mod test {
    use super::*;

    const KEY_SERVER_NAME: &str = "test_key_server_1";
    const DATA_BYTES_LENGTH: usize = 257;

    /// Test the correctness of the sensitive information handling.
    /// 
    ///     In the Release build: sensitive info is expected to be REDACTED
    ///     In the Debug build: sensitive info can be displayed
    #[test]
    fn encryptor_sensitive_info_handling_on_debug_and_display() {
        let mut rng = rand::thread_rng();
        
        // generate some random data
        let data = generate_random_data(DATA_BYTES_LENGTH);

        // generate an encryption key
        let _data_encryption_key = CryptorKey::new(&mut rng);

        let plaintext_data = Encryptor {
            data: data.to_vec(),
            context: CryptorContext {
                key_server_name: KEY_SERVER_NAME.as_bytes().to_vec(),
            },
        };

        // create formatted strings for Debug and Display traits
        let debug_format_cryptor_key = format!("{:?}", plaintext_data);
        let display_format_cryptor_key = format!("{}", plaintext_data);

        println!("\nCryptor key debug:{:?}", debug_format_cryptor_key);
        println!("\nCryptor key display:{}", display_format_cryptor_key);

        // Calculate the expected state of redacted info based on the build type.
        //  False for the Debug build, True for the Release build.
        let should_be_redacted = !cfg!(debug_assertions);

        // check if output contains the redacted tag.
        let is_debug_redacted = debug_format_cryptor_key.contains(&Encryptor::REDACTED_INFO);
        let is_display_redacted = display_format_cryptor_key.contains(&Encryptor::REDACTED_INFO);

        // check if the redacted tag is applied correctly for Debug and Display traits.
        assert_eq!(is_debug_redacted, should_be_redacted,
                    "Unexpected debug output: {}",
                    if should_be_redacted { "Found UN-REDACTED info!!!" } else { "Found REDACTED info." });

        assert_eq!(is_display_redacted, should_be_redacted,
                    "Unexpected display output: {}",
                    if should_be_redacted { "Found UN-REDACTED info!!!" } else { "Found REDACTED info." });
    }

    /// Converts an encryptor between `Encryptor` and `Vec<u8>` representations and
    /// verifies the conversion.
    ///
    /// # Errors
    ///
    /// Returns a `CryptoError` if there is an error during encryption or
    /// conversion.
    #[test]
    fn encryptor_vec_u8_conversion() -> Result<(), CryptoError> {
        //let mut rng = rand::thread_rng();

        // generate some random data
        let data_plaintext = generate_random_data(DATA_BYTES_LENGTH);

        // create an Encryptor instance
        let encryptor = Encryptor {
            data: data_plaintext.to_vec(),
            context: CryptorContext {
                key_server_name: KEY_SERVER_NAME.as_bytes().to_vec(),
            },
        };

        // convert Encryptor to Vec<u8> by cloning
        let encryptor_vec: Vec<u8> = encryptor.clone().try_into()?;

        // convert Vec<u8> back to Encryptor
        let encryptor_from_vec: Encryptor = encryptor_vec.try_into()?;

        println!(
            "\nOriginal raw plaintext data: 0x{data:02x?}",
            data = data_plaintext
        );
        println!(
            "Original raw plaintext data length: {data_len}",
            data_len = data_plaintext.len()
        );

        println!("\nOriginal encryptor: {encryptor}", encryptor = encryptor);
        println!(
            "\nConverted encryptor: {encryptor:?}",
            encryptor = encryptor_from_vec
        );

        // compare the original and converted encryptor
        assert_eq!(encryptor, encryptor_from_vec);

        Ok(())
    }

    /// Encrypts and decrypts data, verifying the consistency of the
    /// encryption process.
    ///
    /// # Errors
    ///
    /// * Returns a `CryptoError` if there is an error during encryption,
    ///   decryption, or verification.
    #[test]
    fn data_encrypt_decrypt() -> Result<(), CryptoError> {

        let mut rng = rand::thread_rng();

        // generate some random data
        let data = generate_random_data(DATA_BYTES_LENGTH);

        // generate an encryption key
        let data_encryption_key = CryptorKey::new(&mut rng);

        let plaintext_data = Encryptor {
            data: data.to_vec(),
            context: CryptorContext {
                key_server_name: KEY_SERVER_NAME.as_bytes().to_vec(),
            },
        };

        // clone, so we can use it later
        let original_data = plaintext_data.clone();

        // encrypt the data
        let encrypted_data = plaintext_data.encrypt(&mut rng, &data_encryption_key)?;

        println!(
            "\nKey server name:\n{} (hex encoded: {})",
            KEY_SERVER_NAME,
            hex::encode(KEY_SERVER_NAME)
        );
        println!(
            "\nPlaintext data:{data:02x?}\
            \nPlaintext data length: {data_len}\
            \n\nEncrypted data:\n{encrypted_data}",
            data = data,
            data_len = data.len(),
            encrypted_data = encrypted_data,
        );

        // decrypt the encrypted data
        let decrypted_data = encrypted_data.decrypt(&data_encryption_key)?;

        println!(
            "\nPlaintext data: {data:02x?}\
            \nPlaintext data length: {data_len}\
            \n\nDecrypted data:\n{decrypted_data}",
            data = data,
            data_len = data.len(),
            decrypted_data = decrypted_data,
        );

        // make sure the decrypted data matches the original data
        assert_eq!(original_data, decrypted_data);

        Ok(())
    }

    /// Encrypts and decrypts data, verifying the consistency of the
    /// context data.
    ///
    /// # Errors
    ///
    /// * Returns a `CryptoError` if there is an error during encryption,
    ///   decryption, or verification.
    #[test]
    fn data_context_fails() -> Result<(), CryptoError> {
        let mut rng = rand::thread_rng();

        // generate some random data
        let data = generate_random_data(DATA_BYTES_LENGTH);

        // create a new data encryption key
        let data_encryption_key = CryptorKey::new(&mut rng);

        // create a new instance of Encryptor
        let plaintext_data = Encryptor {
            data: data.to_vec(),
            context: CryptorContext {
                key_server_name: KEY_SERVER_NAME.as_bytes().to_vec(),
            },
        };

        // encrypt the data
        let mut encrypted_data =
            plaintext_data.encrypt(&mut rng, &data_encryption_key)?;

        println!(
            "\nEncrypted data:{encrypted_data}",
            encrypted_data = encrypted_data
        );

        // modify the context aka associated data
        encrypted_data
            .context
            .key_server_name
            .extend_from_slice("__baaaaaad__".as_bytes());

        println!(
            "\nCorrupt encrypted data :{encrypted_data}",
            encrypted_data = encrypted_data
        );

        // try to decrypt the data with corrupt context
        let decrypted_data = encrypted_data.decrypt(&data_encryption_key);

        // make sure we generated the expected error
        assert_eq!(
            decrypted_data.unwrap_err().to_string(),
            CryptoError::DecryptionFailed.to_string()
        );

        Ok(())
    }

    /// Generate some random data to be used by the unit test functions.
    ///
    /// # Arguments
    ///
    /// * `num_bytes` - The number of random bytes to be generated.
    ///
    /// # Returns
    ///
    /// * A vector of bytes holding the random data requested by the caller.
    fn generate_random_data(num_bytes: usize) -> Vec<u8> {

        let mut rng = rand::rngs::OsRng;
        let mut random_data = vec![0; num_bytes];
        rng.fill_bytes(&mut random_data);

        random_data
    }

}

