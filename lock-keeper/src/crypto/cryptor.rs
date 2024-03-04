//! This defines data types related to [`Encryptor`] and [`Decryptor`].

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use tracing::{error, instrument};

use zeroize::ZeroizeOnDrop;

use crate::crypto::{
    generic::{CryptoError, ParseBytes},
    CryptorKey,
};

use chacha20poly1305::{
    aead::{Aead, Payload},
    AeadCore, ChaCha20Poly1305, KeyInit,
};

use crate::infrastructure::sensitive_info::SensitiveInfoConfig;

/// The [`Encryptor`] type.
/// It contains `data` to be encrypted, plus `context` and `config` fields.
#[derive(Clone, Eq, ZeroizeOnDrop)]
pub struct Encryptor {
    /// The actual bytes of data to be encrypted.
    data: Vec<u8>,
    /// Additional context about the data.
    #[zeroize(skip)]
    context: CryptorContext,
    /// Configuration
    config: SensitiveInfoConfig,
}

/// An implementation of the `std::fmt::Display` trait for [`Encryptor`]
impl std::fmt::Display for Encryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if cfg!(debug_assertions) && !self.config.is_redacted() {
            // this is a Debug build *AND* redacted flag is FALSE

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
            // this is a Release build *OR* redacted flag is TRUE
            write!(
                f,
                "\n---Encryptor begin---\n\n\
                \t{redacted}\n\
                \n---Encryptor end---\n",
                redacted = self.config.clone().redacted_label(),
            )
        }
    }
}

/// An implementation of the `std::fmt::Debug` trait for [`Encryptor`]
impl std::fmt::Debug for Encryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if cfg!(debug_assertions) && !self.config.is_redacted() {
            // this is a Debug build *AND* redacted flag is FALSE

            f.debug_struct("Encryptor")
                .field("data", &self.data)
                .field("context", &self.context)
                .finish()
        } else {
            // this is a Release build *OR* redacted flag is TRUE
            write!(f, "Encryptor {}", self.config.clone().redacted_label())
        }
    }
}

/// Implementation of the `TryFrom` trait for converting to `Vec<u8>`
impl TryFrom<Encryptor> for Vec<u8> {
    type Error = CryptoError;

    fn try_from(encryptor: Encryptor) -> Result<Self, Self::Error> {
        // Output byte array format:
        // data len (2 bytes) || data || context len (2 bytes) ||
        // context data || config len (2 bytes) || config data

        let context: Vec<u8> = encryptor.context.to_owned().into();
        let config: Vec<u8> = encryptor.config.to_owned().try_into()?;

        let data_length =
            u16::try_from(encryptor.data.len()).map_err(|_| CryptoError::CannotEncodeDataLength)?;

        let context_length =
            u16::try_from(context.len()).map_err(|_| CryptoError::CannotEncodeDataLength)?;

        let config_length =
            u16::try_from(config.len()).map_err(|_| CryptoError::CannotEncodeDataLength)?;

        let bytes = data_length
            .to_be_bytes()
            .into_iter()
            .chain(encryptor.data.to_owned())
            .chain(context_length.to_be_bytes())
            .chain(context)
            .chain(config_length.to_be_bytes())
            .chain(config)
            .collect();

        Ok(bytes)
    }
}

/// Implementation of the `TryFrom` trait for converting from `Vec<u8>` to
/// [`Encryptor`]
impl TryFrom<Vec<u8>> for Encryptor {
    type Error = CryptoError;

    #[instrument(skip_all, err(Debug))]
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        // Input byte array format:
        // data len (2 bytes) || data || context len (2 bytes) ||
        // context data || config len (2 bytes) || config data

        // we'll be parsing the byte array, and creating an instance of Encryptor type
        let mut parse = ParseBytes::new(bytes);

        let data_length = parse.take_bytes_as_u16()?;
        // data_length is being converted from u16 to usize.
        // This conversion is always valid, guaranteed to never truncate data,
        // because a usize is always at least as large as a u16.
        let data = parse.take_bytes(data_length as usize)?.to_vec();

        let context_length = parse.take_bytes_as_u16()?;
        let context: Vec<u8> = parse.take_bytes(context_length as usize)?.to_vec();

        let config_length = parse.take_bytes_as_u16()?;
        let config: Vec<u8> = parse.take_rest()?.to_vec();

        // make sure that the length of the context matches the parsed length
        if context.len() != context_length as usize {
            return Err(CryptoError::ConversionError);
        }

        // make sure that the length of the config matches the parsed length
        if config.len() != config_length as usize {
            return Err(CryptoError::ConversionError);
        }

        Ok(Self {
            data,
            context: context.into(),
            config: config.try_into()?,
        })
    }
}

/// Implement the `PartialEq` trait for the [`Encryptor`] type.
impl PartialEq for Encryptor {
    /// Determines if two [`Encryptor`] instances are equal.
    ///
    /// This function compares the `data` and `context` fields of two
    /// [`Encryptor`] instances. It does not compare the `config` fields
    /// because the `config` field does not affect the functional equivalence of
    /// two [`Encryptor`] instances.
    ///
    /// # Arguments
    ///
    /// * `other` - The other [`Encryptor`] instance to compare with.
    ///
    /// # Returns
    ///
    /// Returns `true` if the `data` and `context` fields are equal between the
    /// two [`Encryptor`] instances, Otherwise returns `false`.
    fn eq(&self, other: &Self) -> bool {
        // Don't compare the config fields
        self.data == other.data && self.context == other.context
    }
}

impl Encryptor {
    /// Constructs a new instance of [`Encryptor`] type.
    ///
    /// # Arguments
    ///
    /// * `data` - A vector of bytes representing the data to be managed by the
    ///   instance.
    ///
    /// * `context` - An instance of [`CryptorContext`] that provides necessary
    ///   cryptographic context
    /// for operations that may be performed on `data`.
    ///
    /// * `config` - A [`SensitiveInfoConfig`] instance that provides
    ///   configuration details for
    /// managing sensitive information.
    ///
    /// # Returns
    ///
    /// * Returns a new instance of [`Encryptor`] type, initialized with the
    ///   provided `data`, `context`, and `config`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let data = vec![1, 2, 3, 4, 5];
    /// let context = CryptorContext::new(...);
    /// let config = SensitiveInfoConfig::new(true);
    ///
    /// let encryptor = Encryptor::new(data, context, config);
    /// ```
    pub fn new(data: Vec<u8>, context: CryptorContext, config: SensitiveInfoConfig) -> Self {
        Self {
            data,
            context,
            config,
        }
    }

    /// Returns a reference to the encrypted data bytes stored within the
    /// [`Encryptor`] instance.
    ///
    /// This method provides read-only access to the internal `data` field,
    /// ensuring that the encrypted data cannot be modified directly by the
    /// caller.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Assuming you've set up an `Encryptor` instance named `encryptor`
    /// let data_bytes: &[u8] = encryptor.data();
    /// ```
    ///
    /// # Returns
    ///
    /// A byte slice (`&[u8]`) that represents the encrypted data.    
    /// Returns a reference to the data bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Encrypts data using the provided encryption key.
    ///
    /// # Arguments
    ///
    /// * `rng` - A mutable reference to the random number generator.
    /// * `encryption_key` - The key used to encrypt data.
    ///
    /// # Returns
    ///
    /// * A new instance of the [`Encryptor`]
    /// * Returns an error of type [`CryptoError`] if the encryption process
    ///   fails.
    pub fn encrypt(
        self,
        rng: &mut (impl CryptoRng + RngCore),
        encryption_key: &CryptorKey,
    ) -> Result<Decryptor, CryptoError> {
        // setup cipher... create a new instance of ChaCha20Poly1305 with key
        let cipher = ChaCha20Poly1305::new(&encryption_key.key_material);

        // Format plaintext and associated data
        let payload = Payload {
            msg: &self.data,
            aad: self.context.as_ref(),
        };

        // Generate nonce and encrypt the payload
        let nonce = ChaCha20Poly1305::generate_nonce(rng);
        let encrypted_data = cipher.encrypt(&nonce, payload).map_err(|e| {
            error!("Encryption failed unexpectedly. {:?}", e);
            CryptoError::EncryptionFailed
        })?;

        Ok(Decryptor::new(
            encrypted_data,
            self.context.clone(),
            nonce,
            SensitiveInfoConfig::new(true),
        ))
    }
}

/// The context (a.k.a. associated data).
///
/// TODO: We should consider making this a trait and require the calling
/// application to define appropriate context for each of their encrypted types.
/// See issue key-mgmt#542
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct CryptorContext {
    key_server_name: Vec<u8>,
}

/// An implementation of the `std::fmt::Display` trait for [`CryptorContext`].
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

/// Implement the `AsRef<[u8]>` trait for [`CryptorContext`].
impl AsRef<[u8]> for CryptorContext {
    fn as_ref(&self) -> &[u8] {
        &self.key_server_name
    }
}

impl CryptorContext {
    /// Constructs an instance of [`CryptorContext`].
    /// A type parameter is bounded by the `AsRef<[u8]>` trait.
    ///
    /// This trait is implemented by types that can be referenced as a byte
    /// slice, e.g. `&str`, `Vec<u8>`
    ///
    /// Example usage:
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
    pub fn new<T: AsRef<[u8]>>(key_server_name: T) -> Self {
        CryptorContext {
            // use as_ref method to get a byte slice from the parameter,
            // then convert the byte slice to a Vec<u8> with the to_vec method
            key_server_name: key_server_name.as_ref().to_vec(),
        }
    }
}

/// Conversion from `Vec<u8>` to [`CryptorContext`]
impl From<Vec<u8>> for CryptorContext {
    fn from(data_bytes: Vec<u8>) -> Self {
        // Create a new CryptorContext using the byte data
        CryptorContext {
            key_server_name: data_bytes,
        }
    }
}

/// Conversion to `Vec<u8>`
impl From<CryptorContext> for Vec<u8> {
    fn from(context: CryptorContext) -> Self {
        context.key_server_name
    }
}

/// The [`Decryptor`] type represents a ciphertext encrypted under the
/// [ChaCha20Poly1305 scheme](https://www.rfc-editor.org/rfc/rfc8439) for
/// authenticated encryption with associated data (AEAD).
///
/// As implied by the scheme name, this uses the recommended 20 rounds and a
/// standard 96-bit nonce. For more details, see the
/// [ChaCha20Poly1305 crate](https://docs.rs/chacha20poly1305/latest/chacha20poly1305/index.html).
#[derive(Clone, Eq)]
pub struct Decryptor {
    ciphertext: Vec<u8>,
    context: CryptorContext,
    nonce: chacha20poly1305::Nonce,
    config: SensitiveInfoConfig,
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

        if cfg!(debug_assertions) && !self.config.is_redacted() {
            // this is a Debug build *AND* redacted flag is FALSE

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
        } else {
            // this is a Release build *OR* redacted flag is TRUE
            write!(
                f,
                "\n---Encrypted data begin---\n\n\
                \t{redacted}\n\
                \n---Encrypted data end---\n",
                redacted = self.config.clone().redacted_label(),
            )
        }
    }
}

/// An implementation of the `std::fmt::Debug` trait for [`Decryptor`]
impl std::fmt::Debug for Decryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if cfg!(debug_assertions) && !self.config.is_redacted() {
            // this is a Debug build *AND* redacted flag is FALSE

            f.debug_struct("Decryptor")
                .field("ciphertext", &self.ciphertext)
                .field("nonce", &self.nonce)
                .field("context", &self.context)
                .finish()
        } else {
            // this is a Release build *OR* redacted flag is TRUE
            write!(f, "Decryptor {}", self.config.clone().redacted_label())
        }
    }
}

/// Implementation of the `TryFrom` trait for converting from [`Decryptor`] to
/// `Vec<u8>`
impl TryFrom<Decryptor> for Vec<u8> {
    type Error = CryptoError;

    fn try_from(decryptor: Decryptor) -> Result<Self, Self::Error> {
        // Output byte array format:
        // ciphertext len (2 bytes) || ciphertext || context len (2 bytes) ||
        // context data || nonce len (2 bytes) || nonce data || config len (2 bytes) ||
        // config data

        // de-structure the Decryptor struct to get direct access to its fields
        let Decryptor {
            ciphertext,
            nonce,
            config,
            context,
        } = decryptor;

        // convert each field to bytes as needed
        let context_bytes: Vec<u8> = context.into();
        let config_bytes: Vec<u8> = config.try_into()?;

        // convert lengths to u16...
        let ciphertext_length =
            u16::try_from(ciphertext.len()).map_err(|_| CryptoError::CannotEncodeDataLength)?;

        let context_length =
            u16::try_from(context_bytes.len()).map_err(|_| CryptoError::CannotEncodeDataLength)?;

        let config_length =
            u16::try_from(config_bytes.len()).map_err(|_| CryptoError::CannotEncodeDataLength)?;

        let nonce_length =
            u16::try_from(nonce.len()).map_err(|_| CryptoError::CannotEncodeDataLength)?;

        // construct the output byte array...
        // convert lengths from u16 to big-endian bytes
        let bytes = ciphertext_length
            .to_be_bytes()
            .into_iter()
            .chain(ciphertext)
            .chain(context_length.to_be_bytes())
            .chain(context_bytes)
            .chain(nonce_length.to_be_bytes())
            .chain(nonce)
            .chain(config_length.to_be_bytes())
            .chain(config_bytes)
            .collect();

        Ok(bytes)
    }
}

/// Implementation of the `TryFrom` trait for converting from `Vec<u8>` to
/// [`Decryptor`]
impl TryFrom<Vec<u8>> for Decryptor {
    type Error = CryptoError;

    #[instrument(skip_all, err(Debug))]
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        // Input byte array format:
        // ciphertext len (2 bytes) || ciphertext || context len (2 bytes) ||
        // context data || nonce len (2 bytes) || nonce data || config len (2 bytes) ||
        // config data

        // we'll be parsing the byte array, and creating an instance of Decryptor type
        let mut parse = ParseBytes::new(bytes);

        let ciphertext_length = parse.take_bytes_as_u16()?;
        // data_length is being converted from u16 to usize.
        // This conversion is always valid, guaranteed to never truncate data,
        // because a usize is always at least as large as a u16.
        let ciphertext = parse.take_bytes(ciphertext_length as usize)?.to_vec();

        let context_length = parse.take_bytes_as_u16()?;
        let context: Vec<u8> = parse.take_bytes(context_length as usize)?.to_vec();

        let nonce_length = parse.take_bytes_as_u16()?;
        // ChaCha20Poly1305 nonces should always be exactly 12 bytes
        let nonce: [u8; 12] = parse
            .take_bytes(nonce_length as usize)?
            .try_into()
            .map_err(|_| CryptoError::ConversionError)?;

        let config_length = parse.take_bytes_as_u16()?;
        let config: Vec<u8> = parse.take_rest()?.to_vec();

        // make sure that the length of the config matches the parsed length
        if config.len() != config_length as usize {
            return Err(CryptoError::ConversionError);
        }

        Ok(Self {
            ciphertext,
            context: context.into(),
            nonce: nonce.into(),
            config: config.try_into()?,
        })
    }
}

/// Implement the `PartialEq` trait for the [`Decryptor`] type.
impl PartialEq for Decryptor {
    /// Determines if two [`Decryptor`] instances are equal.
    ///
    /// This function compares the fields of two [`Decryptor`] instances,
    /// excluding the `config` field because the `config` field does not
    /// affect the functional equivalence of two [`Decryptor`] instances.
    ///
    /// # Arguments
    ///
    /// * `other` - The other [`Decryptor`] instance to compare with.
    ///
    /// # Returns
    ///
    /// Returns `true` if the non-`config` fields are equal between the two
    /// [`Decryptor`] instances, Otherwise returns `false`.
    fn eq(&self, other: &Self) -> bool {
        // Don't compare the config fields
        self.ciphertext == other.ciphertext
            && self.context == other.context
            && self.nonce == other.nonce
    }
}

impl Decryptor {
    /// Constructs a new instance of the [`Decryptor`] type.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - A vector of bytes representing the ciphertext. This is
    ///   typically the result of the encrypt operation.
    ///
    /// * `context` - An instance of [`CryptorContext`]
    ///
    /// * `nonce` - A `chacha20poly1305::Nonce` instance. This is used in the
    ///   encryption process to ensure the security of the ciphertext. Every
    ///   time data is encrypted, a unique nonce should be generated.
    ///
    /// # Returns
    ///
    /// Returns a new instance of the [`Decryptor`] type, initialized with the
    /// provided `ciphertext`, `context`, `nonce`, and `config`.
    fn new(
        ciphertext: Vec<u8>,
        context: CryptorContext,
        nonce: chacha20poly1305::Nonce,
        config: SensitiveInfoConfig,
    ) -> Self {
        Self {
            ciphertext,
            context,
            nonce,
            config,
        }
    }

    /// Decrypts data using the provided key.
    ///
    /// # Arguments
    ///
    /// * `decryption_key` - The key used to decrypt the data.
    ///
    /// # Returns
    ///
    /// * A newly created [`Encryptor`] instance containing the decrypted data.
    /// * Returns an error of type [`CryptoError`] if the decryption process
    ///   fails.
    pub fn decrypt(self, decryption_key: &CryptorKey) -> Result<Encryptor, CryptoError> {
        // setup cipher... create a new instance of ChaCha20Poly1305 with key
        let cipher = ChaCha20Poly1305::new(&decryption_key.key_material);

        // Format ciphertext and associated data
        let payload = Payload {
            msg: &self.ciphertext,
            aad: self.context.as_ref(),
        };

        // Decrypt
        let plaintext_data = cipher
            .decrypt(&self.nonce, payload)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        // Return the decrypted data
        Ok(Encryptor::new(
            plaintext_data,
            self.context,
            SensitiveInfoConfig::new(true),
        ))
    }
}

/// Tests...
#[cfg(test)]
mod test {
    use super::*;
    use crate::infrastructure::sensitive_info::sensitive_info_check;

    const KEY_SERVER_NAME: &str = "test_key_server_1";
    const DATA_BYTES_LENGTH: usize = 257;

    /// Test the correctness of the sensitive information handling.
    #[test]
    fn cryptor_key_sensitive_info_handling_on_debug_and_display() {
        // generate some random data
        let data_plaintext = generate_random_data(DATA_BYTES_LENGTH);

        // create an Encryptor instance
        let mut encryptor = Encryptor::new(
            data_plaintext.to_vec(),
            CryptorContext::new(KEY_SERVER_NAME),
            SensitiveInfoConfig::new(true),
        );

        println!(
            "\nEncryptor with redacted config:\n{encryptor}",
            encryptor = encryptor
        );

        // sensitive information is currently redacted, let's test that
        sensitive_info_check(&encryptor, &encryptor.config).unwrap();

        // unredact sensitive information, and test
        encryptor.config.unredact();

        println!(
            "\nEncryptor with un-redacted config:\n{encryptor}",
            encryptor = encryptor
        );

        sensitive_info_check(&encryptor, &encryptor.config).unwrap();
    }

    /// Converts an encryptor between [`Encryptor`] and `Vec<u8>`
    /// representations and verifies the conversion.
    ///
    /// # Errors
    ///
    /// Returns a [`CryptoError`] if there is an error during encryption or
    /// conversion.
    #[test]
    fn encryptor_vec_u8_conversion() -> Result<(), CryptoError> {
        // generate some random data
        let data_plaintext = generate_random_data(DATA_BYTES_LENGTH);

        // create an Encryptor instance
        let encryptor = Encryptor::new(
            data_plaintext.to_vec(),
            CryptorContext::new(KEY_SERVER_NAME),
            SensitiveInfoConfig::new(false),
        );

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
            "\nConverted encryptor: {encryptor}",
            encryptor = encryptor_from_vec
        );

        // compare the original and converted encryptor
        assert_eq!(encryptor, encryptor_from_vec);

        Ok(())
    }

    /// Sets up a [`Decryptor`] instance for testing.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the [`Decryptor`] instance if successful,
    /// or a [`CryptoError`] if any step in the setup fails.    
    fn setup_decryptor() -> Result<Decryptor, CryptoError> {
        let mut rng = rand::thread_rng();

        // Generate some random data
        let data_plaintext = generate_random_data(DATA_BYTES_LENGTH);

        // Create an Encryptor instance
        let encryptor = Encryptor::new(
            data_plaintext.to_vec(),
            CryptorContext::new(KEY_SERVER_NAME),
            SensitiveInfoConfig::new(true),
        );

        // Generate an encryption key
        let data_encryption_key = CryptorKey::new(&mut rng);

        // Encrypt the data
        let mut decryptor = encryptor.encrypt(&mut rng, &data_encryption_key)?;

        // Unredact the decryptor, so we can display all of the sensitive info for
        // debugging/visual inspection
        decryptor.config.unredact();

        Ok(decryptor)
    }

    /// Converts a decryptor from `Vec<u8>` to [`Decryptor`].
    /// Removes some bytes to make the conversion fail.
    ///
    /// # Errors
    ///
    /// Returns a [`CryptoError`] if there is an error
    #[test]
    fn decryptor_from_bytes_requires_all_fields() -> Result<(), CryptoError> {
        let decryptor = setup_decryptor()?;

        let mut decryptor_vec: Vec<u8> = decryptor.try_into()?;

        // Remove some bytes to simulate incomplete fields
        decryptor_vec.truncate(decryptor_vec.len() - 10);

        // This should fail
        assert!(Decryptor::try_from(decryptor_vec).is_err());

        Ok(())
    }

    /// Converts a decryptor from `Vec<u8>` to [`Decryptor`].
    /// Adds extra bytes at the end of the byte array to make the conversion
    /// fail.
    ///
    /// # Errors
    ///
    /// Returns a [`CryptoError`] if there is an error
    #[test]
    fn decryptor_from_bytes_cannot_have_extra_bytes() -> Result<(), CryptoError> {
        let decryptor = setup_decryptor()?;

        let mut decryptor_vec: Vec<u8> = decryptor.try_into()?;

        // Append extra bytes
        decryptor_vec.extend_from_slice(&[0xBB, 0xAA, 0xAA, 0xDD]);

        // This should fail
        assert!(Decryptor::try_from(decryptor_vec).is_err());

        Ok(())
    }

    /// Converts a decryptor between [`Decryptor`] and `Vec<u8>`
    /// representations and verifies the conversion.
    ///
    /// # Errors
    ///
    /// Returns a [`CryptoError`] if there is an error during encryption or
    /// conversion.
    #[test]
    fn decryptor_vec_u8_conversion_works() -> Result<(), CryptoError> {
        let decryptor = setup_decryptor()?;

        // convert decryptor to Vec<u8> by cloning
        let decryptor_vec: Vec<u8> = decryptor.clone().try_into()?;

        // convert Vec<u8> back to decryptor
        let decryptor_from_vec: Decryptor = decryptor_vec.try_into()?;

        println!("\nOriginal decryptor: {decryptor}", decryptor = decryptor);
        println!(
            "\nConverted encryptor: {decryptor}",
            decryptor = decryptor_from_vec
        );

        // compare the original and converted decryptor
        assert_eq!(decryptor, decryptor_from_vec);

        Ok(())
    }

    /// Encrypts and decrypts data, verifying the consistency of the
    /// encryption process.
    ///
    /// # Errors
    ///
    /// * Returns a [`CryptoError`] if there is an error during encryption,
    ///   decryption, or verification.
    #[test]
    fn data_encrypt_decrypt() -> Result<(), CryptoError> {
        let mut rng = rand::thread_rng();

        // generate some random data
        let data = generate_random_data(DATA_BYTES_LENGTH);

        // generate an encryption key
        let data_encryption_key = CryptorKey::new(&mut rng);

        // create an Encryptor instance
        let plaintext_data = Encryptor::new(
            data.to_vec(),
            CryptorContext::new(KEY_SERVER_NAME),
            SensitiveInfoConfig::new(true),
        );

        // clone, so we can use it later
        let original_data = plaintext_data.clone();

        // encrypt the data
        let mut encrypted_data = plaintext_data.encrypt(&mut rng, &data_encryption_key)?;
        // unredact data for display
        encrypted_data.config.unredact();

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
        let mut decrypted_data = encrypted_data.decrypt(&data_encryption_key)?;
        // unredact data for display
        decrypted_data.config.unredact();

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
    /// * Returns a [`CryptoError`] if there is an error during encryption,
    ///   decryption, or verification.
    #[test]
    fn data_context_fails() -> Result<(), CryptoError> {
        let mut rng = rand::thread_rng();

        // generate some random data
        let data = generate_random_data(DATA_BYTES_LENGTH);

        // create a new data encryption key
        let data_encryption_key = CryptorKey::new(&mut rng);

        // create a new instance of Encryptor
        let plaintext_data = Encryptor::new(
            data.to_vec(),
            CryptorContext::new(KEY_SERVER_NAME),
            SensitiveInfoConfig::new(true),
        );

        // encrypt the data
        let mut encrypted_data = plaintext_data.encrypt(&mut rng, &data_encryption_key)?;
        // unredact for display
        encrypted_data.config.unredact();

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

    /// Generates some random data to be used by the unit test functions.
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
