use crate::{types::database::user::UserId, LockKeeperError};
use k256::ecdsa::{
    self,
    signature::{Signer, Verifier},
    SigningKey, VerifyingKey,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use super::{generic::AssociatedData, CryptoError, Encrypted, KeyId, StorageKey};

/// Things that can be signed must implement the `Signable` trait.
pub trait Signable: AsRef<[u8]> {}

/// Right now, we don't have any meaningful signable types, but we implement it
/// for `Vec<u8>` to enable testing.
#[cfg(test)]
impl Signable for Vec<u8> {}

/// An ECDSA signing key pair, including a public component for verifying
/// signatures, a private component for creating them, and context about the key
/// pair.
///
/// This can be generated locally by the client or remotely by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKeyPair {
    signing_key: SigningKey,
    context: AssociatedData,
}

/// The public component of an ECDSA signing key, and context about the key.
#[allow(unused)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningPublicKey(VerifyingKey);

/// Temporary type to represent a remotely generated encrypted
/// [`SigningKeyPair`].
///
/// This can only be "decrypted" by the server.
/// TODO #307: Replace this placeholder with actual encryption.
#[derive(Debug, Deserialize, Serialize)]
pub struct PlaceholderEncryptedSigningKeyPair {
    signing_key: Vec<u8>,
    context: AssociatedData,
}

impl From<SigningKeyPair> for PlaceholderEncryptedSigningKeyPair {
    fn from(key_pair: SigningKeyPair) -> Self {
        Self {
            signing_key: key_pair.signing_key.to_bytes().to_vec(),
            context: key_pair.context,
        }
    }
}

impl TryFrom<PlaceholderEncryptedSigningKeyPair> for SigningKeyPair {
    type Error = LockKeeperError;
    fn try_from(key_pair: PlaceholderEncryptedSigningKeyPair) -> Result<Self, Self::Error> {
        Ok(Self {
            signing_key: SigningKey::from_bytes(key_pair.signing_key.as_slice())
                .map_err(|_| CryptoError::ConversionError)?,
            context: key_pair.context,
        })
    }
}

impl SigningKeyPair {
    /// Create a new `SigningKeyPair` with the given associated data.
    fn generate(rng: &mut (impl CryptoRng + RngCore), context: &AssociatedData) -> Self {
        Self {
            signing_key: SigningKey::random(rng),
            context: context.clone(),
        }
    }

    /// Domain separator for use in serializing signing keypairs.
    fn domain_separator() -> &'static str {
        "ECDSA signing key pair over curve secp256k1"
    }

    /// Retrieve the public portion of the key.
    ///
    /// This method could be made public if necessary.
    #[cfg(test)]
    fn public_key(&self) -> SigningPublicKey {
        SigningPublicKey(self.signing_key.verifying_key())
    }

    /// Retrieve the context associated with the signing key.
    #[cfg(test)]
    fn context(&self) -> &AssociatedData {
        &self.context
    }

    /// Compute an ECDSA signature on the given message.
    pub fn sign<T: Signable>(&self, message: &T) -> Signature<T> {
        Signature {
            signature: self.signing_key.sign(message.as_ref()),
            original_type: PhantomData,
        }
    }

    /// Create a new `SigningKeyPair`. This must be run by the server.
    pub fn remote_generate(
        rng: &mut (impl CryptoRng + RngCore),
        user_id: &UserId,
        key_id: &KeyId,
    ) -> Self {
        let context = AssociatedData::new()
            .with_bytes(user_id.clone())
            .with_bytes(key_id.clone())
            .with_str("server-generated");
        Self::generate(rng, &context)
    }

    /// Create a `SigningKeyPair` from an imported key and encrypt it for
    /// storage at a server, under a key known only to the client.
    ///
    /// This is part of the local import with remote backup flow and must be run
    /// by the client. In this flow, the key server will only receive an
    /// [`Encrypted<SigningKeyPair>`], not the cleartext.
    ///
    /// `key_material` should be a scalar value formatted in big endian. See
    /// [k256 documentation](https://docs.rs/k256/latest/k256/ecdsa/struct.SigningKey.html#method.from_bytes)
    /// for details.
    ///
    /// This function takes the following steps:
    /// 1. Format the `key_material` as a signing key
    /// 2. Encrypt it under the [`StorageKey`], using an AEAD scheme
    pub fn import_and_encrypt(
        key_material: &[u8],
        rng: &mut (impl CryptoRng + RngCore),
        storage_key: &StorageKey,
        user_id: &UserId,
        key_id: &KeyId,
    ) -> Result<(Self, Encrypted<Self>), LockKeeperError> {
        let context = AssociatedData::new()
            .with_bytes(user_id.clone())
            .with_bytes(key_id.clone())
            .with_str("imported key");

        let signing_key = Self {
            signing_key: SigningKey::from_bytes(key_material)
                .map_err(|_| CryptoError::ConversionError)?,
            context: context.clone(),
        };

        Ok((
            signing_key.clone(),
            Encrypted::encrypt(rng, &storage_key.0, signing_key, &context)?,
        ))
    }

    /// Create and encrypt a new signing key for storage at
    /// a server, under a key known only to the client.
    ///
    /// This is part of the local signing key generation flow and must be run by
    /// the client. In this flow the key server will only receive an
    /// [`Encrypted<SigningKeyPair>`], not the cleartext.
    ///
    /// This function takes the following steps:
    /// 1. Generates a new signing key
    /// 2. Encrypt it under the [`StorageKey`], using an AEAD scheme
    pub fn create_and_encrypt(
        rng: &mut (impl CryptoRng + RngCore),
        storage_key: &StorageKey,
        user_id: &UserId,
        key_id: &KeyId,
    ) -> Result<(Self, Encrypted<Self>), LockKeeperError> {
        let context = AssociatedData::new()
            .with_bytes(user_id.clone())
            .with_bytes(key_id.clone())
            .with_str("client-generated");
        let signing_key = SigningKeyPair::generate(rng, &context);

        Ok((
            signing_key.clone(),
            Encrypted::encrypt(rng, &storage_key.0, signing_key, &context)?,
        ))
    }
}

/// Raw material for an imported signing key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    pub key_material: Vec<u8>,
}

impl TryFrom<&[u8]> for Import {
    type Error = LockKeeperError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // Check if these bytes are correctly formatted to make a signing key,
        // but don't actually use the key.
        let _signing_key =
            SigningKey::from_bytes(bytes).map_err(|_| CryptoError::ConversionError)?;

        Ok(Self {
            key_material: bytes.into(),
        })
    }
}

impl Import {
    /// Convert an [`Import`] into a [`SigningKeyPair`] with appropriate
    /// context.
    ///
    /// This is part of the flow to send an imported key in cleartext to the key
    /// server and must be called by the server.
    ///
    /// This will fail if `material` is not a scalar value formatted in big
    /// endian. See [k256 documentation](https://docs.rs/k256/latest/k256/ecdsa/struct.SigningKey.html#method.from_bytes)
    /// for details.
    pub fn into_signing_key(
        self,
        user_id: &UserId,
        key_id: &KeyId,
    ) -> Result<SigningKeyPair, LockKeeperError> {
        let context = AssociatedData::new()
            .with_bytes(user_id.clone())
            .with_bytes(key_id.clone())
            .with_str("imported key");

        let signing_key =
            SigningKey::from_bytes(&self.key_material).map_err(|_| CryptoError::ConversionError)?;

        Ok(SigningKeyPair {
            signing_key,
            context,
        })
    }
}

/// Raw material for an exported signing key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    pub key_material: Vec<u8>,
    pub context: Vec<u8>,
}

impl From<SigningKeyPair> for Export {
    fn from(key_pair: SigningKeyPair) -> Self {
        Self {
            key_material: key_pair.signing_key.to_bytes().to_vec(),
            context: key_pair.context.into(),
        }
    }
}

impl Export {
    /// Convert `Export` into a [`SigningKeyPair`].
    pub fn into_signing_key(self) -> Result<SigningKeyPair, LockKeeperError> {
        let signing_key = SigningKey::from_bytes(self.key_material.as_slice())
            .map_err(|_| CryptoError::ConversionError)?;
        let context = self.context.try_into()?;
        Ok(SigningKeyPair {
            signing_key,
            context,
        })
    }
}

impl From<SigningKeyPair> for Vec<u8> {
    fn from(key_pair: SigningKeyPair) -> Self {
        let domain_separator_bytes: Vec<u8> = SigningKeyPair::domain_separator().into();
        let signing_key = key_pair.signing_key.to_bytes();

        domain_separator_bytes
            .into_iter()
            .chain(std::iter::once(signing_key.len() as u8))
            .chain(signing_key)
            .chain::<Vec<u8>>(key_pair.context.into())
            .collect()
    }
}

impl TryFrom<Vec<u8>> for SigningKeyPair {
    type Error = CryptoError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        // len || domain separator
        let separator_offset = SigningKeyPair::domain_separator().len();
        let separator = std::str::from_utf8(
            value
                .get(0..separator_offset)
                .ok_or(CryptoError::ConversionError)?,
        )
        .map_err(|_| CryptoError::ConversionError)?;
        if separator != SigningKeyPair::domain_separator() {
            return Err(CryptoError::ConversionError);
        }

        // len || signing key
        let signing_key_len = *value
            .get(separator_offset)
            .ok_or(CryptoError::ConversionError)? as usize;
        let signing_key_offset = separator_offset + 1;
        let signing_key_end = signing_key_offset + signing_key_len;
        let signing_key_bytes = value
            .get(signing_key_offset..signing_key_end)
            .ok_or(CryptoError::ConversionError)?;
        let signing_key =
            SigningKey::from_bytes(signing_key_bytes).map_err(|_| CryptoError::ConversionError)?;

        // AssociatedData `try_into` handles length prepending
        let context_offset = signing_key_end;
        let context_bytes = value
            .get(context_offset..)
            .ok_or(CryptoError::ConversionError)?
            .to_vec();
        let context: AssociatedData = context_bytes.try_into()?;

        Ok(Self {
            signing_key,
            context,
        })
    }
}

/// A signature on an object of type `T`, encrypted under the ECDSA signature
/// scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature<T> {
    signature: ecdsa::Signature,
    original_type: PhantomData<T>,
}

impl<T> Signature<T> {
    /// Verify that the signature is over the given message under the
    /// `SigningPublicKey`.
    pub fn verify(&self, public_key: &SigningPublicKey, message: &T) -> Result<(), LockKeeperError>
    where
        T: Signable,
    {
        Ok(public_key
            .0
            .verify(message.as_ref(), &self.signature)
            .map_err(|_| CryptoError::VerificationFailed)?)
    }
}

impl Encrypted<SigningKeyPair> {
    /// Decrypt a signing key. This should be run as part of the subprotocol to
    /// retrieve an encrypted signing key from the server.
    ///
    /// This must be run by the client.
    pub fn decrypt_secret(
        self,
        storage_key: StorageKey,
    ) -> Result<SigningKeyPair, LockKeeperError> {
        let decrypted = self.decrypt(&storage_key.0)?;
        Ok(decrypted)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;
    use std::marker::PhantomData;

    use crate::{
        crypto::{generic::AssociatedData, CryptoError, KeyId, SigningKeyPair, StorageKey},
        types::database::user::UserId,
        LockKeeperError,
    };
    use k256::{ecdsa::SigningKey, schnorr::signature::Signature as EcdsaSignature};

    use super::Signature;

    #[test]
    fn signing_keys_conversion_works() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let signing_key = SigningKey::random(&mut rng);
            let bytes = signing_key.to_bytes();
            let output_key = SigningKey::from_bytes(&bytes).unwrap();
            assert_eq!(signing_key, output_key);

            let byte_vec: Vec<u8> = signing_key.to_bytes().into_iter().collect();
            let output_key = SigningKey::from_bytes(&byte_vec).unwrap();
            assert_eq!(signing_key, output_key);
        }
    }

    #[test]
    fn signing_key_to_vec_u8_conversion_works() -> Result<(), CryptoError> {
        let mut rng = rand::thread_rng();
        for i in 0_i32..1000 {
            let context = AssociatedData::new().with_bytes(i.to_le_bytes());
            let key = SigningKeyPair::generate(&mut rng, &context);
            let vec: Vec<u8> = key.clone().into();

            let output_key = vec.try_into()?;
            assert_eq!(key, output_key);
        }
        Ok(())
    }

    #[test]
    fn export_conversion_works() {
        let mut rng = rand::thread_rng();
        let context = AssociatedData::new().with_str("a key for trying export");
        let key = SigningKeyPair::generate(&mut rng, &context);

        let export: Export = key.clone().into();
        let output_key: SigningKeyPair = export.into_signing_key().unwrap();

        assert_eq!(key, output_key);
    }

    #[test]
    fn import_conversion_works() -> Result<(), LockKeeperError> {
        let mut rng = rand::thread_rng();
        let user_id = UserId::new(&mut rng)?;
        let key_id = KeyId::generate(&mut rng, &user_id)?;

        let context = AssociatedData::new()
            .with_bytes(user_id.clone())
            .with_bytes(key_id.clone())
            .with_str("imported key");

        let key = SigningKeyPair::generate(&mut rng, &context);

        let raw_bytes = key.signing_key.to_bytes();
        let import: Import = raw_bytes.as_slice().try_into()?;

        let output_key: SigningKeyPair = import.into_signing_key(&user_id, &key_id)?;

        // Make sure the output key matches.
        // Note that `context` above is the expected AD for an imported key.
        assert_eq!(key, output_key);
        Ok(())
    }

    #[test]
    fn placeholder_encryption_conversion_works() {
        let mut rng = rand::thread_rng();
        let context = AssociatedData::new().with_str("a key to fake-encrypt");
        let key = SigningKeyPair::generate(&mut rng, &context);

        let placeholder: PlaceholderEncryptedSigningKeyPair = key.clone().into();
        let output_key: SigningKeyPair = placeholder.try_into().unwrap();

        assert_eq!(key, output_key);
    }

    #[test]
    fn signing_key_encryption_works() -> Result<(), LockKeeperError> {
        let mut rng = rand::thread_rng();
        let storage_key = StorageKey::generate(&mut rng);

        let user_id = UserId::new(&mut rng)?;
        let key_id = KeyId::generate(&mut rng, &user_id)?;

        // Create and encrypt a secret
        let (signing_key, encrypted_signing_key) =
            SigningKeyPair::create_and_encrypt(&mut rng, &storage_key, &user_id, &key_id)?;

        // Decrypt the secret
        let decrypted_signing_key = encrypted_signing_key.decrypt_secret(storage_key)?;
        assert_eq!(decrypted_signing_key, signing_key);

        Ok(())
    }

    #[test]
    fn signing_works() {
        let mut rng = rand::thread_rng();

        let signing_key = SigningKeyPair::generate(&mut rng, &AssociatedData::new());
        let public_key = signing_key.public_key();

        // Signatures on random messages must verify
        assert!((0..1000)
            .into_iter()
            .map(|len| -> Vec<u8> { std::iter::repeat_with(|| rng.gen()).take(len).collect() })
            .map(|msg| (signing_key.sign(&msg), msg))
            .all(|(sig, msg)| sig.verify(&public_key, &msg).is_ok()));
    }

    #[test]
    fn verifying_requires_correct_message() {
        let mut rng = rand::thread_rng();

        let signing_key = SigningKeyPair::generate(&mut rng, &AssociatedData::new());
        let public_key = signing_key.public_key();
        let message = b"signatures won't verify with a bad message".to_vec();
        let sig = signing_key.sign(&message);

        let bad_msg = b"this is obviously not the same message".to_vec();
        assert!(sig.verify(&public_key, &bad_msg).is_err());
        assert!(sig.verify(&public_key, &message).is_ok());
    }

    #[test]
    fn verifying_requires_correct_public_key() {
        let mut rng = rand::thread_rng();

        let signing_key = SigningKeyPair::generate(&mut rng, &AssociatedData::new());
        let message = b"signatures won't verify with a bad public key".to_vec();
        let sig = signing_key.sign(&message);

        let bad_key = SigningKeyPair::generate(&mut rng, &AssociatedData::new()).public_key();
        assert!(sig.verify(&bad_key, &message).is_err());
        assert!(sig.verify(&signing_key.public_key(), &message).is_ok());
    }

    #[test]
    fn signature_bits_cannot_be_flipped() {
        let mut rng = rand::thread_rng();

        let signing_key = SigningKeyPair::generate(&mut rng, &AssociatedData::new());
        let message = b"the signature on this message will get tweaked".to_vec();
        let sig = signing_key.sign(&message);
        let sig_bytes = sig.signature.as_bytes();

        // try flipping some of the bits
        for i in 0..sig_bytes.len() {
            let mut tweaked = sig_bytes.to_vec();
            tweaked[i] ^= 1;

            // either the signature won't parse...
            let signature = match k256::ecdsa::Signature::from_bytes(&tweaked) {
                Ok(sig) => sig,
                Err(_) => continue,
            };
            let tweaked_sig = Signature {
                signature,
                original_type: PhantomData,
            };

            // ...or the signature won't verify.
            assert!(tweaked_sig
                .verify(&signing_key.public_key(), &message)
                .is_err());
        }
        assert!(sig.verify(&signing_key.public_key(), &message).is_ok());
    }

    #[test]
    fn into_signing_key_works() -> Result<(), LockKeeperError> {
        let mut rng = rand::thread_rng();

        let user_id = UserId::new(&mut rng)?;
        let key_id = KeyId::generate(&mut rng, &user_id)?;

        let key_material: [u8; 32] = rng.gen();
        let import: Import = key_material.as_ref().try_into()?;

        // With normal arguments, it just works
        let key_pair = import.into_signing_key(&user_id, &key_id)?;

        // Make sure key matches input key material (e.g. the secret material
        // appears somewhere within the serialization).
        let bytes: Vec<u8> = key_pair.into();
        assert!(bytes.windows(32).any(|c| c == key_material));

        // Key material must be the right size
        let not_enough_key_material: [u8; 12] = rng.gen();
        let short_import: Result<Import, _> = not_enough_key_material.as_ref().try_into();
        assert!(short_import.is_err());

        let too_much_key_material: Vec<u8> =
            std::iter::repeat_with(|| rng.gen()).take(64).collect();
        let long_import: Result<Import, _> = too_much_key_material.as_slice().try_into();
        assert!(long_import.is_err());

        Ok(())
    }

    #[test]
    fn import_and_encrypt_encrypts_correct_key() -> Result<(), LockKeeperError> {
        let mut rng = rand::thread_rng();
        let storage_key = StorageKey::generate(&mut rng);

        let user_id = UserId::new(&mut rng)?;
        let key_id = KeyId::generate(&mut rng, &user_id)?;

        let key_material = SigningKey::random(rng.clone()).to_bytes().to_vec();
        let (key, encrypted_key) = SigningKeyPair::import_and_encrypt(
            &key_material,
            &mut rng,
            &storage_key,
            &user_id,
            &key_id,
        )?;

        // Make sure encrypted key matches output key
        let decrypted_key = encrypted_key.decrypt_secret(storage_key)?;
        assert_eq!(key, decrypted_key);

        // Make sure key matches input key material (e.g. the secret material
        // appears somewhere within the serialization).
        let bytes: Vec<u8> = key.into();
        assert!(bytes.windows(32).any(|c| c == key_material));

        Ok(())
    }

    #[test]
    fn keys_are_labelled_with_origin() -> Result<(), LockKeeperError> {
        let mut rng = rand::thread_rng();
        let storage_key = StorageKey::generate(&mut rng);

        let user_id = UserId::new(&mut rng)?;
        let key_id = KeyId::generate(&mut rng, &user_id)?;

        // Convenient, inefficient method to check whether the AD for a key pair
        // contains a given string
        let contains_str = |container: SigningKeyPair, subset: &'static str| -> bool {
            let container_ad: Vec<u8> = container.context().to_owned().into();
            let subset: Vec<u8> = subset.as_bytes().into();
            container_ad.windows(subset.len()).any(|c| c == subset)
        };

        // Create and encrypt a key pair - client side
        let (secret, _) =
            SigningKeyPair::create_and_encrypt(&mut rng, &storage_key, &user_id, &key_id)?;
        assert!(!contains_str(secret.clone(), "imported"));
        assert!(!contains_str(secret.clone(), "server-generated"));
        assert!(contains_str(secret, "client-generated"));

        // Remote generate a key pair -- not imported.
        let secret = SigningKeyPair::remote_generate(&mut rng, &user_id, &key_id);
        assert!(!contains_str(secret.clone(), "imported"));
        assert!(!contains_str(secret.clone(), "client-generated"));
        assert!(contains_str(secret, "server-generated"));

        // Use the local-import creation function
        let key_material = SigningKey::random(rng.clone()).to_bytes();
        let (imported_secret, _) = SigningKeyPair::import_and_encrypt(
            &key_material,
            &mut rng,
            &storage_key,
            &user_id,
            &key_id,
        )?;
        assert!(!contains_str(imported_secret.clone(), "client-generated"));
        assert!(!contains_str(imported_secret.clone(), "server-generated"));
        assert!(contains_str(imported_secret, "imported"));

        // Use the remote-import creation function
        let import: Import = key_material.as_slice().try_into()?;
        let key_pair = import.into_signing_key(&user_id, &key_id)?;
        assert!(!contains_str(key_pair.clone(), "client-generated"));
        assert!(!contains_str(key_pair.clone(), "server-generated"));
        assert!(contains_str(key_pair, "imported"));

        Ok(())
    }
}
