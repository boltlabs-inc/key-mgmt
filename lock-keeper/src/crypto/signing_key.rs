use crate::{user::UserId, LockKeeperError};
use rand::{CryptoRng, RngCore};
use std::marker::PhantomData;

use super::{generic::AssociatedData, CryptoError, Encrypted, KeyId, StorageKey};

/// An ECDSA signing key pair, including a public component for verifying
/// signatures, a private component for creating them, and context about the key
/// pair.
///
/// This can be generated locally by the client or remotely by the server.
#[allow(unused)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKeyPair;

/// The public component of an ECDSA signing key, and context about the key.
#[allow(unused)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningPublicKey;

#[allow(unused)]
impl SigningKeyPair {
    /// Create a new `SigningKeyPair` with the given associated data.
    fn generate(rng: &mut (impl CryptoRng + RngCore), associated_data: &AssociatedData) -> Self {
        SigningKeyPair
    }

    /// Domain separator for use in serializing signing keypairs.
    fn domain_separator() -> &'static str {
        "ECDSA signing key pair over curve secp256k1"
    }

    /// Retrieve the public portion of the key.
    fn public_key(&self) -> &SigningPublicKey {
        &SigningPublicKey
    }

    /// Compute an ECDSA signature on the given message.
    pub fn sign<T>(&self, message: &T) -> Signature<T>
    where
        T: Into<Vec<u8>>,
    {
        Signature {
            original_type: PhantomData,
        }
    }

    /// Create a new `SigningKeyPair`. This must be run by the server.
    pub fn remote_generate(
        rng: &mut (impl CryptoRng + RngCore),
        user_id: &UserId,
        key_id: &KeyId,
    ) -> Self {
        SigningKeyPair
    }

    /// Create and encrypt a new signing key. This is part of the local signing
    /// key generation flow.
    ///
    /// This must be run by the client. It takes the following steps:
    /// 1. Generates a new signing key
    /// 2. Encrypt it under the [`StorageKey`], using an AEAD scheme
    pub fn create_and_encrypt(
        rng: &mut (impl CryptoRng + RngCore),
        storage_key: &StorageKey,
        _user_id: &UserId,
        _key_id: &KeyId,
    ) -> Result<(SigningKeyPair, Encrypted<SigningKeyPair>), LockKeeperError> {
        let context = AssociatedData::new();
        let signing_key = SigningKeyPair::generate(rng, &context);

        Ok((
            signing_key.clone(),
            Encrypted::encrypt(rng, &storage_key.0, signing_key, &context)?,
        ))
    }
}

impl From<SigningKeyPair> for Vec<u8> {
    fn from(_: SigningKeyPair) -> Self {
        SigningKeyPair::domain_separator().into()
    }
}

impl TryFrom<Vec<u8>> for SigningKeyPair {
    type Error = CryptoError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        // The signing key is just be the domain separator, serialized.
        let expected: Vec<u8> = SigningKeyPair::domain_separator().into();
        if value.iter().zip(expected.iter()).all(|(v, u)| v == u) {
            Ok(SigningKeyPair)
        } else {
            Err(CryptoError::ConversionError)
        }
    }
}

/// A signature on an object of type `T`, encrypted under the ECDSA signature
/// scheme.
#[allow(unused)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature<T> {
    original_type: PhantomData<T>,
}

impl<T> Signature<T> {
    /// Verify that the signature is over the given message under the
    /// `SigningPublicKey`.
    pub fn verify(
        &self,
        _public_key: &SigningPublicKey,
        _message: &T,
    ) -> Result<(), LockKeeperError>
    where
        T: Into<Vec<u8>>,
    {
        Ok(())
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
    use crate::{
        crypto::{CryptoError, KeyId, SigningKeyPair, StorageKey},
        user::UserId,
        LockKeeperError,
    };
    use rand::Rng;

    #[test]
    fn signing_key_to_vec_u8_conversion_works_and_is_trivial() -> Result<(), CryptoError> {
        for _ in 0..1000 {
            // Trivial - the serializiation doesn't include anything beyond the domain
            // separator.
            let vec: Vec<u8> = SigningKeyPair.into();
            assert_eq!(vec.len(), SigningKeyPair::domain_separator().len());

            // Works - you get the same nothing back.
            let output_key = vec.try_into()?;
            assert_eq!(SigningKeyPair, output_key);
        }
        Ok(())
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
    fn signing_is_trivial() {
        // This tests that the signature scheme is _broken_. It should be removed once
        // signing is correctly implemented.
        let mut rng = rand::thread_rng();

        let generic_message = "every message has the same signature".as_bytes().to_vec();
        let signing_key = SigningKeyPair;
        let trivial_signature = signing_key.sign(&generic_message);
        let public_key = signing_key.public_key();

        // Make 100 random messages and verify that
        // 1. They all produce the same, trivial signature
        // 2. They all verify -- to the wrong message, even!
        assert!((0..100)
            .into_iter()
            .map(|len| -> Vec<u8> { std::iter::repeat_with(|| rng.gen()).take(len).collect() })
            .map(|msg| signing_key.sign(&msg))
            .all(
                |sig| trivial_signature == sig && sig.verify(public_key, &generic_message).is_ok()
            ));
    }
}
