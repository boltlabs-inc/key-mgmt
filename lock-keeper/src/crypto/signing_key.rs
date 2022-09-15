use crate::{user::UserId, LockKeeperError};
use rand::{CryptoRng, RngCore};
use std::marker::PhantomData;

use super::{generic::AssociatedData, CryptoError, Encrypted, KeyId, StorageKey};

/// An ECDSA signing key.
///
/// This can be generated locally by the client or remotely by the server.
#[allow(unused)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKey;

impl SigningKey {
    fn domain_separator() -> &'static str {
        "ECDSA signing key"
    }
}

impl From<SigningKey> for Vec<u8> {
    fn from(_: SigningKey) -> Self {
        SigningKey::domain_separator().into()
    }
}

impl TryFrom<Vec<u8>> for SigningKey {
    type Error = CryptoError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let expected: Vec<u8> = SigningKey::domain_separator().into();
        if value.iter().zip(expected.iter()).all(|(v, u)| v == u) {
            Ok(SigningKey)
        } else {
            Err(CryptoError::ConversionError)
        }
    }
}

/// A signature on an object of type `T`, encrypted under the ECDSA signature
/// scheme.
#[allow(unused)]
#[derive(Debug, Clone)]
struct Signature<T> {
    original_type: PhantomData<T>,
}

impl Encrypted<SigningKey> {
    /// Decrypt a signing key. This should be run as part of the subprotocol to
    /// retrieve an encrypted signing key from the server.
    ///
    /// This must be run by the client.
    pub fn decrypt_secret(self, storage_key: StorageKey) -> Result<SigningKey, LockKeeperError> {
        let decrypted = self.decrypt(&storage_key.0)?;
        Ok(decrypted)
    }
}

impl StorageKey {
    /// Create and encrypt a new signing key. This is part of the local signing
    /// key generation flow.
    ///
    /// This must be run by the client. It takes the following steps:
    /// 1. Generates a new signing key
    /// 2. Encrypt it under the [`StorageKey`], using an AEAD scheme
    pub fn create_and_encrypt_signing_key(
        self,
        rng: &mut (impl CryptoRng + RngCore),
        _user_id: &UserId,
        _key_id: &KeyId,
    ) -> Result<(SigningKey, Encrypted<SigningKey>), LockKeeperError> {
        let context = AssociatedData::new();

        Ok((
            SigningKey,
            Encrypted::encrypt(rng, &self.0, SigningKey, &context)?,
        ))
    }
}

#[cfg(test)]
mod test {
    use crate::{
        crypto::{CryptoError, KeyId, SigningKey, StorageKey},
        user::UserId,
        LockKeeperError,
    };

    #[test]
    fn signing_key_to_vec_u8_conversion_works_and_is_trivial() -> Result<(), CryptoError> {
        for _ in 0..1000 {
            // Trivial - the serializiation doesn't include anything beyond the domain
            // separator.
            let vec: Vec<u8> = SigningKey.into();
            assert_eq!(vec.len(), SigningKey::domain_separator().len());

            // Works - you get the same nothing back.
            let output_key = vec.try_into()?;
            assert_eq!(SigningKey, output_key);
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
        let (signing_key, encrypted_signing_key) = storage_key
            .clone()
            .create_and_encrypt_signing_key(&mut rng, &user_id, &key_id)?;

        // Decrypt the secret
        let decrypted_signing_key = encrypted_signing_key.decrypt_secret(storage_key)?;
        assert_eq!(decrypted_signing_key, signing_key);

        Ok(())
    }
}
