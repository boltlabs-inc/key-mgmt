use crate::{user::UserId, LockKeeperError};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

use crate::crypto::{
    generic::{self, AssociatedData, CryptoError},
    Encrypted, KeyId, StorageKey,
};

use super::Storable;

/// An arbitrary secret.
///
/// This is generated by the client and should never be revealed to the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Secret(pub(super) generic::Secret);

impl From<Secret> for Vec<u8> {
    fn from(secret: Secret) -> Self {
        secret.0.into()
    }
}

impl TryFrom<Vec<u8>> for Secret {
    type Error = CryptoError;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Secret(value.try_into()?))
    }
}

impl Encrypted<Secret> {
    /// Decrypt a secret. This should be run as part of the subprotocol to
    /// retrieve a secret from the server.
    ///
    /// This must be run by the client.
    pub fn decrypt_secret(self, storage_key: StorageKey) -> Result<Secret, LockKeeperError> {
        let decrypted = self.decrypt(&storage_key.0)?;
        Ok(decrypted)
    }
}

impl Storable for Secret {
    fn create_and_encrypt(
        rng: &mut (impl CryptoRng + RngCore),
        storage_key: &StorageKey,
        user_id: &UserId,
        key_id: &KeyId,
    ) -> Result<(Secret, Encrypted<Secret>), LockKeeperError> {
        let context = AssociatedData::new()
            .with_bytes(user_id.clone())
            .with_bytes(key_id.clone())
            .with_str("client-generated");
        let secret = Secret(generic::Secret::generate(rng, 32, context.clone()));

        Ok((
            secret.clone(),
            Encrypted::encrypt(rng, &storage_key.0, secret, &context)?,
        ))
    }

    fn remote_generate(
        rng: &mut (impl CryptoRng + RngCore),
        user_id: &UserId,
        key_id: &KeyId,
    ) -> Self {
        let context = AssociatedData::new()
            .with_bytes(user_id.clone())
            .with_bytes(key_id.clone())
            .with_str("server-generated");

        Secret(generic::Secret::generate(rng, 32, context))
    }
}

#[cfg(test)]
mod test {
    use crate::{
        crypto::{KeyId, Secret, Storable, StorageKey},
        user::UserId,
        LockKeeperError,
    };

    #[test]
    fn secret_to_vec_u8_conversion_works() -> Result<(), LockKeeperError> {
        let mut rng = rand::thread_rng();
        let storage_key = StorageKey::generate(&mut rng);
        let user_id = UserId::new(&mut rng)?;

        for _ in 0..100 {
            let key_id = KeyId::generate(&mut rng, &user_id)?;
            let (secret, _) =
                Secret::create_and_encrypt(&mut rng, &storage_key, &user_id, &key_id)?;

            // Convert to Vec<u8> and back
            let secret_vec: Vec<u8> = secret.clone().into();
            let output_secret: Secret = secret_vec.try_into()?;

            assert_eq!(secret, output_secret);
        }

        Ok(())
    }

    #[test]
    fn secret_encryption_works() -> Result<(), LockKeeperError> {
        let mut rng = rand::thread_rng();
        let storage_key = StorageKey::generate(&mut rng);

        let user_id = UserId::new(&mut rng)?;
        let key_id = KeyId::generate(&mut rng, &user_id)?;

        // Create and encrypt a secret
        let (secret, encrypted_secret) =
            Secret::create_and_encrypt(&mut rng, &storage_key, &user_id, &key_id)?;

        // Decrypt the secret
        let decrypted_secret = encrypted_secret.decrypt_secret(storage_key)?;
        assert_eq!(decrypted_secret, secret);

        Ok(())
    }
}
