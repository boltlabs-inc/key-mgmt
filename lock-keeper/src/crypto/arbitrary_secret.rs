use crate::{types::database::user::UserId, LockKeeperError};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    convert::TryFrom,
    fmt::{Display, Formatter},
};
use zeroize::ZeroizeOnDrop;

use crate::crypto::{
    generic::{self, AssociatedData, CryptoError},
    Encrypted, Export, KeyId, StorageKey,
};

/// An arbitrary secret.
///
/// This is generated by the client and should never be revealed to the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Secret(pub(super) generic::Secret);

impl From<Secret> for Vec<u8> {
    fn from(secret: Secret) -> Self {
        secret.0.to_owned().into()
    }
}

impl TryFrom<Vec<u8>> for Secret {
    type Error = CryptoError;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Secret(value.try_into()?))
    }
}

/// Allow secret to be displayed for demo purposes. Note we do not expose the
/// internal type representation of the secret.
impl Display for Secret {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0.get_material()))
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

impl Secret {
    /// Create and encrypt a new secret. This is part of the
    /// generate a new secret flow.
    ///
    /// This must be run by the client. It takes the following steps:
    /// 1. Generates a new secret
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
        let secret = Secret(generic::Secret::generate(rng, 32, context.clone()));

        Ok((
            secret.clone(),
            Encrypted::encrypt(rng, &storage_key.0, secret, &context)?,
        ))
    }

    /// Create a `Secret` from an imported key and encrypt it for
    /// storage at a server, under a key known only to the client.
    ///
    /// This is part of the local import with remote backup flow and must be run
    /// by the client.
    pub fn import_and_encrypt(
        secret_material: &[u8],
        rng: &mut (impl CryptoRng + RngCore),
        storage_key: &StorageKey,
        user_id: &UserId,
        key_id: &KeyId,
    ) -> Result<(Self, Encrypted<Self>), LockKeeperError> {
        let context = AssociatedData::new()
            .with_bytes(user_id.clone())
            .with_bytes(key_id.clone())
            .with_str("imported key");

        let secret = Secret(generic::Secret::from_parts(secret_material, &context));

        Ok((
            secret.clone(),
            Encrypted::encrypt(rng, &storage_key.0, secret, &context)?,
        ))
    }

    /// Retrieve the context for the secret.
    ///
    /// This is only used in testing right now, but it would be fine to make it
    /// public.
    fn context(&self) -> &AssociatedData {
        self.0.context()
    }
}

impl From<Secret> for Export {
    fn from(secret: Secret) -> Self {
        Self {
            key_material: secret.0.get_material().into(),
            context: secret.context().clone().into(),
        }
    }
}

impl TryFrom<Export> for Secret {
    type Error = LockKeeperError;

    fn try_from(export: Export) -> Result<Self, Self::Error> {
        let context = export.context.clone().try_into()?;
        let inner = generic::Secret::from_parts(&export.key_material, &context);
        Ok(Secret(inner))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;

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

    #[test]
    fn import_and_encrypt_encrypts_correct_key() -> Result<(), LockKeeperError> {
        let mut rng = rand::thread_rng();
        let storage_key = StorageKey::generate(&mut rng);

        let user_id = UserId::new(&mut rng)?;
        let key_id = KeyId::generate(&mut rng, &user_id)?;

        let secret_material: [u8; 32] = rng.gen();
        let (secret, encrypted_secret) = Secret::import_and_encrypt(
            &secret_material,
            &mut rng,
            &storage_key,
            &user_id,
            &key_id,
        )?;

        // Make sure encrypted secret matches secret
        let decrypted_secret = encrypted_secret.decrypt_secret(storage_key)?;
        assert_eq!(secret, decrypted_secret);

        // Make sure secret matches input secret material (e.g. the secret material
        // appears somewhere within the serialization).
        let bytes: Vec<u8> = secret.into();
        assert!(bytes.windows(32).any(|c| c == secret_material));

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
        let contains_str = |container: Secret, subset: &'static str| -> bool {
            let container_ad: Vec<u8> = container.context().to_owned().into();
            let subset: Vec<u8> = subset.as_bytes().into();
            container_ad.windows(subset.len()).any(|c| c == subset)
        };

        // Create and encrypt a secret -- not imported.
        let (secret, _) = Secret::create_and_encrypt(&mut rng, &storage_key, &user_id, &key_id)?;
        assert!(!contains_str(secret.clone(), "imported"));
        assert!(contains_str(secret, "client-generated"));

        // Use the local-import creation function
        let secret_material: [u8; 32] = rng.gen();
        let (imported_secret, _) = Secret::import_and_encrypt(
            &secret_material,
            &mut rng,
            &storage_key,
            &user_id,
            &key_id,
        )?;
        assert!(!contains_str(imported_secret.clone(), "client-generated"));
        assert!(contains_str(imported_secret, "imported"));

        Ok(())
    }
}
