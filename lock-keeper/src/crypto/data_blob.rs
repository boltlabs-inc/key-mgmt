//! This module defines `[DataBlob]`: A blob of bytes for storing in the server.
//! As well as accompanying functionality for server-side encrypting and
//! decrypting `[DataBlob]s`.

use crate::{
    crypto::{generic, generic::AssociatedData, CryptoError, Encrypted, KeyId, RemoteStorageKey},
    types::database::account::UserId,
    LockKeeperError,
};
use serde::{Deserialize, Serialize};
use tracing::{error, instrument};
use zeroize::ZeroizeOnDrop;

/// A blob of bytes for storing in the server.
///
/// The server will encrypt this data before storing it and will decrypt it when
/// client retrieves this data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct DataBlob(pub(super) generic::Secret);

impl DataBlob {
    /// Unique identifier used to generate `[DataBlob]'s` `[AssociatedData]`.
    const GENERATION_TYPE: &'static str = "data blob";

    /// Create a new `[DataBlob]` from the given data. The `user_id` and
    /// `key_id` are used to create the `[DataBlob]'s` `[AssociatedData]`
    /// (used for encryption/decryption).
    pub fn create(
        data: Vec<u8>,
        user_id: &UserId,
        key_id: &KeyId,
    ) -> Result<Self, LockKeeperError> {
        let context = AssociatedData::new()
            .with_bytes(user_id.clone())
            .with_bytes(key_id.clone())
            .with_str(Self::GENERATION_TYPE);

        Ok(DataBlob(generic::Secret::from_parts(data, context)))
    }

    /// Move actual data associated with this blob.
    pub fn blob_data(self) -> Vec<u8> {
        self.0.borrow_material().to_vec()
    }

    /// Domain separator for use in serializing data blobs.
    fn domain_separator() -> &'static str {
        "data blob"
    }

    pub(super) fn context(&self) -> &AssociatedData {
        self.0.context()
    }
}

/// This implementation is required to use the `[Encrypted::encrypt]` function.
impl TryFrom<DataBlob> for Vec<u8> {
    type Error = CryptoError;

    fn try_from(secret: DataBlob) -> Result<Self, Self::Error> {
        // Serialize bytes using domain separator + serialized generic secret.
        let mut bytes = Vec::new();
        bytes.append(&mut DataBlob::domain_separator().into());
        bytes.append(&mut secret.0.to_owned().try_into()?);
        Ok(bytes)
    }
}

/// This implementation is required to use the `[Encrypted::encrypt]` function.
impl TryFrom<Vec<u8>> for DataBlob {
    type Error = CryptoError;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        // Check domain separator and strip it.
        let expected_ds: Vec<u8> = DataBlob::domain_separator().into();

        // Check length before splitting.
        if expected_ds.len() > value.len() {
            return Err(CryptoError::ConversionError);
        }
        // It is now safe to call split_at.
        let (actual_ds, secret) = value.split_at(expected_ds.len());
        if expected_ds != actual_ds {
            error!("Incorrect domain separator found: {:?}", actual_ds);
            return Err(CryptoError::ConversionError);
        }
        Ok(DataBlob(secret.to_vec().try_into()?))
    }
}

impl Encrypted<DataBlob> {
    /// Decrypt data blob server-side.
    #[instrument(skip_all, err(Debug))]
    pub fn decrypt_data_blob(
        self,
        remote_storage_key: &RemoteStorageKey,
    ) -> Result<DataBlob, LockKeeperError> {
        let decrypted = self.decrypt_inner(&remote_storage_key.0)?;
        Ok(decrypted)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        crypto::{CryptoError, DataBlob, KeyId, RemoteStorageKey},
        types::database::account::UserId,
        LockKeeperError,
    };
    use rand::Rng;

    #[test]
    fn encrypt_decrypt_data_blob() -> Result<(), LockKeeperError> {
        let mut rng = rand::thread_rng();
        // Produce random values to encrypt and decrypt.
        let data: Vec<u8> = std::iter::repeat_with(|| rng.gen()).take(512).collect();

        let uid = UserId::new(&mut rng)?;
        let key_id = KeyId::generate(&mut rng, &uid)?;
        let blob = DataBlob::create(data, &uid, &key_id)?;
        let key = RemoteStorageKey::generate(&mut rng);

        let encrypted = key.encrypt_data_blob(&mut rng, blob.clone())?;
        let decrypted = encrypted.decrypt_data_blob(&key)?;
        assert_eq!(decrypted, blob);
        Ok(())
    }

    /// If the blob length is above our current u16 max size, the blob fails
    /// during conversion.
    #[test]
    fn too_large_blob_fails_to_encode() -> Result<(), LockKeeperError> {
        let mut rng = rand::thread_rng();
        // Produce random values to encrypt and decrypt.
        let too_large = u16::MAX as usize + 1;
        let data: Vec<u8> = std::iter::repeat_with(|| rng.gen())
            .take(too_large)
            .collect();

        let uid = UserId::new(&mut rng)?;
        let key_id = KeyId::generate(&mut rng, &uid)?;
        let blob = DataBlob::create(data, &uid, &key_id)?;
        let key = RemoteStorageKey::generate(&mut rng);

        let decrypt = key.encrypt_data_blob(&mut rng, blob);
        assert!(matches!(
            decrypt,
            Err(LockKeeperError::Crypto(CryptoError::CannotEncodeDataLength))
        ));

        Ok(())
    }
}
