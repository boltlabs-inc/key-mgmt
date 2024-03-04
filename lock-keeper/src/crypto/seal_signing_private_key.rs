use aes_gcm_siv::{aead::Aead, AeadCore, Aes256GcmSiv, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::{sharding::SealKey, CryptoError, SigningPrivateKey};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedAttestationPrivateKey {
    encrypted: Vec<u8>,
    nonce: Nonce,
}

impl EncryptedAttestationPrivateKey {
    pub fn seal(
        seal_key: &SealKey,
        attestation_private_key: &SigningPrivateKey,
    ) -> Result<Self, CryptoError> {
        let nonce: Nonce = Aes256GcmSiv::generate_nonce(&mut OsRng);
        let cipher = Aes256GcmSiv::new(seal_key.as_ref());
        let encrypted = cipher
            .encrypt(&nonce, attestation_private_key.as_bytes().as_slice())
            .map_err(|_err| CryptoError::EncryptionFailed)?;
        Ok(Self { encrypted, nonce })
    }

    pub fn decrypt(self, seal_key: &SealKey) -> Result<SigningPrivateKey, CryptoError> {
        let cipher = Aes256GcmSiv::new(seal_key.as_ref());
        let mut decrypted = cipher
            .decrypt(&self.nonce, self.encrypted.as_slice())
            .map_err(|_err| CryptoError::DecryptionFailed)?;
        let signing_private_key = SigningPrivateKey::from_bytes(&decrypted)
            .map_err(|_err| CryptoError::ConversionError)?;
        decrypted.zeroize();
        Ok(signing_private_key)
    }

    pub fn into_base64(self) -> Result<String, CryptoError> {
        let serialized = bincode::serialize(&self)?;
        Ok(general_purpose::STANDARD.encode(serialized))
    }

    pub fn from_base64(attestation_key_string: &str) -> Result<Self, CryptoError> {
        let decoded: Vec<u8> = general_purpose::STANDARD.decode(attestation_key_string)?;
        Ok(bincode::deserialize(&decoded)?)
    }

    pub fn set_nonce(&mut self, new_nonce: Nonce) {
        self.nonce = new_nonce;
    }
}
