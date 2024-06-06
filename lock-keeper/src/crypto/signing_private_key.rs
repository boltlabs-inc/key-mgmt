use crate::crypto::{CryptoError, Signature, SigningPublicKey};
use k256::{
    ecdsa,
    ecdsa::{signature::DigestSigner, RecoveryId, VerifyingKey},
    NonZeroScalar,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::Digest;
use std::str::FromStr;
use zeroize::ZeroizeOnDrop;

/// A recoverable signature.
///
/// We avoid using the `[ecdsa::recoverable::Signature]` type directly. It,
/// annoyingly, does not implement Serialize/Deserialize, so we represent our
/// `[RecoverableSignature]` as its individual components, which are
/// Serialize/Deserialize, so that we can derive these traits.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct RecoverableSignature {
    signature: Signature,
    recovery_id: u8,
}

impl From<ecdsa::Signature> for Signature {
    fn from(s: ecdsa::Signature) -> Self {
        Signature(s)
    }
}

/// Type representing signature broken into its constituent parts.
///
/// Useful for interoperability with other libraries.
pub struct RecoverableSignatureParts {
    /// Get `r` component of signature.
    pub r: [u8; 32],
    /// Get `s` component of signature.
    pub s: [u8; 32],
    /// `v` (recovery ID) component of signature.
    pub v: u8,
}

impl RecoverableSignature {
    pub fn new(signature: Signature, recovery_id: RecoveryId) -> Self {
        RecoverableSignature {
            signature,
            recovery_id: u8::from(recovery_id),
        }
    }

    /// Recover the public key from a message and this signature.
    ///
    /// WARNING: This function should only be used for testing code.
    pub fn recover_verifying_key(
        &self,
        message: impl AsRef<[u8]>,
    ) -> Result<SigningPublicKey, CryptoError> {
        let recovery_id = RecoveryId::try_from(self.recovery_id)?;
        let mut digest = sha3::Keccak256::new();
        digest.update(message);

        let pk = VerifyingKey::recover_from_digest(digest, &self.signature.0, recovery_id)?;
        Ok(SigningPublicKey::from(pk))
    }

    /// Turn this `[RecoverableSignature]` to a standard (non-recoverable)
    /// `[Signature]`.
    pub fn to_standard(&self) -> &Signature {
        &self.signature
    }

    pub fn into_parts(self) -> RecoverableSignatureParts {
        let (r, s) = self.signature.0.split_bytes();

        RecoverableSignatureParts {
            r: r.into(),
            s: s.into(),
            v: self.recovery_id,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, ZeroizeOnDrop)]
pub struct SigningPrivateKey(pub(super) ecdsa::SigningKey);

impl SigningPrivateKey {
    /// Create a `[SigningPrivateKey]` from the bytes emitted by a previous call
    /// to `[SigningPrivateKey::as_bytes]`
    pub fn from_bytes(key_material: &[u8]) -> Result<Self, CryptoError> {
        let key =
            ecdsa::SigningKey::try_from(key_material).map_err(|_| CryptoError::ConversionError)?;
        Ok(Self(key))
    }

    /// Return the `[SigningPrivateKey]` byte representation.
    ///
    /// Note: It is unclear exactly what the underlying byte representation is.
    /// This function should only be used with the accompanying
    /// `[SigningPrivateKey::from_bytes]` function.
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    /// Generate a new `[SigningPrivateKey]`
    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self(ecdsa::SigningKey::random(rng))
    }

    /// Retrieve the public portion of the key.
    pub fn public_key(&self) -> SigningPublicKey {
        SigningPublicKey::from(*self.0.verifying_key())
    }

    /// Sign a message returning a `[Signature]`. This function will hash the
    /// message using SHA3-256 (Keccak).
    pub fn sign(&self, message: impl AsRef<[u8]>) -> Signature {
        let digest = sha3::Keccak256::new_with_prefix(message);
        let signature = self.0.sign_digest(digest);
        Signature(signature)
    }

    /// Sign a message returning a `[RecoverableSignature]`. This function will
    /// hash the message using SHA3-256 (Keccak).
    pub fn sign_recoverable(
        &self,
        message: impl AsRef<[u8]>,
    ) -> Result<RecoverableSignature, CryptoError> {
        let digest = sha3::Keccak256::new_with_prefix(message);
        let (signature, recovery_id) = self.0.sign_digest_recoverable(digest)?;

        // Convert `recoverable::Signature` into regular `Signature`.
        Ok(RecoverableSignature::new(Signature(signature), recovery_id))
    }

    pub fn as_nonzero_scalar(&self) -> &NonZeroScalar {
        self.0.as_nonzero_scalar()
    }

    /// Deserialize PKCS#8-encoded private key from PEM.
    // Keys in this format begin with the following delimiter:
    // -----BEGIN PRIVATE KEY-----
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, CryptoError> {
        let key = ecdsa::SigningKey::from_str(pem)?;
        Ok(Self(key))
    }
}

#[cfg(test)]
mod test {
    use crate::crypto::signing_private_key::SigningPrivateKey;
    use rand::rngs::OsRng;

    #[test]
    fn from_pkcs8_pem_works() {
        const TEST_PRIVATE_KEY: &str = r#"
-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg5X2FE2dAPaL6hD6hAN93
6Gd61wZkW5i00WrrIQVt9P2hRANCAAQR/D8w6a2hucXfogqLpZw3+xJs/aet1ITd
splX1fSP5u6QfX3Cq3Kn4kLo6IpjkTwtCfltYzuKEHLb7ROXSYdV
-----END PRIVATE KEY-----
"#;
        assert!(
            SigningPrivateKey::from_pkcs8_pem(TEST_PRIVATE_KEY).is_ok(),
            "Failed to parse given private key."
        );
    }

    #[test]
    fn signing_and_verification_works() -> anyhow::Result<()> {
        let message = b"Hello World!";
        let key = SigningPrivateKey::generate(&mut OsRng);
        let signature = key.sign(message);
        key.public_key().verify(message, &signature)?;

        Ok(())
    }

    #[test]
    fn wrong_hash_does_not_verify() -> anyhow::Result<()> {
        let message = b"Hello World!";
        let message2 = b"Goodbye World!";

        let key = SigningPrivateKey::generate(&mut OsRng);
        let signature = key.sign(message);

        assert!(
            key.public_key().verify(message2, &signature).is_err(),
            "Should not verify"
        );

        Ok(())
    }

    #[test]
    fn signing_and_verification_works_recoverable_sig() -> anyhow::Result<()> {
        let message = b"Hello World!";
        let key = SigningPrivateKey::generate(&mut OsRng);
        let signature = key.sign_recoverable(message)?;

        let recovered_public_key = signature.recover_verifying_key(message)?;
        recovered_public_key.verify(message, signature.to_standard())?;

        Ok(())
    }

    #[test]
    fn verification_wrong_hash_does_verify_recoverable_sig() -> anyhow::Result<()> {
        let message = b"Hello World!";
        let message2 = b"Goodbye World!";

        let key = SigningPrivateKey::generate(&mut OsRng);
        let signature = key.sign_recoverable(message)?;

        let recovered_public_key = signature.recover_verifying_key(message2)?;

        let result = recovered_public_key.verify(message, signature.to_standard());
        assert!(result.is_err(), "Should not verify");

        Ok(())
    }
}
