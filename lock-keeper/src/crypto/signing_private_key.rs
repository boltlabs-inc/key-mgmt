use crate::crypto::{CryptoError, Signature, SigningPublicKey};
use k256::{
    ecdsa,
    ecdsa::{recoverable, signature::hazmat::PrehashSigner},
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

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

impl RecoverableSignature {
    pub fn new(signature: Signature, recovery_id: recoverable::Id) -> Self {
        RecoverableSignature {
            signature,
            recovery_id: u8::from(recovery_id),
        }
    }

    pub fn recover_verifying_key_prehash(
        &self,
        hashed: impl AsRef<[u8]>,
    ) -> Result<SigningPublicKey, CryptoError> {
        let recovery_id = recoverable::Id::new(self.recovery_id)?;
        let signature = recoverable::Signature::new(&self.signature.0, recovery_id)?;

        let pk = signature
            .recover_verifying_key_from_digest_bytes(hashed.as_ref().into())
            .map_err(CryptoError::Signature)?;
        Ok(SigningPublicKey(pk))
    }
    /// Turn this `[RecoverableSignature]` to a standard (non-recoverable)
    /// `[Signature]`.
    pub fn to_standard(&self) -> &Signature {
        &self.signature
    }

    /// Get `r` component of signature.
    pub fn r(&self) -> [u8; 32] {
        self.signature.0.split_bytes().0.into()
    }

    /// Get `s` component of signature.
    pub fn s(&self) -> [u8; 32] {
        self.signature.0.split_bytes().1.into()
    }

    /// Get `v` (recovery ID) component of signature.
    pub fn v(&self) -> u8 {
        self.recovery_id
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SigningPrivateKey(ecdsa::SigningKey);

impl SigningPrivateKey {
    // TODO: What format are these bytes expected in?
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(ecdsa::SigningKey::from_bytes(bytes).unwrap())
    }

    // TODO: What format are these bytes in?
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().as_slice().to_vec()
    }

    /// Generate a new `[SigningPrivateKey]`
    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self(ecdsa::SigningKey::random(rng))
    }

    /// Retrieve the public portion of the key.
    pub fn public_key(&self) -> SigningPublicKey {
        SigningPublicKey(self.0.verifying_key())
    }

    /// Sign a pre-hashed message returning a `[Signature]`
    pub fn sign_prehash(&self, hashed: impl AsRef<[u8]>) -> Result<Signature, CryptoError> {
        let signature = self
            .0
            .sign_prehash(hashed.as_ref())
            .map_err(CryptoError::Signature)?;
        Ok(Signature(signature))
    }

    /// Sign a pre-hashed message returning a `[RecoverableSignature]`
    pub fn sign_prehash_recoverable(
        &self,
        hashed: impl AsRef<[u8]>,
    ) -> Result<RecoverableSignature, CryptoError> {
        let signature: recoverable::Signature = self
            .0
            .sign_prehash(hashed.as_ref())
            .map_err(CryptoError::Signature)?;

        // Convert `recoverable::Signature` into regular `Signature`.
        // Saving the recovery ID for use later.
        let signature = RecoverableSignature {
            signature: Signature(ecdsa::Signature::from(signature)),
            recovery_id: u8::from(signature.recovery_id()),
        };
        Ok(signature)
    }

    pub fn to_k256_signing_key(self) -> ecdsa::SigningKey {
        self.0
    }
}

#[cfg(test)]
mod test {
    use crate::crypto::signing_private_key::SigningPrivateKey;
    use rand::rngs::OsRng;
    use sha3::Digest;

    /// Hash bytes using sha3 keccak256.
    fn keccak256<B: AsRef<[u8]>>(bytes: B) -> Vec<u8> {
        let mut hasher = sha3::Keccak256::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }

    #[test]
    fn signing_and_verification_works() -> anyhow::Result<()> {
        let hashed = keccak256("Hello World!");
        let key = SigningPrivateKey::generate(&mut OsRng);
        let signature = key.sign_prehash(&hashed)?;
        key.public_key().verify_prehash(hashed, &signature)?;

        Ok(())
    }

    #[test]
    fn wrong_hash_does_not_verify() -> anyhow::Result<()> {
        let hashed = keccak256("Hello World!");
        let key = SigningPrivateKey::generate(&mut OsRng);
        let signature = key.sign_prehash(&hashed)?;

        let hashed2 = keccak256("Goodbye World!");
        assert!(
            key.public_key()
                .verify_prehash(hashed2, &signature)
                .is_err(),
            "Should not verify"
        );

        Ok(())
    }

    #[test]
    fn signing_and_verification_works_recoverable_sig() -> anyhow::Result<()> {
        let hashed = keccak256("Hello World!");
        let key = SigningPrivateKey::generate(&mut OsRng);
        let signature = key.sign_prehash_recoverable(&hashed)?;

        let recovered_public_key = signature.recover_verifying_key_prehash(&hashed)?;
        recovered_public_key.verify_prehash(hashed, &signature.to_standard())?;

        Ok(())
    }

    #[test]
    fn verification_wrong_hash_does_verify_recoverable_sig() -> anyhow::Result<()> {
        let hashed = keccak256("Hello World!");

        let key = SigningPrivateKey::generate(&mut OsRng);
        let signature = key.sign_prehash_recoverable(&hashed)?;

        let hashed2 = keccak256("Goodbye World!");
        let recovered_public_key = signature.recover_verifying_key_prehash(&hashed2)?;

        let result = recovered_public_key.verify_prehash(hashed, &signature.to_standard());
        assert!(result.is_err(), "Should not verify");

        Ok(())
    }
}
