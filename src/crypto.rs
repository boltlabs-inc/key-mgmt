//! This module will contain cryptographic tools used in the digital asset management service.
//! It defines a representation of asymmetric keys and secret shares of those keys.
//!
//! Eventually, it will define cryptographic operations using these key pairs, including
//! multi-party computations (and any necessary intermediate types). It might abstract over
//! keys for different schemes.

/// Cryptographic public key corresponding to a [`PrivateKey`].
#[derive(Debug)]
pub struct PublicKey;

/// Cryptographic private key corresponding to a [`PublicKey`].
#[derive(Debug)]
struct PrivateKey;

#[allow(unused)]
impl PrivateKey {
    /// Transforms a private key into a set of independent shares, such that no
    /// information about the original [`PrivateKey`] can be derived from an individual
    /// [`PrivateKeyShare`].
    fn share(self) -> Vec<PrivateKeyShare> {
        todo!()
    }
}

/// Secret share of a [`PrivateKey`].
#[derive(Debug)]
struct PrivateKeyShare;

/// Asymmetric key pair used for cryptographic operations.
#[derive(Debug)]
#[allow(unused)]
pub struct KeyPair {
    public_key: PublicKey,
    private_key: PrivateKey,
}

#[allow(unused)]
impl KeyPair {
    /// Retrieve the public part of the key pair.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Transforms a key pair into a set of independent shares, such that no
    /// information about the original [`PrivateKey`] embedded in the [`KeyPair`] can
    /// be derived from an individual [`KeyPairShare`].
    fn share(self) -> Vec<KeyPairShare> {
        todo!()
    }
}

/// Secret share of a [`KeyPair`].
#[derive(Debug)]
#[allow(unused)]
pub struct KeyPairShare {
    public_key: PublicKey,
    private_key: PrivateKeyShare,
}
