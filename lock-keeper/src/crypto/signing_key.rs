use crate::{
    crypto::{
        generic::EncryptionKey,
        signing_key::generation_types::{CLIENT_GENERATED, IMPORTED, SERVER_GENERATED},
        RemoteStorageKey,
    },
    types::database::account::UserId,
    LockKeeperError,
};
use k256::ecdsa::{
    self,
    signature::{hazmat::PrehashVerifier, Signer, Verifier},
    VerifyingKey,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tracing::error;
use zeroize::ZeroizeOnDrop;

use super::{generic::AssociatedData, CryptoError, Encrypted, Export, KeyId, StorageKey};

/// Provides the methods necessary to sign and verify a piece of data with a
/// [`SigningKeyPair`]. This trait should be explicitly implemented on types
/// that are intended to be signed.
///
/// It requires `AsRef<[u8]>` so that we can accept `impl Signable` in the
/// public client API but send `SignableBytes` over the network. This
/// requirement may be removed in the future.
pub trait Signable: AsRef<[u8]> {
    fn sign(&self, signing_key: &SigningKeyPair) -> Signature;
    fn verify(
        &self,
        public_key: &SigningPublicKey,
        signature: &Signature,
    ) -> Result<(), CryptoError>;
}

/// Wrapper used to declare arbitrary bytes as [`Signable`].
///
/// [`SignableBytes`] is used to send bytes across the network in a format that
/// is easy to work with during serialization and deserialization.
///
/// NOTE: This type is only meant to be used in message types and should not be
/// exposed by the client API.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignableBytes(pub Vec<u8>);

impl AsRef<[u8]> for SignableBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Signable for SignableBytes {
    fn sign(&self, signing_key_pair: &SigningKeyPair) -> Signature {
        Signature(signing_key_pair.signing_key.sign(&self.0))
    }

    fn verify(
        &self,
        public_key: &SigningPublicKey,
        signature: &Signature,
    ) -> Result<(), CryptoError> {
        public_key.verify(&self.0, signature)
    }
}

pub mod generation_types {
    pub const SERVER_GENERATED: &str = "server-generated";
    pub const CLIENT_GENERATED: &str = "client-generated";
    pub const IMPORTED: &str = "imported key";
}

/// An ECDSA signing key pair, including a public component for verifying
/// signatures, a private component for creating them, and context about the key
/// pair.
///
/// This can be generated locally by the client or remotely by the server.
#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct SigningKeyPair {
    signing_key: ecdsa::SigningKey,
    #[zeroize(skip)]
    context: AssociatedData,
}

impl SigningKeyPair {
    /// Create a new `SigningKeyPair` with the given associated data.
    fn generate(rng: &mut (impl CryptoRng + RngCore), context: &AssociatedData) -> Self {
        Self {
            signing_key: ecdsa::SigningKey::random(rng),
            context: context.clone(),
        }
    }

    /// Domain separator for use in serializing signing keypairs.
    fn domain_separator() -> &'static str {
        "ECDSA signing key pair over curve secp256k1"
    }

    /// Retrieve the public portion of the key.
    pub fn public_key(&self) -> SigningPublicKey {
        SigningPublicKey(self.signing_key.verifying_key())
    }

    /// Retrieve the context associated with the signing key.
    pub(super) fn context(&self) -> &AssociatedData {
        &self.context
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
            .with_str(SERVER_GENERATED);
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
            .with_str(IMPORTED);

        let signing_key = Self {
            signing_key: ecdsa::SigningKey::from_bytes(key_material)
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
            .with_str(CLIENT_GENERATED);
        let signing_key = SigningKeyPair::generate(rng, &context);

        Ok((
            signing_key.clone(),
            Encrypted::encrypt(rng, &storage_key.0, signing_key, &context)?,
        ))
    }
}

/// The public component of an ECDSA signing key.
#[allow(unused)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningPublicKey(pub VerifyingKey);

impl SigningPublicKey {
    /// Verify a `Signature` using this public key. This function will hash the
    /// message using ??? TODO.
    pub fn verify(
        &self,
        message: impl AsRef<[u8]>,
        signature: &Signature,
    ) -> Result<(), CryptoError> {
        self.0.verify(message.as_ref(), &signature.0).map_err(|e| {
            error!("{e}");
            CryptoError::VerificationFailed
        })
    }

    /// Verify a `Signature` using this public key. This function expects `hash`
    /// to be an already hashed message.
    pub fn verify_prehash(
        &self,
        hash: impl AsRef<[u8]>,
        signature: &Signature,
    ) -> Result<(), CryptoError> {
        self.0
            .verify_prehash(hash.as_ref(), &signature.0)
            .map_err(|e| {
                error!("{e}");
                CryptoError::VerificationFailed
            })
    }

    // Construct a [`SigningPublicKey`] from a PEM-encoded string.
    //
    // Keys in this format begin with the following delimiter:
    // -----BEGIN PUBLIC KEY-----
    pub fn from_pem(pem: &str) -> Result<Self, CryptoError> {
        let key = VerifyingKey::from_str(pem).map_err(|e| {
            error!("{e}");
            CryptoError::ConversionError
        })?;

        Ok(Self(key))
    }
}

impl Encrypted<SigningKeyPair> {
    /// Decrypt a signing key. This should be run as part of the subprotocol to
    /// retrieve an encrypted signing key from the server.
    ///
    /// This must be run by the client.
    pub fn decrypt_signing_key(
        self,
        storage_key: StorageKey,
        user_id: UserId,
        key_id: KeyId,
    ) -> Result<SigningKeyPair, LockKeeperError> {
        self.decrypt(
            &storage_key.0,
            user_id,
            key_id,
            vec![IMPORTED, CLIENT_GENERATED],
        )
    }

    /// Decrypt a signing key. This should be run by the server as part of the
    /// subprotocol to retrieve a signing key from the server.
    pub fn decrypt_signing_key_by_server(
        self,
        remote_storage_key: &RemoteStorageKey,
        user_id: UserId,
        key_id: KeyId,
    ) -> Result<SigningKeyPair, LockKeeperError> {
        self.decrypt(
            &remote_storage_key.0,
            user_id,
            key_id,
            vec![IMPORTED, SERVER_GENERATED],
        )
    }

    fn decrypt(
        self,
        encryption_key: &EncryptionKey,
        user_id: UserId,
        key_id: KeyId,
        possible_context_strings: Vec<&str>,
    ) -> Result<SigningKeyPair, LockKeeperError> {
        let identifying_context = AssociatedData::new().with_bytes(user_id).with_bytes(key_id);

        if possible_context_strings
            .iter()
            .map(|context| identifying_context.clone().with_str(context))
            .any(|x| x == self.associated_data)
        {
            Ok(self.decrypt_inner(encryption_key)?)
        } else {
            Err(CryptoError::DecryptionFailed.into())
        }
    }
}

/// Raw material for an imported signing key.
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Import {
    key_material: Vec<u8>,
}

impl TryFrom<&[u8]> for Import {
    type Error = LockKeeperError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        // Check if these bytes are correctly formatted to make a signing key,
        // but don't actually use the key.
        let _signing_key =
            ecdsa::SigningKey::from_bytes(bytes).map_err(|_| CryptoError::ConversionError)?;

        Ok(Self {
            key_material: bytes.into(),
        })
    }
}

impl Import {
    /// Create a new [`Import`] around the bytes representing signing key
    /// material. Bytes are validated for appropriate format.
    pub fn new(bytes: Vec<u8>) -> Result<Self, LockKeeperError> {
        let import = Self::try_from(bytes.as_slice())?;
        Ok(import)
    }

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
            .with_str(IMPORTED);

        let signing_key = ecdsa::SigningKey::from_bytes(&self.key_material)
            .map_err(|_| CryptoError::ConversionError)?;

        Ok(SigningKeyPair {
            signing_key,
            context,
        })
    }
}

impl From<SigningKeyPair> for Export {
    fn from(key_pair: SigningKeyPair) -> Self {
        Self {
            key_material: key_pair.signing_key.to_bytes().to_vec(),
            context: key_pair.context.to_owned().into(),
        }
    }
}

impl Export {
    /// Convert `Export` into a [`SigningKeyPair`].
    pub fn into_signing_key(self) -> Result<SigningKeyPair, LockKeeperError> {
        let signing_key = ecdsa::SigningKey::from_bytes(self.key_material.as_slice())
            .map_err(|_| CryptoError::ConversionError)?;
        let context = self.context.to_owned().try_into()?;
        Ok(SigningKeyPair {
            signing_key,
            context,
        })
    }
}

impl TryFrom<SigningKeyPair> for Vec<u8> {
    type Error = CryptoError;

    fn try_from(key_pair: SigningKeyPair) -> Result<Self, Self::Error> {
        let domain_separator_bytes: Vec<u8> = SigningKeyPair::domain_separator().into();
        let signing_key = key_pair.signing_key.to_bytes();
        let sk_length =
            u8::try_from(signing_key.len()).map_err(|_| CryptoError::CannotEncodeDataLength)?;
        let context = Vec::<u8>::from(key_pair.context.to_owned());

        let bytes = domain_separator_bytes
            .into_iter()
            .chain(std::iter::once(sk_length))
            .chain(signing_key)
            .chain(context)
            .collect();
        Ok(bytes)
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
        let signing_key = ecdsa::SigningKey::from_bytes(signing_key_bytes)
            .map_err(|_| CryptoError::ConversionError)?;

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

/// A signature on an object encrypted under the ECDSA signature scheme.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(pub(super) ecdsa::Signature);

impl Signature {
    /// Serialize this signature as ASN.1 DER.
    pub fn to_der(&self) -> Vec<u8> {
        self.0.to_der().as_bytes().to_vec()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;

    use super::Signature;
    use crate::{
        crypto::{generic::AssociatedData, CryptoError, KeyId, Signable, StorageKey},
        types::database::account::UserId,
        LockKeeperError,
    };
    use k256::{ecdsa, schnorr::signature::Signature as EcdsaSignature};

    /* Public and private key pairs used for testing. These keys were generated
       as follows using the `openssl` command line utility:
       # Generate `secp256k1` private key
       > openssl ecparam -genkey -out test.pem -name secp256k1 -noout
       # Derive  public key from private key.
       > openssl ec -in test.pem -pubout -out test_public.pem
       # Get private key in PKCS#8-encoded pem format.
       > openssl pkcs8 -topk8 -nocrypt -in test.pem -out test_p8.pem
    */
    const PUBLIC_KEY: &'static str = r#"
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEEfw/MOmtobnF36IKi6WcN/sSbP2nrdSE
3bKZV9X0j+bukH19wqtyp+JC6OiKY5E8LQn5bWM7ihBy2+0Tl0mHVQ==
-----END PUBLIC KEY-----
"#;

    const PRIVATE_KEY: &'static str = r#"
-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg5X2FE2dAPaL6hD6hAN93
6Gd61wZkW5i00WrrIQVt9P2hRANCAAQR/D8w6a2hucXfogqLpZw3+xJs/aet1ITd
splX1fSP5u6QfX3Cq3Kn4kLo6IpjkTwtCfltYzuKEHLb7ROXSYdV
-----END PRIVATE KEY-----
"#;

    // Ensure we can read a public key in the expected format.
    #[test]
    fn public_key_from_pem_works() {
        let _ = SigningPublicKey::from_pem(PUBLIC_KEY).unwrap();
    }

    // Ensure a public key we read in can be used to verify bytes signed by the
    // corresponding private key.
    #[test]
    fn public_key_from_pem_can_verify() {
        let public_key = SigningPublicKey::from_pem(PUBLIC_KEY).unwrap();
        let signing_key = ecdsa::SigningKey::from_str(PRIVATE_KEY).unwrap();

        let message = "hello world!".as_bytes();
        let signature = Signature(signing_key.sign(&message));

        public_key.verify(&message, &signature).unwrap();
    }

    #[test]
    fn signing_keys_conversion_works() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let signing_key = ecdsa::SigningKey::random(&mut rng);
            let bytes = signing_key.to_bytes();
            let output_key = ecdsa::SigningKey::from_bytes(&bytes).unwrap();
            assert_eq!(signing_key, output_key);

            let byte_vec: Vec<u8> = signing_key.to_bytes().into_iter().collect();
            let output_key = ecdsa::SigningKey::from_bytes(&byte_vec).unwrap();
            assert_eq!(signing_key, output_key);
        }
    }

    #[test]
    fn signing_key_to_vec_u8_conversion_works() -> Result<(), CryptoError> {
        let mut rng = rand::thread_rng();
        for i in 0_i32..1000 {
            let context = AssociatedData::new().with_bytes(i.to_le_bytes());
            let key = SigningKeyPair::generate(&mut rng, &context);
            let vec: Vec<u8> = key.clone().try_into()?;

            let output_key = vec.try_into()?;
            assert_eq!(key, output_key);
        }
        Ok(())
    }

    /// Checks some should-fail permutations of context for client-generated and
    /// imported keys (encrypted under a storage key).
    fn check_context(
        mut encrypted_key: Encrypted<SigningKeyPair>,
        expected_extra_context: &'static str,
        user_id: UserId,
        key_id: KeyId,
        storage_key: StorageKey,
    ) -> Result<(), LockKeeperError> {
        let mut rng = rand::thread_rng();

        // Normal decryption works
        assert!(encrypted_key
            .clone()
            .decrypt_signing_key(storage_key.clone(), user_id.clone(), key_id.clone())
            .is_ok());

        // User id must be correct
        let bad_user_id = UserId::new(&mut rng)?;
        let bad_user_context = AssociatedData::new()
            .with_bytes(bad_user_id)
            .with_bytes(key_id.clone())
            .with_str(expected_extra_context);
        encrypted_key.associated_data = bad_user_context;
        assert!(encrypted_key
            .clone()
            .decrypt_signing_key(storage_key.clone(), user_id.clone(), key_id.clone())
            .is_err());

        // Key id must be correct
        let bad_key_id = KeyId::generate(&mut rng, &user_id)?;
        let bad_key_context = AssociatedData::new()
            .with_bytes(user_id.clone())
            .with_bytes(bad_key_id)
            .with_str(expected_extra_context);
        encrypted_key.associated_data = bad_key_context;
        assert!(encrypted_key
            .clone()
            .decrypt_signing_key(storage_key.clone(), user_id.clone(), key_id.clone())
            .is_err());

        // Extra context must be correct
        let bad_extra_context = AssociatedData::new()
            .with_bytes(user_id.clone())
            .with_bytes(key_id.clone())
            .with_str(SERVER_GENERATED);
        encrypted_key.associated_data = bad_extra_context;
        assert!(encrypted_key
            .clone()
            .decrypt_signing_key(storage_key.clone(), user_id.clone(), key_id.clone())
            .is_err());

        // random extra context doesn't work
        let random_context = AssociatedData::new()
            .with_bytes(user_id.clone())
            .with_bytes(key_id.clone())
            .with_str(expected_extra_context)
            .with_str("here is some interesting context that will fail to decrypt our key!");
        encrypted_key.associated_data = random_context;
        assert!(encrypted_key
            .decrypt_signing_key(storage_key, user_id, key_id)
            .is_err());

        Ok(())
    }

    #[test]
    fn client_generated_signing_key_decryption_fails_with_bad_associated_data(
    ) -> Result<(), LockKeeperError> {
        let mut rng = rand::thread_rng();
        let storage_key = StorageKey::generate(&mut rng);

        let user_id = UserId::new(&mut rng)?;
        let key_id = KeyId::generate(&mut rng, &user_id)?;

        let (_, encrypted_client_key) =
            SigningKeyPair::create_and_encrypt(&mut rng, &storage_key, &user_id, &key_id)?;

        check_context(
            encrypted_client_key,
            CLIENT_GENERATED,
            user_id,
            key_id,
            storage_key,
        )
    }

    #[test]
    fn imported_signing_key_decryption_fails_with_bad_associated_data(
    ) -> Result<(), LockKeeperError> {
        let mut rng = rand::thread_rng();
        let storage_key = StorageKey::generate(&mut rng);

        let user_id = UserId::new(&mut rng)?;
        let key_id = KeyId::generate(&mut rng, &user_id)?;

        let key_material = ecdsa::SigningKey::random(rng.clone()).to_bytes().to_vec();
        let (_, encrypted_import_key) = SigningKeyPair::import_and_encrypt(
            &key_material,
            &mut rng,
            &storage_key,
            &user_id,
            &key_id,
        )?;
        check_context(encrypted_import_key, IMPORTED, user_id, key_id, storage_key)
    }

    #[test]
    fn import_conversion_works() -> Result<(), LockKeeperError> {
        let mut rng = rand::thread_rng();
        let user_id = UserId::new(&mut rng)?;
        let key_id = KeyId::generate(&mut rng, &user_id)?;

        let context = AssociatedData::new()
            .with_bytes(user_id.clone())
            .with_bytes(key_id.clone())
            .with_str(IMPORTED);

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
    fn signing_key_encryption_works() -> Result<(), LockKeeperError> {
        let mut rng = rand::thread_rng();
        let storage_key = StorageKey::generate(&mut rng);

        let user_id = UserId::new(&mut rng)?;
        let key_id = KeyId::generate(&mut rng, &user_id)?;

        // Create and encrypt a secret
        let (signing_key, encrypted_signing_key) =
            SigningKeyPair::create_and_encrypt(&mut rng, &storage_key, &user_id, &key_id)?;

        // Decrypt the secret
        let decrypted_signing_key =
            encrypted_signing_key.decrypt_signing_key(storage_key, user_id, key_id)?;
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
            .map(|len| -> Vec<u8> { std::iter::repeat_with(|| rng.gen()).take(len).collect() })
            .map(|msg| (msg.sign(&signing_key), msg))
            .all(|(sig, msg)| msg.verify(&public_key, &sig).is_ok()));
    }

    #[test]
    fn verifying_requires_correct_message() {
        let mut rng = rand::thread_rng();

        let signing_key = SigningKeyPair::generate(&mut rng, &AssociatedData::new());
        let public_key = signing_key.public_key();
        let message = b"signatures won't verify with a bad message".to_vec();
        let sig = message.sign(&signing_key);

        let bad_msg = b"this is obviously not the same message".to_vec();
        assert!(bad_msg.verify(&public_key, &sig).is_err());
        assert!(message.verify(&public_key, &sig).is_ok());
    }

    #[test]
    fn verifying_requires_correct_public_key() {
        let mut rng = rand::thread_rng();

        let signing_key = SigningKeyPair::generate(&mut rng, &AssociatedData::new());
        let message = b"signatures won't verify with a bad public key".to_vec();
        let sig = message.sign(&signing_key);

        let bad_key = SigningKeyPair::generate(&mut rng, &AssociatedData::new()).public_key();
        assert!(message.verify(&bad_key, &sig).is_err());
        assert!(message.verify(&signing_key.public_key(), &sig).is_ok());
    }

    #[test]
    fn signature_bits_cannot_be_flipped() {
        let mut rng = rand::thread_rng();

        let signing_key = SigningKeyPair::generate(&mut rng, &AssociatedData::new());
        let message = b"the signature on this message will get tweaked".to_vec();
        let sig = message.sign(&signing_key);
        let sig_bytes = sig.0.as_bytes();

        // try flipping some of the bits
        for i in 0..sig_bytes.len() {
            let mut tweaked = sig_bytes.to_vec();
            tweaked[i] ^= 1;

            // either the signature won't parse...
            let signature = match k256::ecdsa::Signature::from_bytes(&tweaked) {
                Ok(sig) => sig,
                Err(_) => continue,
            };
            let tweaked_sig = Signature(signature);

            // ...or the signature won't verify.
            assert!(message
                .verify(&signing_key.public_key(), &tweaked_sig)
                .is_err());
        }
        assert!(message.verify(&signing_key.public_key(), &sig).is_ok());
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
        let bytes: Vec<u8> = key_pair.try_into()?;
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

        let key_material = ecdsa::SigningKey::random(rng.clone()).to_bytes().to_vec();
        let (key, encrypted_key) = SigningKeyPair::import_and_encrypt(
            &key_material,
            &mut rng,
            &storage_key,
            &user_id,
            &key_id,
        )?;

        // Make sure encrypted key matches output key
        let decrypted_key = encrypted_key.decrypt_signing_key(storage_key, user_id, key_id)?;
        assert_eq!(key, decrypted_key);

        // Make sure key matches input key material (e.g. the secret material
        // appears somewhere within the serialization).
        let bytes: Vec<u8> = key.try_into()?;
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
        assert!(!contains_str(secret.clone(), IMPORTED));
        assert!(!contains_str(secret.clone(), SERVER_GENERATED));
        assert!(contains_str(secret, CLIENT_GENERATED));

        // Remote generate a key pair -- not imported.
        let secret = SigningKeyPair::remote_generate(&mut rng, &user_id, &key_id);
        assert!(!contains_str(secret.clone(), IMPORTED));
        assert!(!contains_str(secret.clone(), CLIENT_GENERATED));
        assert!(contains_str(secret, SERVER_GENERATED));

        // Use the local-import creation function
        let key_material = ecdsa::SigningKey::random(rng.clone()).to_bytes();
        let (imported_secret, _) = SigningKeyPair::import_and_encrypt(
            &key_material,
            &mut rng,
            &storage_key,
            &user_id,
            &key_id,
        )?;
        assert!(!contains_str(imported_secret.clone(), CLIENT_GENERATED));
        assert!(!contains_str(imported_secret.clone(), SERVER_GENERATED));
        assert!(contains_str(imported_secret, IMPORTED));

        // Use the remote-import creation function
        let import: Import = key_material.as_slice().try_into()?;
        let key_pair = import.into_signing_key(&user_id, &key_id)?;
        assert!(!contains_str(key_pair.clone(), CLIENT_GENERATED));
        assert!(!contains_str(key_pair.clone(), SERVER_GENERATED));
        assert!(contains_str(key_pair, IMPORTED));

        Ok(())
    }

    impl Signable for Vec<u8> {
        fn sign(&self, signing_key: &SigningKeyPair) -> Signature {
            (&self).sign(signing_key)
        }

        fn verify(
            &self,
            public_key: &SigningPublicKey,
            signature: &Signature,
        ) -> Result<(), CryptoError> {
            (&self).verify(public_key, signature)
        }
    }

    impl Signable for &Vec<u8> {
        fn sign(&self, signing_key: &SigningKeyPair) -> Signature {
            Signature(signing_key.signing_key.sign(self))
        }

        fn verify(
            &self,
            public_key: &SigningPublicKey,
            signature: &Signature,
        ) -> Result<(), CryptoError> {
            public_key
                .0
                .verify(self, &signature.0)
                .map_err(|_| CryptoError::VerificationFailed)
        }
    }
}
