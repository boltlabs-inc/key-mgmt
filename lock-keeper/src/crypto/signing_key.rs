use std::marker::PhantomData;

use super::CryptoError;

/// An ECDSA signing key.
///
/// This can be generated locally by the client or remotely by the server.
#[allow(unused)]
#[derive(Debug, Clone)]
struct SigningKey;

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
