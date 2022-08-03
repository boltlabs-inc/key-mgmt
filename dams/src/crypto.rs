use bytes::BytesMut;
use serde::{Deserialize, Serialize};

use crate::{keys::KeyId, user::UserId};

/// Export key is secure key material produced as client output from OPAQUE.
///
/// This uses standardized naming, but is _not_ directly used as an encryption
/// key in this system. Instead, it is used to derive a `MasterKey`.
///
/// Implementation note: this is a wrapper around `opaque_ke`'s `export_key`
/// field in the
/// [ClientRegistrationFinishResult](opaque_ke::ClientRegistrationFinishResult)
/// and corresponding registration result.
#[allow(unused)]
#[derive(Debug)]
pub struct ExportKey;

impl ExportKey {
    /// Derive a [`MasterKey`] from the export key.
    pub fn derive_master_key(&self) -> MasterKey {
        todo!()
    }
}

/// The master key is a default-length symmetric key for (TODO #107: encryption
/// scheme). It is used to securely encrypt a user's [`StorageKey`].
#[allow(unused)]
#[derive(Debug)]
pub struct MasterKey;

#[allow(unused)]
impl MasterKey {
    /// Encrypt the given [`StorageKey`] under an AEAD scheme (TODO #107:
    /// describe).
    ///
    /// TODO: Define encrypted storage key return type.
    pub fn encrypt_storage_key(self, storage_key: StorageKey) {
        todo!()
    }
}

/// A storage key is used to encrypt stored data. It is derived by and only
/// known to a client.
///
/// A storage key is a default-length symmetric key for (TODO #107: encryption
/// scheme).
#[allow(unused)]
#[derive(Debug)]
pub struct StorageKey;

#[allow(unused)]
impl StorageKey {
    /// Generate a new 32-byte [`StorageKey`].
    pub fn generate() -> Self {
        todo!()
    }

    /// Encrypt the given [`KeyMaterial`] under an AEAD scheme (TODO #107:
    /// describe).
    ///
    /// TODO: Define encrypted storage key return type.
    pub fn encrypt_data(self, secret: &Secret) {}
}

/// An arbitrary secret.
///
/// This is generated by and known only to the client.
#[derive(Debug, Deserialize, Serialize)]
pub struct Secret {
    material: BytesMut,
    len: u32,
    context: Context,
}

#[allow(unused)]
impl Secret {
    /// Generate a new secret of length `len`.
    pub fn generate(len: u32) -> Self {
        todo!()
    }
}

/// Context and application specific information used in various cryptographic
/// protocols. This enum lists the specific contexts that arise throughout the
/// system.
///
/// Context is used in key derivation and authenticated encryption with
/// associated data.
#[allow(unused)]
#[derive(Debug, Serialize, Deserialize)]
enum Context {
    /// Opaque-derived Lock Keeper master key.
    MasterKey,
    /// Context for a secret stored by the specified under the given [`KeyId`].
    OwnedSecret(UserId, KeyId),
}
