//! Convenience functions for dealing with PEM files.

use std::path::Path;

use rustls::{Certificate, PrivateKey};

use crate::LockKeeperError;

/// Returns all certificates in the pemfile at the given path
pub fn read_certificates(path: impl AsRef<Path>) -> Result<Vec<Certificate>, LockKeeperError> {
    let fd = std::fs::File::open(path.as_ref())
        .map_err(|e| LockKeeperError::FileIo(e, path.as_ref().to_path_buf()))?;
    let mut buf = std::io::BufReader::new(&fd);
    let certs = rustls_pemfile::certs(&mut buf)?
        .into_iter()
        .map(Certificate)
        .collect();

    Ok(certs)
}

/// Returns the first private key found in the pemfile at the given path
pub fn read_private_key_from_file(path: impl AsRef<Path>) -> Result<PrivateKey, LockKeeperError> {
    let bytes = std::fs::read(&path)
        .map_err(|e| LockKeeperError::FileIo(e, path.as_ref().to_path_buf()))?;
    read_private_key_from_bytes(&bytes)
}

/// Returns the first private key found in the given bytes
pub fn read_private_key_from_bytes(bytes: &[u8]) -> Result<PrivateKey, LockKeeperError> {
    let mut buf = std::io::BufReader::new(bytes);
    let key = rustls_pemfile::pkcs8_private_keys(&mut buf)?
        .into_iter()
        .next()
        .map(PrivateKey)
        .ok_or(LockKeeperError::InvalidPrivateKey)?;

    Ok(key)
}
