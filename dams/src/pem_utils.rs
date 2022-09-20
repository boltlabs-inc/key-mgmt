use std::path::Path;

use rustls::{Certificate, PrivateKey};

use crate::DamsError;

/// Returns all certificates in the pemfile at the given path
pub fn read_certificates(path: impl AsRef<Path>) -> Result<Vec<Certificate>, DamsError> {
    let fd = std::fs::File::open(path.as_ref())?;
    let mut buf = std::io::BufReader::new(&fd);
    let certs = rustls_pemfile::certs(&mut buf)?
        .into_iter()
        .map(Certificate)
        .collect();

    Ok(certs)
}

/// Returns the first private key found in the pemfile at the given path
pub fn read_private_key(path: impl AsRef<Path>) -> Result<PrivateKey, DamsError> {
    let fd = std::fs::File::open(path.as_ref())?;
    let mut buf = std::io::BufReader::new(&fd);
    let key = rustls_pemfile::pkcs8_private_keys(&mut buf)?
        .into_iter()
        .next()
        .map(PrivateKey)
        .ok_or(DamsError::InvalidPrivateKey)?;

    Ok(key)
}
