use lock_keeper::infrastructure::pem_utils;
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};
use tonic::transport::Uri;

use crate::LockKeeperClientError;

/// Client configuration with all fields ready to use.
#[derive(Clone)]
pub struct Config {
    pub server_uri: Uri,
    pub tls_config: ClientConfig,
}

impl Config {
    pub fn from_file(
        config_path: impl AsRef<Path>,
        private_key_bytes: Option<Vec<u8>>,
    ) -> Result<Self, LockKeeperClientError> {
        let config_string = std::fs::read_to_string(&config_path)?;
        let config_file = ConfigFile::from_str(&config_string)?;
        Self::from_config_file(config_file, private_key_bytes)
    }

    pub fn from_config_file(
        config: ConfigFile,
        private_key_bytes: Option<Vec<u8>>,
    ) -> Result<Self, LockKeeperClientError> {
        Ok(Self {
            server_uri: Uri::from_str(&config.server_uri)?,
            tls_config: config.tls_config(private_key_bytes)?,
        })
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("server_uri", &self.server_uri)
            .field("tls_config", &"[Does not implement Debug]")
            .finish()
    }
}

/// Client configuration file format.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[non_exhaustive]
pub struct ConfigFile {
    pub server_uri: String,
    pub ca_chain: PathBuf,
    pub client_auth: Option<ClientAuth>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[non_exhaustive]
pub struct ClientAuth {
    pub certificate_chain: PathBuf,
    /// The private key can be provided as a file or passed to the
    /// [`Config`] constructors.
    pub private_key: Option<PathBuf>,
}

impl ConfigFile {
    pub fn tls_config(
        &self,
        private_key_bytes: Option<Vec<u8>>,
    ) -> Result<ClientConfig, LockKeeperClientError> {
        let mut root_store = RootCertStore::empty();

        let root_cert = pem_utils::read_certificates(&self.ca_chain)?;
        for cert in root_cert {
            root_store.add(&cert)?;
        }

        let base_tls_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store);

        let tls_config = if let Some(auth) = &self.client_auth {
            let certs = pem_utils::read_certificates(&auth.certificate_chain)?;

            let key = if let Some(bytes) = private_key_bytes {
                pem_utils::read_private_key_from_bytes(&bytes)?
            } else if let Some(key_path) = &auth.private_key {
                pem_utils::read_private_key_from_file(key_path)?
            } else {
                return Err(LockKeeperClientError::PrivateKeyMissing);
            };

            base_tls_config.with_single_cert(certs, key)?
        } else {
            base_tls_config.with_no_client_auth()
        };

        Ok(tls_config)
    }
}

impl FromStr for ConfigFile {
    type Err = LockKeeperClientError;

    fn from_str(config_string: &str) -> Result<Self, Self::Err> {
        Ok(toml::from_str(config_string)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_str() {
        let config_str = r#"
        server_uri = "https://localhost:1113"
        ca_chain = "signing-ca.chain"
        
        [client_auth]
        certificate_chain = "client.chain"
        private_key = "client.key"        
        "#;

        // Destructure so the test breaks when fields are added
        let ConfigFile {
            server_uri,
            ca_chain,
            client_auth,
        } = ConfigFile::from_str(config_str).unwrap();

        let client_auth = client_auth.unwrap();

        assert_eq!(server_uri, "https://localhost:1113");
        assert_eq!(ca_chain, PathBuf::from("signing-ca.chain"));
        assert_eq!(client_auth.private_key, Some(PathBuf::from("client.key")));
        assert_eq!(client_auth.certificate_chain, PathBuf::from("client.chain"));
    }
}
