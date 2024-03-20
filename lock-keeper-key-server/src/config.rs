use lock_keeper::{
    config::opaque::OpaqueCipherSuite, crypto::RemoteStorageKey, infrastructure::pem_utils,
};
use opaque_ke::{keypair::PrivateKey, Ristretto255, ServerSetup};
use rand::{rngs::StdRng, SeedableRng};
use rustls::{
    server::{AllowAnyAuthenticatedClient, NoClientAuth},
    RootCertStore, ServerConfig,
};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
};
use tracing::Level;

use crate::{
    server::opaque_storage::create_or_retrieve_server_setup_opaque, LockKeeperServerError,
};

/// Server configuration with all fields ready to use
#[derive(Clone)]
pub struct Config {
    pub address: IpAddr,
    pub port: u16,
    pub tls_config: Option<ServerConfig>,
    pub opaque_server_setup: ServerSetup<OpaqueCipherSuite, PrivateKey<Ristretto255>>,
    pub remote_storage_key: RemoteStorageKey,
    pub logging: LoggingConfig,
    pub release_toml_path: PathBuf,
    /// Maximum size allowed for the store sever-encrypted blob endpoint.
    /// This size  bounded by types lengths that can be represented as a u16.
    pub max_blob_size: u16,
}

impl Config {
    pub const OPAQUE_SERVER_SETUP: &'static str = "OPAQUE_SERVER_SETUP";

    pub fn from_file(
        config_path: impl AsRef<Path>,
        private_key_bytes: Option<Vec<u8>>,
        remote_storage_key_bytes: Option<Vec<u8>>,
        opaque_server_setup_bytes: Option<Vec<u8>>,
    ) -> Result<Self, LockKeeperServerError> {
        let config_string = std::fs::read_to_string(&config_path)
            .map_err(|e| LockKeeperServerError::FileIo(e, config_path.as_ref().to_path_buf()))?;
        let config_file = ConfigFile::from_str(&config_string)?;
        Self::from_config_file(
            config_file,
            private_key_bytes,
            remote_storage_key_bytes,
            opaque_server_setup_bytes,
        )
    }

    pub fn from_config_file(
        config: ConfigFile,
        private_key_bytes: Option<Vec<u8>>,
        remote_storage_key_bytes: Option<Vec<u8>>,
        opaque_server_setup_bytes: Option<Vec<u8>>,
    ) -> Result<Self, LockKeeperServerError> {
        let mut rng = StdRng::from_entropy();

        let remote_storage_key = config.remote_storage_key_config(remote_storage_key_bytes)?;
        let tls_config = config
            .tls_config
            .map(|tc| tc.into_rustls_config(private_key_bytes))
            .transpose()?;

        let opaque_server_setup = create_or_retrieve_server_setup_opaque(
            &mut rng,
            config.opaque_server_key,
            opaque_server_setup_bytes,
        )?;

        Ok(Self {
            remote_storage_key,
            address: config.address,
            port: config.port,
            tls_config,
            opaque_server_setup,
            logging: config.logging,
            release_toml_path: config.release_toml_path,
            max_blob_size: config.max_blob_size,
        })
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("address", &self.address)
            .field("port", &self.port)
            .field("tls_config", &"[Does not implement Debug]")
            .field("opaque_server_setup", &self.opaque_server_setup)
            .finish()
    }
}

/// Server configuration file format.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[non_exhaustive]
pub struct ConfigFile {
    pub address: IpAddr,
    pub port: u16,
    /// The remote storage key can be provided as a file or passed to
    /// the [`Config`] constructors.
    pub remote_storage_key: Option<PathBuf>,
    pub opaque_path: PathBuf,
    pub opaque_server_key: Option<PathBuf>,
    pub logging: LoggingConfig,
    pub release_toml_path: PathBuf,
    pub tls_config: Option<TlsConfig>,
    pub max_blob_size: u16,
}

impl FromStr for ConfigFile {
    type Err = LockKeeperServerError;

    fn from_str(config_string: &str) -> Result<Self, Self::Err> {
        Ok(toml::from_str(config_string)?)
    }
}

impl ConfigFile {
    pub fn remote_storage_key_config(
        &self,
        remote_storage_key_bytes: Option<Vec<u8>>,
    ) -> Result<RemoteStorageKey, LockKeeperServerError> {
        let key = if let Some(bytes) = remote_storage_key_bytes {
            RemoteStorageKey::from_bytes(&bytes)?
        } else if let Some(key_path) = &self.remote_storage_key {
            RemoteStorageKey::read_from_file(key_path)?
        } else {
            return Err(LockKeeperServerError::RemoteStorageKeyMissing);
        };

        Ok(key)
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct LoggingConfig {
    #[serde_as(as = "DisplayFromStr")]
    pub stdout_log_level: Level,
    pub log_files: Option<LoggingFileConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct LoggingFileConfig {
    pub lock_keeper_logs_file_name: PathBuf,
    pub all_logs_file_name: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// The private key can be provided as a file or passed to the
    /// [`Config`] constructors.
    pub private_key: Option<PathBuf>,
    pub certificate_chain: PathBuf,
    #[serde(default)]
    pub client_auth: bool,
}

impl TlsConfig {
    pub fn into_rustls_config(
        &self,
        private_key_bytes: Option<Vec<u8>>,
    ) -> Result<ServerConfig, LockKeeperServerError> {
        let chain = pem_utils::read_certificates(&self.certificate_chain)?;

        let key = if let Some(bytes) = private_key_bytes {
            pem_utils::read_private_key_from_bytes(&bytes)?
        } else if let Some(key_path) = &self.private_key {
            pem_utils::read_private_key_from_file(key_path)?
        } else {
            return Err(LockKeeperServerError::PrivateKeyMissing);
        };

        let client_auth = if self.client_auth {
            let mut client_auth_roots = RootCertStore::empty();
            for root in &chain {
                client_auth_roots.add(root)?;
            }

            AllowAnyAuthenticatedClient::new(client_auth_roots)
        } else {
            NoClientAuth::new()
        };

        let mut tls = ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(client_auth)
            .with_single_cert(chain, key)?;
        tls.alpn_protocols = vec![b"h2".to_vec()];

        Ok(tls)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn config_from_str() {
        let config_str = r#"
            address = "127.0.0.2"
            port = 1114
            opaque_path = "tests/gen/opaque"
            opaque_server_key = "tests/gen/opaque/server_setup"
            remote_storage_key = "test_sse.key"
            release_toml_path = "./boltlabs-release.toml
            max_blob_size = 1024

            [tls_config]
            private_key = "test.key"
            certificate_chain = "test.crt"
            client_auth = false

            [logging]
            stdout_log_level = "INFO"

            [logging.log_files]
            lock_keeper_logs_file_name = "./dev/logs/server.log"
            all_logs_file_name = "./dev/logs/all.log"
        "#;

        // Destructure so the test breaks when fields are added
        let ConfigFile {
            address,
            port,
            remote_storage_key,
            tls_config,
            opaque_path,
            opaque_server_key,
            logging,
            release_toml_path,
            max_blob_size,
        } = ConfigFile::from_str(config_str).unwrap();

        let tls_config = tls_config.unwrap();

        assert_eq!(address, IpAddr::from_str("127.0.0.2").unwrap());
        assert_eq!(port, 1114);
        assert_eq!(remote_storage_key, Some(PathBuf::from("test_sse.key")));
        assert_eq!(release_toml_path, PathBuf::from("./boltlabs-release.toml"));
        assert_eq!(tls_config.private_key, Some(PathBuf::from("test.key")));
        assert_eq!(tls_config.certificate_chain, PathBuf::from("test.crt"));
        assert!(!tls_config.client_auth);
        assert_eq!(opaque_path, PathBuf::from("tests/gen/opaque"));
        assert_eq!(
            opaque_server_key.unwrap(),
            PathBuf::from("tests/gen/opaque/server_setup")
        );
        assert_eq!(max_blob_size, 1024);
        let expected_log = LoggingConfig {
            stdout_log_level: Level::INFO,
            log_files: Some(LoggingFileConfig {
                lock_keeper_logs_file_name: "./dev/logs/server.log".parse().unwrap(),
                all_logs_file_name: "./dev/logs/all.log".parse().unwrap(),
            }),
        };
        assert_eq!(logging, expected_log);
    }
}
