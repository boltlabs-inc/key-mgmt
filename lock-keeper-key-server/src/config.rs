use lock_keeper::{
    config::opaque::OpaqueCipherSuite, crypto::ServerSideEncryptionKey, infrastructure::pem_utils,
};
use opaque_ke::{keypair::PrivateKey, Ristretto255, ServerSetup};
use rand::{rngs::StdRng, SeedableRng};
use rustls::{
    server::{AllowAnyAuthenticatedClient, NoClientAuth},
    RootCertStore, ServerConfig,
};
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use crate::{server::opaque_storage::create_or_retrieve_server_key_opaque, LockKeeperServerError};

/// Server configuration with all fields ready to use
#[derive(Clone)]
pub struct Config {
    pub address: IpAddr,
    pub port: u16,
    pub session_timeout: Duration,
    pub tls_config: Option<ServerConfig>,
    pub opaque_server_setup: ServerSetup<OpaqueCipherSuite, PrivateKey<Ristretto255>>,
    pub server_side_encryption_key: ServerSideEncryptionKey,
    pub database: DatabaseSpec,
    pub logging: LoggingConfig,
}

impl Config {
    pub fn from_file(
        config_path: impl AsRef<Path>,
        private_key_bytes: Option<Vec<u8>>,
        server_side_encryption_key_bytes: Option<Vec<u8>>,
    ) -> Result<Self, LockKeeperServerError> {
        let config_string = std::fs::read_to_string(&config_path)?;
        let config_file = ConfigFile::from_str(&config_string)?;
        Self::from_config_file(
            config_file,
            private_key_bytes,
            server_side_encryption_key_bytes,
        )
    }

    pub fn from_config_file(
        config: ConfigFile,
        private_key_bytes: Option<Vec<u8>>,
        server_side_encryption_key_bytes: Option<Vec<u8>>,
    ) -> Result<Self, LockKeeperServerError> {
        let mut rng = StdRng::from_entropy();

        let tls_config = config
            .tls_config
            .map(|tc| tc.into_rustls_config(private_key_bytes))
            .transpose()?;

        Ok(Self {
            address: config.address,
            port: config.port,
            session_timeout: config.session_timeout,
            tls_config,
            server_side_encryption_key: config
                .server_side_encryption_key_config(server_side_encryption_key_bytes)?,
            opaque_server_setup: create_or_retrieve_server_key_opaque(
                &mut rng,
                config.opaque_server_key,
            )?,
            database: config.database,
            logging: config.logging,
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
            .field("database", &self.database)
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
    #[serde(with = "humantime_serde")]
    pub session_timeout: Duration,
    /// The server side encryption key can be provided as a file or passed to
    /// the [`Config`] constructors.
    pub server_side_encryption_key: Option<PathBuf>,
    pub opaque_path: PathBuf,
    pub opaque_server_key: PathBuf,
    pub database: DatabaseSpec,
    pub logging: LoggingConfig,
    pub tls_config: Option<TlsConfig>,
}

impl FromStr for ConfigFile {
    type Err = LockKeeperServerError;

    fn from_str(config_string: &str) -> Result<Self, Self::Err> {
        Ok(toml::from_str(config_string)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct LoggingConfig {
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

    pub fn server_side_encryption_key_config(
        &self,
        server_side_encryption_key_bytes: Option<Vec<u8>>,
    ) -> Result<ServerSideEncryptionKey, LockKeeperServerError> {
        let key = if let Some(bytes) = server_side_encryption_key_bytes {
            ServerSideEncryptionKey::from_bytes(&bytes)?
        } else if let Some(key_path) = &self.server_side_encryption_key {
            ServerSideEncryptionKey::read_from_file(key_path)?
        } else {
            return Err(LockKeeperServerError::ServerSideEncryptionKeyMissing);
        };

        Ok(key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct DatabaseSpec {
    pub mongodb_uri: String,
    pub db_name: String,
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
            session_timeout = "60s"
            opaque_path = "tests/gen/opaque"
            opaque_server_key = "tests/gen/opaque/server_setup"

            [tls_config]
            private_key = "test.key"
            server_side_encryption_key = "test_sse.key"
            certificate_chain = "test.crt"
            client_auth = false

            [database]
            mongodb_uri = "mongodb://localhost:27017"
            db_name = "lock-keeper-test-db"

            [logging]
            lock_keeper_logs_file_name = "./dev/logs/server.log"
            all_logs_file_name = "./dev/logs/all.log"
        "#;

        // Destructure so the test breaks when fields are added
        let ConfigFile {
            address,
            port,
            session_timeout,
            server_side_encryption_key,
            tls_config,
            opaque_path,
            opaque_server_key,
            database:
                DatabaseSpec {
                    mongodb_uri,
                    db_name,
                },
            logging,
        } = ConfigFile::from_str(config_str).unwrap();

        let tls_config = tls_config.unwrap();

        assert_eq!(mongodb_uri, "mongodb://localhost:27017");
        assert_eq!(db_name, "lock-keeper-test-db");
        assert_eq!(address, IpAddr::from_str("127.0.0.2").unwrap());
        assert_eq!(port, 1114);
        assert_eq!(session_timeout, Duration::from_secs(60));
        assert_eq!(
            server_side_encryption_key,
            Some(PathBuf::from("test_sse.key"))
        );
        assert_eq!(tls_config.private_key, Some(PathBuf::from("test.key")));
        assert_eq!(tls_config.certificate_chain, PathBuf::from("test.crt"));
        assert!(!tls_config.client_auth);
        assert_eq!(opaque_path, PathBuf::from("tests/gen/opaque"));
        assert_eq!(
            opaque_server_key,
            PathBuf::from("tests/gen/opaque/server_setup")
        );
        let expected_log = LoggingConfig {
            lock_keeper_logs_file_name: "./dev/logs/server.log".parse().unwrap(),
            all_logs_file_name: "./dev/logs/all.log".parse().unwrap(),
        };
        assert_eq!(logging, expected_log);
    }
}
