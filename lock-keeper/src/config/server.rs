use rustls::ServerConfig;
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use crate::{defaults::server as defaults, error::LockKeeperError, pem_utils};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[non_exhaustive]
pub struct Config {
    #[serde(rename = "service")]
    pub services: Vec<Service>,
    pub database: DatabaseSpec,
}

impl Config {
    pub async fn load(config_path: impl AsRef<Path>) -> Result<Config, LockKeeperError> {
        let config_string = tokio::fs::read_to_string(&config_path).await?;
        let config = Self::from_str(&config_string)?;
        Ok(config)
    }
}

impl FromStr for Config {
    type Err = LockKeeperError;

    fn from_str(config_string: &str) -> Result<Self, Self::Err> {
        let config: Config = toml::from_str(config_string)?;
        Ok(config)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct DatabaseSpec {
    pub mongodb_uri: String,
    pub db_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[non_exhaustive]
pub struct Service {
    #[serde(default = "defaults::address")]
    pub address: IpAddr,
    #[serde(default = "defaults::port")]
    pub port: u16,
    #[serde(with = "humantime_serde", default)]
    pub connection_timeout: Option<Duration>,
    #[serde(default = "defaults::max_pending_connection_retries")]
    pub max_pending_connection_retries: usize,
    #[serde(with = "humantime_serde", default = "defaults::message_timeout")]
    pub message_timeout: Duration,
    #[serde(default = "defaults::max_message_length")]
    pub max_message_length: usize,
    pub private_key: PathBuf,
    pub certificate: PathBuf,
    pub opaque_path: PathBuf,
    pub opaque_server_key: PathBuf,
}

impl Service {
    pub fn tls_config(&self) -> Result<ServerConfig, LockKeeperError> {
        let certs = pem_utils::read_certificates(&self.certificate)?;
        let key = pem_utils::read_private_key(&self.private_key)?;

        let mut tls = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
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
            [[service]]
            address = "127.0.0.2"
            port = 1114
            connection_timeout = "20s"
            max_pending_connection_retries = 10
            message_timeout = "20s"
            max_message_length = 100
            private_key = "tests/gen/localhost.key"
            certificate = "tests/gen/localhost.crt"
            opaque_path = "tests/gen/opaque"
            opaque_server_key = "tests/gen/opaque/server_setup"

            [database]
            mongodb_uri = "mongodb://localhost:27017"
            db_name = "lock-keeper-test-db"
        "#;

        // Destructure so the test breaks when fields are added
        let Config {
            mut services,
            database:
                DatabaseSpec {
                    mongodb_uri,
                    db_name,
                },
        } = Config::from_str(config_str).unwrap();

        assert_eq!(mongodb_uri, "mongodb://localhost:27017");
        assert_eq!(db_name, "lock-keeper-test-db");

        let Service {
            address,
            port,
            connection_timeout,
            max_pending_connection_retries,
            message_timeout,
            max_message_length,
            private_key,
            certificate,
            opaque_path,
            opaque_server_key,
        } = services.pop().unwrap();

        assert_eq!(address, IpAddr::from_str("127.0.0.2").unwrap());
        assert_eq!(port, 1114);
        assert_eq!(connection_timeout, Some(Duration::from_secs(20)));
        assert_eq!(max_pending_connection_retries, 10);
        assert_eq!(message_timeout, Duration::from_secs(20));
        assert_eq!(max_message_length, 100);
        assert_eq!(private_key, PathBuf::from("tests/gen/localhost.key"));
        assert_eq!(certificate, PathBuf::from("tests/gen/localhost.crt"));
        assert_eq!(opaque_path, PathBuf::from("tests/gen/opaque"));
        assert_eq!(
            opaque_server_key,
            PathBuf::from("tests/gen/opaque/server_setup")
        );
    }

    #[test]
    fn config_defaults() {
        let config_str = r#"
            [[service]]
            private_key = "tests/gen/localhost.key"
            certificate = "tests/gen/localhost.crt"
            opaque_path = "tests/gen/opaque"
            opaque_server_key = "tests/gen/opaque/server_setup"

            [database]
            mongodb_uri = "mongodb://localhost:27017"
            db_name = "lock-keeper-test-db"
        "#;

        // Destructure so the test breaks when fields are added
        let Config {
            mut services,
            database:
                DatabaseSpec {
                    mongodb_uri,
                    db_name,
                },
        } = Config::from_str(config_str).unwrap();

        assert_eq!(mongodb_uri, "mongodb://localhost:27017");
        assert_eq!(db_name, "lock-keeper-test-db");

        let Service {
            address,
            port,
            connection_timeout,
            max_pending_connection_retries,
            message_timeout,
            max_message_length,
            private_key,
            certificate,
            opaque_path,
            opaque_server_key,
        } = services.pop().unwrap();

        assert_eq!(address, IpAddr::from_str("127.0.0.1").unwrap());
        assert_eq!(port, 1113);
        assert_eq!(connection_timeout, None);
        assert_eq!(max_pending_connection_retries, 4);
        assert_eq!(message_timeout, Duration::from_secs(60));
        assert_eq!(max_message_length, 1024 * 16);
        assert_eq!(private_key, PathBuf::from("tests/gen/localhost.key"));
        assert_eq!(certificate, PathBuf::from("tests/gen/localhost.crt"));
        assert_eq!(opaque_path, PathBuf::from("tests/gen/opaque"));
        assert_eq!(
            opaque_server_key,
            PathBuf::from("tests/gen/opaque/server_setup")
        );
    }
}