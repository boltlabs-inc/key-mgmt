use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr, time::Duration,
};
use tracing::Level;

use crate::BlobServerError;

/// Server configuration with all fields ready to use
#[derive(Clone, Debug)]
pub struct Config {
    pub address: IpAddr,
    pub port: u16,
    pub logging: LoggingConfig,
    pub database: DatabaseConfig,
    /// Maximum size allowed for the store sever-encrypted blob endpoint.
    /// This size  bounded by types lengths that can be represented as a u16.
    pub max_blob_size: u16,
}

impl Config {
    pub fn from_file(config_path: impl AsRef<Path>, db_username: Option<String>, db_password: Option<String>) -> Result<Self, BlobServerError> {
        let config_string = std::fs::read_to_string(&config_path)
            .map_err(|e| BlobServerError::FileIo(e, config_path.as_ref().to_path_buf()))?;
        let config_file = ConfigFile::from_str(&config_string)?;
        Self::from_config_file(config_file, db_username, db_password)
    }

    pub fn from_config_file(mut config_file: ConfigFile, db_username: Option<String>, db_password: Option<String>) -> Result<Self, BlobServerError> {
        if let Some(username) = db_username {
            config_file.database.username = Some(username);
        }
        if let Some(password) = db_password {
            config_file.database.password = Some(password);
        }

        Ok(Self {
            address: config_file.address,
            port: config_file.port,
            logging: config_file.logging,
            database: config_file.database.try_into()?,
            max_blob_size: config_file.max_blob_size,
        })
    }
}

/// Server configuration file format.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[non_exhaustive]
pub struct ConfigFile {
    pub address: IpAddr,
    pub port: u16,
    pub logging: LoggingConfig,
    pub database: DatabaseConfigFile,
    pub max_blob_size: u16,
}

impl FromStr for ConfigFile {
    type Err = BlobServerError;

    fn from_str(config_string: &str) -> Result<Self, Self::Err> {
        Ok(toml::from_str(config_string)?)
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
    pub blob_server_logs_file_name: PathBuf,
    pub all_logs_file_name: PathBuf,
}

#[derive(Clone)]
pub struct DatabaseConfig {
    pub username: String,
    pub password: String,
    pub address: String,

    /// Name of database. Appended to URI to make the full path.
    pub db_name: String,
    pub max_connections: u32,
    pub connection_retries: u32,
    pub connection_retry_delay: Duration,
    pub connection_timeout: Duration,
}

impl DatabaseConfig {
    pub const DB_USERNAME: &'static str = "DB_USERNAME";
    pub const DB_PASSWORD: &'static str = "DB_PASSWORD";

    /// Generate full URI for our database based on the config in the form of:
    /// postgres://username:password@address/db_name.
    pub fn uri(&self) -> String {
        format!(
            "postgres://{}:{}@{}/{}",
            self.username, self.password, self.address, self.db_name
        )
    }
}

impl std::fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("username", &"REDACTED")
            .field("password", &"REDACTED")
            .field("address", &self.address)
            .field("db_name", &self.db_name)
            .field("max_connections", &self.max_connections)
            .field("connection_retries", &self.connection_retries)
            .field("connection_retry_delay", &self.connection_retry_delay)
            .field("connection_timeout", &self.connection_timeout)
            .finish()
    }
}

impl TryFrom<DatabaseConfigFile> for DatabaseConfig {
    type Error = BlobServerError;

    fn try_from(config: DatabaseConfigFile) -> Result<Self, Self::Error> {
        let config = DatabaseConfig {
            username: config.username.ok_or(BlobServerError::invalid_config("Missing username"))?,
            password: config.password.ok_or(BlobServerError::invalid_config("Missing password"))?,
            address: config.address,
            db_name: config.db_name,
            max_connections: config.max_connections,
            connection_retries: config.connection_retries,
            connection_retry_delay: config.connection_retry_delay,
            connection_timeout: config.connection_timeout,
        };

        Ok(config)
    }
}

#[derive(Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct DatabaseConfigFile {
    /// Optional, convenience field for specifying the username. Should only be
    /// used for development!
    pub username: Option<String>,
    /// Optional, convenience field for specifying the password. Should only be
    /// used for development!
    pub password: Option<String>,
    pub address: String,
    pub db_name: String,
    pub max_connections: u32,
    pub connection_retries: u32,
    #[serde(with = "humantime_serde")]
    pub connection_retry_delay: Duration,
    #[serde(with = "humantime_serde")]
    pub connection_timeout: Duration,
}

impl DatabaseConfigFile {
    pub fn from_file(config_path: impl AsRef<Path>) -> Result<Self, BlobServerError> {
        let config_string = std::fs::read_to_string(&config_path).map_err(|e| {
            BlobServerError::invalid_config(format!("{e}; path: {:?}", config_path.as_ref()))
        })?;
        Self::from_str(&config_string)
    }
}

impl std::fmt::Debug for DatabaseConfigFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("username", if self.username.is_some() { &"REDACTED" } else { &"None" })
            .field("password", if self.password.is_some() { &"REDACTED" } else { &"None" })
            .field("address", &self.address)
            .field("db_name", &self.db_name)
            .field("max_connections", &self.max_connections)
            .field("connection_retries", &self.connection_retries)
            .field("connection_retry_delay", &self.connection_retry_delay)
            .field("connection_timeout", &self.connection_timeout)
            .finish()
    }
}

impl FromStr for DatabaseConfigFile {
    type Err = BlobServerError;

    fn from_str(config_string: &str) -> Result<Self, Self::Err> {
        Ok(toml::from_str(config_string)?)
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
            max_blob_size = 1024

            [logging]
            stdout_log_level = "INFO"

            [logging.log_files]
            blob_server_logs_file_name = "./dev/logs/blob-server.log"
            all_logs_file_name = "./dev/logs/blob-all.log"

            [database]
            username = 'test'
            password = 'test_password'
            address = 'postgres:5432'
            db_name = 'test'
            max_connections = 5
            connection_retries = 5
            connection_retry_delay = "5s"
            connection_timeout = "3s"            
        "#;

        // Destructure so the test breaks when fields are added
        let ConfigFile {
            address,
            port,
            logging,
            database,
            max_blob_size,
        } = ConfigFile::from_str(config_str).unwrap();

        assert_eq!(address, IpAddr::from_str("127.0.0.2").unwrap());
        assert_eq!(port, 1114);
        assert_eq!(max_blob_size, 1024);

        let expected_logging_config = LoggingConfig {
            stdout_log_level: Level::INFO,
            log_files: Some(LoggingFileConfig {
                blob_server_logs_file_name: "./dev/logs/blob-server.log".parse().unwrap(),
                all_logs_file_name: "./dev/logs/blob-all.log".parse().unwrap(),
            }),
        };
        assert_eq!(logging, expected_logging_config);

        let expected_database_config = DatabaseConfigFile {
            username: Some("test".to_string()),
            password: Some("test_password".to_string()),
            address: "postgres:5432".to_string(),
            db_name: "test".to_string(),
            max_connections: 5,
            connection_retries: 5,
            connection_retry_delay: Duration::from_secs(5),
            connection_timeout: Duration::from_secs(3),
        };
        assert_eq!(database, expected_database_config);
    }
}
