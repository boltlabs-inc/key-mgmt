use crate::error::ConfigError;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Formatter},
    fs::read_to_string,
    path::Path,
    str::FromStr,
    time::Duration,
};

#[derive(Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct ConfigFile {
    /// Optional, convenience field for specifying the username. Should only be
    /// used for development!
    pub username: Option<String>,
    /// Optional, convenience field for specifying the password. Should only be
    /// used for development!
    pub password: Option<String>,
    pub address: String,
    pub db_name: String,
    pub min_connections: u32,
    pub max_connections: u32,
    pub connection_retries: u32,
    #[serde(with = "humantime_serde")]
    pub connection_retry_delay: Duration,
    #[serde(with = "humantime_serde")]
    pub connection_timeout: Duration,
}

impl ConfigFile {
    pub fn from_file(config_path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let config_string = read_to_string(&config_path).map_err(|e| {
            ConfigError::ConfigFileReadFailure(e, config_path.as_ref().to_path_buf())
        })?;
        Self::from_str(&config_string)
    }
}

impl Debug for ConfigFile {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("username", &"REDACTED")
            .field("password", &"REDACTED")
            .field("address", &self.address)
            .field("db_name", &self.db_name)
            .field("min_connections", &self.min_connections)
            .field("max_connections", &self.max_connections)
            .field("connection_retries", &self.connection_retries)
            .field("connection_retry_delay", &self.connection_retry_delay)
            .field("connection_timeout", &self.connection_timeout)
            .finish()
    }
}

impl FromStr for ConfigFile {
    type Err = ConfigError;

    fn from_str(config_string: &str) -> Result<Self, Self::Err> {
        Ok(toml::from_str(config_string)?)
    }
}

pub struct Config {
    pub username: String,
    pub password: String,
    pub address: String,

    /// Name of database. Appended to URI to make the full path.
    pub db_name: String,
    pub min_connections: u32,
    pub max_connections: u32,
    pub connection_retries: u32,
    pub connection_retry_delay: Duration,
    pub connection_timeout: Duration,
}

impl Debug for Config {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("username", &"REDACTED")
            .field("password", &"REDACTED")
            .field("address", &self.address)
            .field("db_name", &self.db_name)
            .field("min_connections", &self.min_connections)
            .field("max_connections", &self.max_connections)
            .field("connection_retries", &self.connection_retries)
            .field("connection_retry_delay", &self.connection_retry_delay)
            .field("connection_timeout", &self.connection_timeout)
            .finish()
    }
}

impl Config {
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

impl TryFrom<ConfigFile> for Config {
    type Error = ConfigError;

    fn try_from(config: ConfigFile) -> Result<Self, Self::Error> {
        let config = Config {
            username: config.username.ok_or(ConfigError::MissingUsername)?,
            password: config.password.ok_or(ConfigError::MissingPassword)?,
            address: config.address,
            db_name: config.db_name,
            min_connections: config.min_connections,
            max_connections: config.max_connections,
            connection_retries: config.connection_retries,
            connection_retry_delay: config.connection_retry_delay,
            connection_timeout: config.connection_timeout,
        };

        Ok(config)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Helper method for creating a test [ConfigFile]
    fn test_config_file() -> ConfigFile {
        ConfigFile {
            username: Some("test_user".to_string()),
            password: Some("test_password".to_string()),
            address: "localhost".to_string(),
            db_name: "test_db".to_string(),
            min_connections: 2,
            max_connections: 5,
            connection_retries: 5,
            connection_retry_delay: Duration::from_secs(5),
            connection_timeout: Duration::from_secs(3),
        }
    }

    #[test]
    fn from_string() {
        let config_str = r#"
            username = "test_user"
            password = "test_password"
            address = "localhost"
            db_name = "test_db"
            min_connections = 2
            max_connections = 5
            connection_retries = 5
            connection_retry_delay = "5s"
            connection_timeout = "3s"
            "#;

        let config_file = ConfigFile::from_str(config_str).unwrap();
        assert_eq!(test_config_file(), config_file);
    }

    #[test]
    fn correct_uri() {
        let config: Config = test_config_file().try_into().unwrap();
        assert_eq!(
            config.uri(),
            "postgres://test_user:test_password@localhost/test_db"
        );
    }

    #[test]
    fn config_does_not_show_password_on_debug() {
        let config: Config = test_config_file().try_into().unwrap();
        let debug_format_config = format!("{config:?}");
        assert!(debug_format_config.contains("REDACTED"));
        assert!(!debug_format_config.contains("test_user"));
        assert!(!debug_format_config.contains("test_password"));
    }

    #[test]
    fn config_file_does_not_show_password_on_debug() {
        let config_file = test_config_file();
        let debug_format_config = format!("{config_file:?}");
        assert!(debug_format_config.contains("REDACTED"));
        assert!(!debug_format_config.contains("test_user"));
        assert!(!debug_format_config.contains("test_password"));
    }
}
