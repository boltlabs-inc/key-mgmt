//! Config for session cache.

use crate::{error::ConfigError, Error};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Formatter},
    path::Path,
    str::FromStr,
    time::Duration,
};

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
    pub session_expiration: Duration,
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
            .field("session_expiration", &self.session_expiration)
            .finish()
    }
}

impl Config {
    pub const SESSION_CACHE_USERNAME: &'static str = "SESSION_CACHE_USERNAME";
    pub const SESSION_CACHE_PASSWORD: &'static str = "SESSION_CACHE_PASSWORD";

    /// Generate full URI for our database based on the config in the form of:
    /// postgres://username:password@address/db_name.
    pub fn uri(&self) -> String {
        format!(
            "postgres://{}:{}@{}/{}",
            self.username, self.password, self.address, self.db_name
        )
    }
}

impl FromStr for Config {
    type Err = Error;

    fn from_str(config_string: &str) -> Result<Self, Self::Err> {
        let config_file = ConfigFile::from_str(config_string)?;
        Ok(config_file.try_into()?)
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
            session_expiration: config.session_expiration,
        };

        Ok(config)
    }
}

#[derive(Clone, Deserialize, Serialize)]
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
    #[serde(with = "humantime_serde")]
    pub session_expiration: Duration,
}

impl ConfigFile {
    pub fn from_file(config_path: impl AsRef<Path>) -> Result<Self, Error> {
        let config_string = std::fs::read_to_string(&config_path)?;
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
            .field("session_expiration", &self.session_expiration)
            .finish()
    }
}

impl FromStr for ConfigFile {
    type Err = Error;

    fn from_str(config_string: &str) -> Result<Self, Self::Err> {
        Ok(toml::from_str(config_string)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_does_not_show_password_on_debug() {
        let config = Config {
            username: "this_is_the_username".to_string(),
            password: "this_is_the_password".to_string(),
            address: "address".to_string(),
            db_name: "db_name".to_string(),
            min_connections: 2,
            max_connections: 5,
            connection_retries: 1,
            connection_retry_delay: Duration::from_secs(1),
            connection_timeout: Duration::from_secs(1),
            session_expiration: Duration::from_secs(1),
        };
        let debug_format_config = format!("{config:?}");
        assert!(debug_format_config.contains("REDACTED"));
        assert!(!debug_format_config.contains("this_is_the_username"));
        assert!(!debug_format_config.contains("this_is_the_password"));
    }

    #[test]
    fn config_file_does_not_show_password_on_debug() {
        let config_file = ConfigFile {
            username: Some("this_is_the_username".to_string()),
            password: Some("this_is_the_password".to_string()),
            address: "localhost".to_string(),
            db_name: "test_db".to_string(),
            min_connections: 2,
            max_connections: 5,
            connection_retries: 5,
            connection_retry_delay: Duration::from_secs(5),
            connection_timeout: Duration::from_secs(3),
            session_expiration: Duration::from_secs(3),
        };
        let debug_format_config = format!("{config_file:?}");
        assert!(debug_format_config.contains("REDACTED"));
        assert!(!debug_format_config.contains("this_is_the_username"));
        assert!(!debug_format_config.contains("this_is_the_password"));
    }
}
