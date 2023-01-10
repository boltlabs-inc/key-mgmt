//! Config for session cache.

use serde::{Deserialize, Serialize};
use std::{env, path::Path, str::FromStr, time::Duration};
use tracing::log::warn;

use crate::{error::ConfigError, Error};

#[derive(Debug)]
pub struct Config {
    pub username: String,
    pub password: String,
    pub address: String,

    /// Name of database. Appended to URI to make the full path.
    pub db_name: String,
    pub max_connections: u32,
    pub connection_timeout: Duration,
    pub session_expiration: Duration,
}

impl Config {
    const SESSION_CACHE_USERNAME: &'static str = "SESSION_CACHE_USERNAME";
    const SESSION_CACHE_PASSWORD: &'static str = "SESSION_CACHE_PASSWORD";

    pub fn from_file(config_path: impl AsRef<Path>) -> Result<Self, Error> {
        let config_string = std::fs::read_to_string(&config_path)?;
        let config_file = ConfigFile::from_str(&config_string)?;
        Ok(config_file.try_into()?)
    }

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
    /// Optional, convenience field for specifying the username. Should only be
    /// used for development!
    fn try_from(config: ConfigFile) -> Result<Self, Self::Error> {
        let username = match config.username {
            None => {
                env::var(Config::SESSION_CACHE_USERNAME).map_err(ConfigError::MissingUsername)?
            }
            Some(username) => {
                warn!("Username found via config file. Ensure you are not running in production.");
                username
            }
        };

        let password = match config.password {
            None => {
                env::var(Config::SESSION_CACHE_PASSWORD).map_err(ConfigError::MissingPassword)?
            }
            Some(password) => {
                warn!("Password found via config file. Ensure you are not running in production.");
                password
            }
        };

        let config = Config {
            username,
            password,
            address: config.address,
            db_name: config.db_name,
            max_connections: config.max_connections,
            connection_timeout: config.connection_timeout,
            session_expiration: config.session_expiration,
        };

        Ok(config)
    }
}

impl FromStr for Config {
    type Err = Error;

    fn from_str(config_string: &str) -> Result<Self, Self::Err> {
        Ok(ConfigFile::from_str(config_string)?.try_into()?)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct ConfigFile {
    /// Optional, convenience field for specifying the username. Should only be
    /// used for development!
    username: Option<String>,
    /// Optional, convenience field for specifying the password. Should only be
    /// used for development!
    password: Option<String>,
    address: String,
    db_name: String,
    max_connections: u32,
    #[serde(with = "humantime_serde")]
    connection_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub session_expiration: Duration,
}

impl ConfigFile {
    pub fn from_file(config_path: impl AsRef<Path>) -> Result<Self, Error> {
        let config_string = std::fs::read_to_string(&config_path)?;
        Self::from_str(&config_string)
    }
}

impl FromStr for ConfigFile {
    type Err = Error;

    fn from_str(config_string: &str) -> Result<Self, Self::Err> {
        Ok(toml::from_str(config_string)?)
    }
}
