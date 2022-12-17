use crate::error::{
    ConfigError,
    ConfigError::{MissingPassword, MissingUsername},
};
use serde::{Deserialize, Serialize};
use std::{env, fs::read_to_string, path::Path, str::FromStr};
use tracing::log::warn;

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
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
    connecting_timeout_seconds: u64,
}

impl ConfigFile {
    pub fn from_file(config_path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let config_string = read_to_string(&config_path).map_err(|e| {
            ConfigError::ConfigFileReadFailure(e, config_path.as_ref().to_path_buf())
        })?;
        Self::from_str(&config_string)
    }
}

impl FromStr for ConfigFile {
    type Err = ConfigError;

    fn from_str(config_string: &str) -> Result<Self, Self::Err> {
        Ok(toml::from_str(config_string)?)
    }
}

#[derive(Debug)]
pub struct Config {
    pub username: String,
    pub password: String,
    pub address: String,

    /// Name of database. Appended to URI to make the full path.
    pub db_name: String,
    pub max_connections: u32,
    pub connecting_timeout_seconds: u64,
}

impl Config {
    const DB_USERNAME: &'static str = "DB_USERNAME";
    const DB_PASSWORD: &'static str = "DB_PASSWORD";

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
            None => env::var(Config::DB_USERNAME).map_err(MissingUsername)?,
            Some(username) => {
                warn!("Username found via config file. Ensure you are not running in production.");
                username
            }
        };

        let password = match config.password {
            None => env::var(Config::DB_PASSWORD).map_err(MissingPassword)?,
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
            connecting_timeout_seconds: config.connecting_timeout_seconds,
        };

        Ok(config)
    }
}

#[cfg(test)]
mod test {
    use crate::{Config, ConfigFile};
    use std::{env, str::FromStr};

    /// Helper method for creating a test [ConfigFile]
    fn test_config_file() -> ConfigFile {
        ConfigFile {
            username: Some("test_user".to_string()),
            password: Some("test_password".to_string()),
            address: "localhost".to_string(),
            db_name: "test_db".to_string(),
            max_connections: 5,
            connecting_timeout_seconds: 3,
        }
    }

    #[test]
    fn from_string() {
        let config_str = r#"
            username = "test_user"
            password = "test_password"
            address = "localhost"
            db_name = "test_db"
            max_connections = 5
            connecting_timeout_seconds = 3
            "#;

        let config_file = ConfigFile::from_str(config_str).unwrap();
        assert_eq!(test_config_file(), config_file);
    }

    #[test]
    fn correct_uri() {
        let config: Config = TryFrom::try_from(test_config_file()).unwrap();
        assert_eq!(
            config.uri(),
            "postgres://test_user:test_password@localhost/test_db"
        );
    }

    #[test]
    fn correct_uri_from_env_vars() {
        let config_file = ConfigFile {
            username: None,
            password: None,
            ..test_config_file()
        };

        env::set_var(Config::DB_USERNAME, "test_user");
        env::set_var(Config::DB_PASSWORD, "test_password");

        let config: Config = TryFrom::try_from(config_file).unwrap();
        assert_eq!(
            config.uri(),
            "postgres://test_user:test_password@localhost/test_db"
        );
    }
}
