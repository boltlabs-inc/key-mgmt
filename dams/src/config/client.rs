use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use crate::{defaults::client as defaults, error::DamsError};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[non_exhaustive]
pub struct Config {
    #[serde(with = "humantime_serde", default = "defaults::connection_timeout")]
    pub connection_timeout: Option<Duration>,
    #[serde(default = "defaults::max_pending_connection_retries")]
    pub max_pending_connection_retries: usize,
    #[serde(with = "humantime_serde", default = "defaults::message_timeout")]
    pub message_timeout: Duration,
    #[serde(default = "defaults::max_message_length")]
    pub max_message_length: usize,
    #[serde(default = "defaults::max_note_length")]
    pub max_note_length: u64,
    #[serde(default)]
    pub trust_certificate: Option<PathBuf>,
}

impl Config {
    pub async fn load(config_path: impl AsRef<Path>) -> Result<Config, DamsError> {
        let config_string = tokio::fs::read_to_string(&config_path).await?;
        let mut config = Self::from_str(&config_string)?;

        // Directory containing the configuration path
        let config_dir = config_path
            .as_ref()
            .parent()
            .expect("Client configuration path must exist in some parent directory");

        // Adjust contained paths to be relative to the config path
        config.trust_certificate = config
            .trust_certificate
            .map(|ref cert_path| config_dir.join(cert_path));

        Ok(config)
    }
}

impl FromStr for Config {
    type Err = DamsError;

    fn from_str(config_string: &str) -> Result<Self, Self::Err> {
        let config: Config = toml::from_str(config_string)?;
        Ok(config)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            connection_timeout: None,
            max_pending_connection_retries: 4,
            message_timeout: Duration::from_secs(60),
            max_message_length: 1024 * 16,
            max_note_length: 0,
            trust_certificate: Some(PathBuf::from("tests/gen/localhost.crt")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_str() {
        let config_str = r#"
            connection_timeout = "20s"
            max_pending_connection_retries = 10
            message_timeout = "20s"
            max_message_length = 100
            max_note_length = 100
        "#;

        // Destructure so the test breaks when fields are added
        let Config {
            connection_timeout,
            max_pending_connection_retries,
            message_timeout,
            max_message_length,
            max_note_length,
            trust_certificate,
        } = Config::from_str(config_str).unwrap();

        assert_eq!(connection_timeout, Some(Duration::from_secs(20)));
        assert_eq!(max_pending_connection_retries, 10);
        assert_eq!(message_timeout, Duration::from_secs(20));
        assert_eq!(max_message_length, 100);
        assert_eq!(max_note_length, 100);
        assert_eq!(trust_certificate, None);
    }

    #[test]
    fn config_defaults() {
        let config_str = r#"
            trust_certificate = "tests/gen/localhost.crt"
        "#;

        // Destructure so the test breaks when fields are added
        let Config {
            connection_timeout,
            max_pending_connection_retries,
            message_timeout,
            max_message_length,
            max_note_length,
            trust_certificate,
        } = Config::from_str(config_str).unwrap();

        assert_eq!(connection_timeout, Some(Duration::from_secs(60)));
        assert_eq!(max_pending_connection_retries, 4);
        assert_eq!(message_timeout, Duration::from_secs(60));
        assert_eq!(max_message_length, 1024 * 16);
        assert_eq!(max_note_length, 1024 * 8);
        assert_eq!(
            trust_certificate,
            Some(PathBuf::from("tests/gen/localhost.crt"))
        );
    }
}
