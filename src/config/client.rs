use dialectic_reconnect::Backoff;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use crate::client::defaults;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[non_exhaustive]
pub struct Config {
    #[serde(default = "defaults::backoff")]
    pub backoff: Backoff,
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
    pub async fn load(config_path: impl AsRef<Path>) -> Result<Config, anyhow::Error> {
        let mut config: Config = toml::from_str(&tokio::fs::read_to_string(&config_path).await?)?;

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
