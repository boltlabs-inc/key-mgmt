use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::defaults::server as defaults;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[non_exhaustive]
pub struct Config {
    #[serde(rename = "service")]
    pub services: Vec<Service>,
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
}

impl Config {
    pub async fn load(config_path: impl AsRef<Path>) -> Result<Config, anyhow::Error> {
        let mut config: Config = toml::from_str(&tokio::fs::read_to_string(&config_path).await?)?;

        // Directory containing the configuration path
        let config_dir = config_path
            .as_ref()
            .parent()
            .expect("Server configuration path must exist in some parent directory");

        // Adjust contained paths to be relative to the config path
        for service in config.services.as_mut_slice() {
            service.private_key = config_dir.join(&service.private_key);
            service.certificate = config_dir.join(&service.certificate);
        }

        Ok(config)
    }
}
