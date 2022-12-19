//! Config for session cache.

use serde::{Deserialize, Serialize};
use std::{path::Path, str::FromStr, time::Duration};

use crate::Error;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct Config {
    #[serde(with = "humantime_serde")]
    pub session_expiration: Duration,
}

impl Config {
    pub fn from_file(config_path: impl AsRef<Path>) -> Result<Self, Error> {
        let config_string = std::fs::read_to_string(&config_path)?;
        Self::from_str(&config_string)
    }
}

impl FromStr for Config {
    type Err = Error;

    fn from_str(config_string: &str) -> Result<Self, Self::Err> {
        Ok(toml::from_str(config_string)?)
    }
}
