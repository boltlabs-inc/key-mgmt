//! Config for database.

use serde::{Deserialize, Serialize};
use std::{path::Path, str::FromStr};

use crate::error::Error;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct Config {
    pub mongodb_uri: String,
    pub db_name: String,
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
