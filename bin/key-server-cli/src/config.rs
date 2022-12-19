//! Config for key server binary.

use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct Config {
    pub server: PathBuf,
    pub database: PathBuf,
    pub session_cache: PathBuf,
}

impl Config {
    pub fn from_file(config_path: impl AsRef<Path>) -> Self {
        let config_string =
            std::fs::read_to_string(&config_path).expect("Unable to read from config file.");
        Self::from_str(&config_string).expect("Unable to convert config to TOML.")
    }
}

impl FromStr for Config {
    type Err = toml::de::Error;

    fn from_str(config_string: &str) -> Result<Self, Self::Err> {
        toml::from_str(config_string)
    }
}
