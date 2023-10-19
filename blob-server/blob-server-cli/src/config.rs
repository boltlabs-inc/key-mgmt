//! Config for key server binary.

use blob_server_backend::BlobServerError;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct Config {
    pub server: PathBuf,
}

impl Config {
    pub fn from_file(config_path: impl AsRef<Path>) -> Result<Self, BlobServerError> {
        let config_string = std::fs::read_to_string(&config_path)
            .map_err(|e| BlobServerError::FileIo(e, config_path.as_ref().to_path_buf()))?;
        Ok(Self::from_str(&config_string)?)
    }
}

impl FromStr for Config {
    type Err = toml::de::Error;

    fn from_str(config_string: &str) -> Result<Self, Self::Err> {
        toml::from_str(config_string)
    }
}
