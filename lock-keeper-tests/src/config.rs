//! Test config types

use std::path::PathBuf;

use crate::{error::LockKeeperTestError, Cli};
use lock_keeper_client::Config as ClientConfig;

#[derive(Debug, Clone)]
pub struct Config {
    pub client_config: ClientConfig,
    pub client_config_path: PathBuf,
    pub mutual_auth_client_config: ClientConfig,
    pub mutual_auth_client_config_path: PathBuf,
    pub filters: TestFilters,
}

impl TryFrom<Cli> for Config {
    type Error = LockKeeperTestError;

    fn try_from(cli: Cli) -> Result<Self, Self::Error> {
        let client_config = ClientConfig::from_file(&cli.client_config, None)?;
        let mutual_auth_client_config =
            ClientConfig::from_file(&cli.mutual_auth_client_config, None)?;
        Ok(Self {
            client_config,
            client_config_path: cli.client_config.clone(),
            mutual_auth_client_config,
            mutual_auth_client_config_path: cli.mutual_auth_client_config.clone(),
            filters: cli.filters.unwrap_or_default().into(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct TestFilters {
    filters: Vec<String>,
}

impl From<Vec<String>> for TestFilters {
    fn from(filters: Vec<String>) -> Self {
        Self { filters }
    }
}

impl TestFilters {
    pub fn matches(&self, text: &str) -> bool {
        if self.filters.is_empty() {
            return true;
        }

        for filter in &self.filters {
            if text.to_lowercase().contains(&filter.to_lowercase()) {
                return true;
            }
        }
        false
    }
}
