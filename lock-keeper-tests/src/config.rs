//! Test config types

use std::{collections::HashMap, path::PathBuf};

use lock_keeper_client::Config;

use crate::{error::LockKeeperTestError, utils, Cli};

pub const STANDARD_CONFIG_NAME: &str = "standard";
pub const CLIENT_AUTH_CONFIG_NAME: &str = "client_auth";
pub const REQUIRED_CONFIGS: &[&str] = &[STANDARD_CONFIG_NAME, CLIENT_AUTH_CONFIG_NAME];

/// Contains test configs for all environments defined in the test environment
/// configuration file. This allows us to use specific configs for certain tests
/// or to run certain tests in all environments.
#[derive(Clone, Debug)]
pub struct Environments {
    pub configs: HashMap<String, Config>,
    pub filters: TestFilters,
}

impl TryFrom<Cli> for Environments {
    type Error = LockKeeperTestError;

    fn try_from(cli: Cli) -> Result<Self, Self::Error> {
        let environments_string = std::fs::read_to_string(&cli.environments)?;
        let environment_paths: HashMap<String, PathBuf> = toml::from_str(&environments_string)?;

        let filters: TestFilters = cli.filters.unwrap_or_default().into();

        let mut configs = HashMap::new();
        for (name, path) in environment_paths {
            // The `standard_only` flag lets you run e2e tests locally against a single
            // environment
            if cli.standard_only && name != STANDARD_CONFIG_NAME {
                continue;
            }
            let client_config = Config::from_file(path, None)?;
            configs.insert(name, client_config);
        }

        // Set required configs based on simple flag
        let required_configs = if cli.standard_only {
            &[STANDARD_CONFIG_NAME]
        } else {
            REQUIRED_CONFIGS
        };

        for required_config in required_configs {
            if !configs.contains_key(*required_config) {
                return Err(LockKeeperTestError::MissingRequiredConfig(
                    required_config.to_string(),
                ));
            }
        }

        Ok(Self { configs, filters })
    }
}

impl Environments {
    pub async fn wait(&self) -> Result<(), LockKeeperTestError> {
        for (name, config) in &self.configs {
            println!("Waiting for environment: {name}");
            if let Err(LockKeeperTestError::WaitForServerTimedOut) =
                utils::wait_for_server(config).await
            {
                return Err(LockKeeperTestError::WaitForEnvironmentFailed(name.clone()));
            }
        }

        Ok(())
    }

    pub fn config(&self, environment_name: &str) -> Result<&Config, LockKeeperTestError> {
        self.configs
            .get(environment_name)
            .ok_or_else(|| LockKeeperTestError::UndefinedEnvironment(environment_name.to_string()))
    }

    pub fn standard_config(&self) -> Result<&Config, LockKeeperTestError> {
        self.config(STANDARD_CONFIG_NAME)
    }

    pub fn client_auth_config(&self) -> Result<&Config, LockKeeperTestError> {
        self.config(CLIENT_AUTH_CONFIG_NAME)
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
