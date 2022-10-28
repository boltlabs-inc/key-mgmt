//! Test config types

use lock_keeper::config::client;

use crate::Cli;

#[derive(Debug, Clone)]
pub struct Config {
    pub client_config: client::Config,
    pub filters: TestFilters,
}

impl TryFrom<Cli> for Config {
    type Error = anyhow::Error;

    fn try_from(cli: Cli) -> Result<Self, Self::Error> {
        let client_config = client::Config::load(&cli.client_config)?;
        Ok(Self {
            client_config,
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
