//! Types for the state of the running application and any related types
//! contained in the state.

use std::path::PathBuf;

use crate::storage::{Entry, Storage};
use lock_keeper::types::database::account::AccountName;
use lock_keeper_client::{client::Password, Config};

/// In-memory state for a running application
#[derive(Debug)]
pub struct State {
    /// `LockKeeperClient` config
    pub config: Config,
    /// Local storage for key information
    pub storage: Storage,
    /// Contains the credentials of the currently logged-in user
    pub credentials: Option<Credentials>,
}

impl State {
    pub fn new(config: Config, storage_path: PathBuf) -> anyhow::Result<Self> {
        Ok(Self {
            config,
            storage: Storage::new(storage_path)?,
            credentials: None,
        })
    }

    pub fn get_credentials(&self) -> Result<&Credentials, anyhow::Error> {
        self.credentials
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not authenticated"))
    }

    /// Fetch the key_id named `named` belonging to the currently authenticated
    /// user.
    ///
    /// This operation will fail if no user is currently authenticated.
    pub fn get_key_id(&self, name: &str) -> Result<&Entry, anyhow::Error> {
        let account_name = &self.get_credentials()?.account_name;
        let entry = self
            .storage
            .get(account_name, name)?
            .ok_or_else(|| anyhow::anyhow!("No key found with name {name}"))?;
        Ok(entry)
    }

    /// Store an entry with the given name, if no name is specified one will be
    /// autogenerated for you. Return the name assigned to the stored entry.
    pub fn store_entry(
        &mut self,
        name: Option<String>,
        entry: impl Into<Entry>,
    ) -> Result<String, anyhow::Error> {
        let credentials = self.get_credentials()?;

        match name {
            None => self.storage.store(credentials.account_name.clone(), entry),
            Some(name) => {
                self.storage
                    .store_named(credentials.account_name.clone(), name.clone(), entry)?;
                Ok(name)
            }
        }
    }
}

/// User credentials
#[derive(Debug)]
pub struct Credentials {
    pub account_name: AccountName,
    pub password: Password,
}
