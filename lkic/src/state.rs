//! Types for the state of the running application and any related types
//! contained in the state.

use std::path::PathBuf;

use crate::storage::Storage;
use lock_keeper::{config::client::Config, user::AccountName};
use lock_keeper_client::client::Password;

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
}

/// User credentials
#[derive(Debug)]
pub struct Credentials {
    pub account_name: AccountName,
    pub password: Password,
}
