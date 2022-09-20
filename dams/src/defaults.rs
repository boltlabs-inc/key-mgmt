use directories::ProjectDirs;
use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    time::Duration,
};

use crate::error::DamsError;

fn project_dirs() -> Result<ProjectDirs, DamsError> {
    ProjectDirs::from("", shared::ORGANIZATION, shared::APPLICATION).ok_or(DamsError::ProjectDirs)
}

pub(crate) mod shared {
    use super::*;

    pub const ORGANIZATION: &str = "Bolt Labs";
    pub const APPLICATION: &str = "key-mgmt";
    pub const LOCAL_SERVER_URI: &str = "https://localhost:1113";

    pub const fn max_pending_connection_retries() -> usize {
        4
    }

    pub const fn max_message_length() -> usize {
        1024 * 16
    }

    pub const fn port() -> u16 {
        1113
    }

    /// Length of time (seconds) that a party waits for a normal message to be
    /// computed and sent.
    pub const fn message_timeout() -> Duration {
        Duration::from_secs(60)
    }
}

pub mod server {
    use super::*;

    pub use super::shared::*;

    pub const fn address() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    pub const CONFIG_FILE: &str = "Server.toml";

    pub fn config_path() -> Result<PathBuf, DamsError> {
        Ok(project_dirs()?.config_dir().join(CONFIG_FILE))
    }
}

pub mod client {
    use super::*;

    pub use super::shared::*;

    pub const fn connection_timeout() -> Option<Duration> {
        Some(Duration::from_secs(60))
    }

    pub const CONFIG_FILE: &str = "Client.toml";

    pub fn config_path() -> Result<PathBuf, DamsError> {
        Ok(project_dirs()?.config_dir().join(CONFIG_FILE))
    }

    pub const fn max_note_length() -> u64 {
        1024 * 8
    }
}
