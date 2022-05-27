//! Public API for the DAMS local client library.
//!

use crate::keys::{KeyTag, UsePermission, UseRestriction};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionError {}

#[derive(Debug)]
pub struct Password;

/// Deployment details for a session.
///
/// Sample fields: timeouts, key server IPs
#[derive(Debug)]
pub struct SessionConfig;

/// Communication session with a set of key servers.
/// A session can be ended manually, or it might time out and require re-authentication (that is, a new [`Session`])
#[allow(unused)]
pub struct Session {
    config: SessionConfig,
}

#[allow(unused)]
impl Session {
    /// Open a new session for a registered user.
    pub fn open(password: Password, config: &SessionConfig) -> Result<Self, SessionError> {
        todo!()
    }

    /// Register a new user who has not yet interacted with the service.
    pub fn register(password: Password, config: &SessionConfig) -> Result<Self, SessionError> {
        todo!()
    }

    /// Close a session.
    pub fn close(self) -> Result<(), SessionError> {
        todo!()
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Session failed: {0:?}")]
    SessionError(#[from] SessionError),
}

#[allow(unused)]
pub fn create_digital_asset_key(
    session: Session,
    key_tag: Option<KeyTag>,
    //blockchain: 
    permission: impl UsePermission,
    restriction: impl UseRestriction,
    // user policy specification - should this be a parameter of [`Delegated`]?
) -> Result<(), Error> {
    todo!()
}