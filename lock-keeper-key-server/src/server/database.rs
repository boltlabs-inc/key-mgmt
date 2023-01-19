//! Database for key-servers.
//!
//! This database will hold information on users and the secret material
//! they have stored in the key server.

use async_trait::async_trait;
use lock_keeper::{
    config::opaque::OpaqueCipherSuite,
    crypto::{Encrypted, KeyId, StorageKey},
    types::{
        audit_event::{AuditEvent, AuditEventOptions, EventStatus, EventType},
        database::{
            account::{Account, AccountId, AccountName, UserId},
            secrets::StoredSecret,
        },
        operations::ClientAction,
    },
};
use opaque_ke::ServerRegistration;
use thiserror::Error;
use tonic::Status;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("No such entry in table.")]
    NoEntry,
    #[error("More entries than expected were found.")]
    InvalidCountFound,
    #[error("The provided audit event filtering options were not formatted correctly.")]
    InvalidAuditEventOptions,
    #[error("Key ID exists but associated user ID or key type were incorrect.")]
    IncorrectKeyMetadata,
    #[error("An error occurred within the database: {0}. See database logs.")]
    InternalDatabaseError(String),
}

impl From<DatabaseError> for Status {
    fn from(err: DatabaseError) -> Self {
        Status::internal(err.to_string())
    }
}

/// Defines the expected interface between a key server and its database.
///
/// This trait definition is not complete. New trait methods may be added
/// in future server versions.
#[async_trait]
pub trait DataStore: Send + Sync + 'static {
    /// Create a new [`AuditEvent`] for the given actor, action, and outcome
    async fn create_audit_event(
        &self,
        request_id: Uuid,
        account_id: AccountId,
        key_id: &Option<KeyId>,
        action: ClientAction,
        status: EventStatus,
    ) -> Result<(), DatabaseError>;

    /// Find [`AuditEvent`]s that correspond to the event type and provided
    /// filters
    async fn find_audit_events(
        &self,
        account_id: AccountId,
        event_type: EventType,
        options: AuditEventOptions,
    ) -> Result<Vec<AuditEvent>, DatabaseError>;

    // Secret
    /// Add a [`StoredSecret`] to a [`Account`]'s list of arbitrary
    /// secrets
    async fn add_secret(&self, secret: StoredSecret) -> Result<(), DatabaseError>;

    /// Get a [`Account`]'s [`StoredSecret`] based on its [`KeyId`].
    /// A [`StoredSecret`] will only be returned if it matches the given
    /// [`SecretFilter`].
    async fn get_secret(
        &self,
        account_id: AccountId,
        key_id: &KeyId,
        filter: SecretFilter,
    ) -> Result<StoredSecret, DatabaseError>;

    // User
    /// Create a new [`Account`] with their authentication information and
    /// insert it into the database.
    async fn create_account(
        &self,
        user_id: &UserId,
        account_name: &AccountName,
        server_registration: &ServerRegistration<OpaqueCipherSuite>,
    ) -> Result<Account, DatabaseError>;

    /// Find a [`Account`] by their human-readable [`AccountName`].
    async fn find_account_by_name(
        &self,
        account_name: &AccountName,
    ) -> Result<Option<Account>, DatabaseError>;

    /// Find a [`Account`] by their [`AccountId`].
    async fn find_account(&self, account_id: AccountId) -> Result<Option<Account>, DatabaseError>;

    /// Delete a [`Account`] by their [`AccountId`]
    async fn delete_account(&self, account_id: AccountId) -> Result<(), DatabaseError>;

    /// Set the `storage_key` field for the [`Account`] associated with a given
    /// [`AccountId`]
    /// Returns a `LockKeeperServerError::InvalidAccount` if the given
    /// `account_id` does not exist.
    async fn set_storage_key(
        &self,
        account_id: AccountId,
        storage_key: Encrypted<StorageKey>,
    ) -> Result<(), DatabaseError>;

    /// Returns `true` if the [`UserId`] already exists in the database.
    async fn user_id_exists(&self, user_id: &UserId) -> Result<bool, DatabaseError>;
}

/// Filters that can be used to influence database queries.
/// Any new database filters for secrets (e.g. created_time)
/// should be added to this struct as optional fields.
/// This will allow us to add new filters with minimal breakage.
///
/// If you're constructing this type directly, use `..Default::default()`
/// to guard against breaking changes.
///
/// ## Example:
/// ```
/// # use lock_keeper_key_server::server::database::SecretFilter;
/// SecretFilter {
///     secret_type: None,
///     ..Default::default()
/// };
/// ```
#[derive(Clone, Debug, Default)]
pub struct SecretFilter {
    pub secret_type: Option<String>,
}

impl SecretFilter {
    /// Convenience function to filter by secret type.
    pub fn secret_type(secret_type: impl std::fmt::Display) -> Self {
        Self {
            secret_type: Some(secret_type.to_string()),
        }
    }
}
