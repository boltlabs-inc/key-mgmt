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
            secrets::StoredSecret,
            user::{Account, AccountName, UserId},
        },
        operations::ClientAction,
    },
};
use opaque_ke::ServerRegistration;
use uuid::Uuid;

/// Defines the expected interface between a key server and its database.
///
/// This trait definition is not complete. New trait methods may be added
/// in future server versions.
#[async_trait]
pub trait DataStore: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Create a new [`AuditEvent`] for the given actor, action, and outcome
    async fn create_audit_event(
        &self,
        request_id: Uuid,
        account_name: &AccountName,
        key_id: &Option<KeyId>,
        action: ClientAction,
        status: EventStatus,
    ) -> Result<(), Self::Error>;

    /// Find [`AuditEvent`]s that correspond to the event type and provided
    /// filters
    async fn find_audit_events(
        &self,
        account_name: &AccountName,
        event_type: EventType,
        options: AuditEventOptions,
    ) -> Result<Vec<AuditEvent>, Self::Error>;

    // Secret
    /// Add a [`StoredSecret`] to a [`Account`]'s list of arbitrary
    /// secrets
    async fn add_secret(&self, secret: StoredSecret) -> Result<(), Self::Error>;

    /// Get a [`Account`]'s [`StoredSecret`] based on its [`KeyId`].
    /// A [`StoredSecret`] will only be returned if it matches the given
    /// [`SecretFilter`].
    async fn get_secret(
        &self,
        user_id: &UserId,
        key_id: &KeyId,
        filter: SecretFilter,
    ) -> Result<StoredSecret, Self::Error>;

    // User
    /// Create a new [`Account`] with their authentication information and
    /// insert it into the database.
    async fn create_account(
        &self,
        user_id: &UserId,
        account_name: &AccountName,
        server_registration: &ServerRegistration<OpaqueCipherSuite>,
    ) -> Result<Account, Self::Error>;

    /// Find a [`Account`] by their human-readable [`AccountName`].
    async fn find_account(
        &self,
        account_name: &AccountName,
    ) -> Result<Option<Account>, Self::Error>;

    /// Find a [`Account`] by their machine-readable [`UserId`].
    async fn find_account_by_id(&self, user_id: &UserId) -> Result<Option<Account>, Self::Error>;

    /// Delete a [`Account`] by their [`UserId`]
    async fn delete_account(&self, user_id: &UserId) -> Result<(), Self::Error>;

    /// Set the `storage_key` field for the [`Account`] associated with a given
    /// [`UserId`]
    /// Returns a `LockKeeperServerError::InvalidAccount` if the given
    /// `user_id` does not exist.
    async fn set_storage_key(
        &self,
        user_id: &UserId,
        storage_key: Encrypted<StorageKey>,
    ) -> Result<(), Self::Error>;
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
/// # use lock_keeper_key_server::database::SecretFilter;
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
