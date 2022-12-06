use crate::{constants::USERS, error::Error};
use async_trait::async_trait;
use lock_keeper::{
    config::opaque::OpaqueCipherSuite,
    constants::{ACCOUNT_NAME, USER_ID},
    crypto::{Encrypted, KeyId, StorageKey},
    types::{
        audit_event::{AuditEvent, AuditEventOptions, EventStatus, EventType},
        database::{
            secrets::StoredSecret,
            user::{AccountName, User, UserId},
        },
        operations::ClientAction,
    },
};
use lock_keeper_key_server::{
    config::DatabaseSpec,
    database::{DataStore, SecretFilter},
};
use mongodb::{
    bson::doc,
    options::{ClientOptions, IndexOptions},
    Client, Database as MongoDB, IndexModel,
};
use opaque_ke::ServerRegistration;

mod audit_event;
mod secret;
mod user;

#[derive(Debug, Clone)]
pub struct Database {
    handle: MongoDB,
}

impl Database {
    /// Connect to the MongoDB instance specified by the given [`DatabaseSpec`]
    pub async fn connect(database_spec: &DatabaseSpec) -> Result<Self, Error> {
        // Parse a connection string into an options struct
        let client_options = ClientOptions::parse(&database_spec.mongodb_uri).await?;
        // Get a handle to the deployment
        let client = Client::with_options(client_options)?;
        // Get a handle to the database
        let db = client.database(&database_spec.db_name);

        // Enforce that the user ID is unique
        let enforce_uniqueness = IndexOptions::builder().unique(true).build();
        let user_id_index = IndexModel::builder()
            .keys(doc! {USER_ID: 1})
            .options(enforce_uniqueness)
            .build();

        // Enforce that the account name is unique
        let enforce_uniqueness = IndexOptions::builder().unique(true).build();
        let account_name_index = IndexModel::builder()
            .keys(doc! {ACCOUNT_NAME: 1})
            .options(enforce_uniqueness)
            .build();

        // Apply uniqueness to the database
        let _created_indices = db
            .collection::<User>(USERS)
            .create_indexes([user_id_index, account_name_index], None)
            .await?;

        Ok(Self { handle: db })
    }
}

#[async_trait]
impl DataStore for Database {
    type Error = Error;

    async fn create_audit_event(
        &self,
        actor: &AccountName,
        secret_id: &Option<KeyId>,
        action: ClientAction,
        status: EventStatus,
    ) -> Result<(), Self::Error> {
        self.create_audit_event(actor, secret_id, action, status)
            .await?;
        Ok(())
    }

    async fn find_audit_events(
        &self,
        account_name: &AccountName,
        event_type: EventType,
        options: AuditEventOptions,
    ) -> Result<Vec<AuditEvent>, Self::Error> {
        let audit_events = self
            .find_audit_events(account_name, event_type, options)
            .await?;
        Ok(audit_events)
    }

    async fn add_user_secret(
        &self,
        user_id: &UserId,
        secret: StoredSecret,
    ) -> Result<(), Self::Error> {
        self.add_user_secret(user_id, secret).await?;
        Ok(())
    }

    async fn get_user_secret(
        &self,
        user_id: &UserId,
        key_id: &KeyId,
        filter: SecretFilter,
    ) -> Result<StoredSecret, Self::Error> {
        let stored_encrypted_secret = self.get_user_secret(user_id, key_id, filter).await?;
        Ok(stored_encrypted_secret)
    }

    async fn create_user(
        &self,
        user_id: &UserId,
        account_name: &AccountName,
        server_registration: &ServerRegistration<OpaqueCipherSuite>,
    ) -> Result<User, Self::Error> {
        let user = self
            .create_user(user_id, account_name, server_registration)
            .await?;
        Ok(user)
    }

    async fn find_user(&self, account_name: &AccountName) -> Result<Option<User>, Self::Error> {
        let opt_user = self.find_user(account_name).await?;
        Ok(opt_user)
    }

    async fn find_user_by_id(&self, user_id: &UserId) -> Result<Option<User>, Self::Error> {
        let opt_user = self.find_user_by_id(user_id).await?;
        Ok(opt_user)
    }

    async fn delete_user(&self, user_id: &UserId) -> Result<(), Self::Error> {
        self.delete_user(user_id).await?;
        Ok(())
    }

    async fn set_storage_key(
        &self,
        user_id: &UserId,
        storage_key: Encrypted<StorageKey>,
    ) -> Result<(), Self::Error> {
        self.set_storage_key(user_id, storage_key).await?;
        Ok(())
    }
}
