use crate::{
    types::{AccountDB, AuditEventDB, SecretDB},
    Config, PostgresError,
};
use async_trait::async_trait;
use lock_keeper::{
    config::opaque::OpaqueCipherSuite,
    crypto::{Encrypted, KeyId, StorageKey},
    infrastructure::logging,
    types::{
        audit_event::{AuditEvent, AuditEventOptions, EventStatus, EventType},
        database::{
            secrets::StoredSecret,
            user::{Account, AccountName, UserId},
        },
        operations::ClientAction,
    },
};
use lock_keeper_key_server::database::{DataStore, SecretFilter};
use opaque_ke::ServerRegistration;
use sqlx::{postgres::PgPoolOptions, Encode, PgPool, Postgres, QueryBuilder, Type};
use std::{
    fmt::{Debug, Formatter},
    sync::Arc,
};
use time::OffsetDateTime;
use tracing::{debug, info, instrument};
use uuid::Uuid;

#[derive(Clone)]
pub struct PostgresDB {
    config: Arc<Config>,
    /// PgPool is already implemented in terms of an Arc. No need to wrap it.
    connection_pool: PgPool,
}

#[async_trait]
impl DataStore for PostgresDB {
    type Error = PostgresError;

    async fn create_audit_event(
        &self,
        request_id: Uuid,
        account_name: &AccountName,
        key_id: &Option<KeyId>,
        action: ClientAction,
        status: EventStatus,
    ) -> Result<(), PostgresError> {
        self.create_audit_event(request_id, account_name, key_id, action, status)
            .await
    }

    async fn find_audit_events(
        &self,
        account_name: &AccountName,
        event_type: EventType,
        options: AuditEventOptions,
    ) -> Result<Vec<AuditEvent>, Self::Error> {
        self.find_audit_events(account_name, event_type, options)
            .await
    }

    async fn add_secret(&self, secret: StoredSecret) -> Result<(), Self::Error> {
        self.add_secret(secret).await
    }

    async fn get_secret(
        &self,
        user_id: &UserId,
        key_id: &KeyId,
        filter: SecretFilter,
    ) -> Result<StoredSecret, Self::Error> {
        self.get_secret(user_id, key_id, filter).await
    }

    async fn create_account(
        &self,
        user_id: &UserId,
        account_name: &AccountName,
        server_registration: &ServerRegistration<OpaqueCipherSuite>,
    ) -> Result<Account, Self::Error> {
        self.create_account(user_id, account_name, server_registration)
            .await
    }

    async fn find_account(
        &self,
        account_name: &AccountName,
    ) -> Result<Option<Account>, Self::Error> {
        self.find_account(account_name).await
    }

    async fn find_account_by_id(&self, user_id: &UserId) -> Result<Option<Account>, Self::Error> {
        self.find_account_by_id(user_id).await
    }

    async fn delete_account(&self, user_id: &UserId) -> Result<(), Self::Error> {
        self.delete_account(user_id).await
    }

    async fn set_storage_key(
        &self,
        user_id: &UserId,
        storage_key: Encrypted<StorageKey>,
    ) -> Result<(), Self::Error> {
        self.set_storage_key(user_id, storage_key).await
    }
}

impl Debug for PostgresDB {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresDB")
            .field("uri", &self.config.uri())
            .finish()
    }
}

impl PostgresDB {
    #[instrument(err(Debug))]
    pub async fn connect(config: Config) -> Result<Self, PostgresError> {
        info!("Connecting to database");

        // Create a connection pool based on our config.
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(config.connection_timeout)
            .connect(&config.uri())
            .await?;

        Ok(PostgresDB {
            config: Arc::new(config),
            connection_pool: pool,
        })
    }

    pub fn db_name(&self) -> &str {
        &self.config.db_name
    }

    #[instrument(skip(self), err(Debug))]
    pub(crate) async fn create_audit_event(
        &self,
        request_id: Uuid,
        account_name: &AccountName,
        key_id: &Option<KeyId>,
        action: ClientAction,
        status: EventStatus,
    ) -> Result<(), PostgresError> {
        debug!("Storing new audit event.");

        let timestamp = OffsetDateTime::now_utc();
        let key_id = key_id.as_ref().map(|k| k.as_bytes());

        let _ = sqlx::query!(
            "INSERT INTO AuditEvents (account_name, key_id, request_id, client_action_id, event_status, timestamp) \
             VALUES ($1, $2, $3, $4, $5, $6)",
            account_name.as_ref(),
            key_id,
            request_id,
            action as i64,
            status.to_string(),
            timestamp,
        )
        .execute(&self.connection_pool)
        .await?;

        Ok(())
    }

    /// Create a dynamic query to fetch audit events specified by the caller.
    #[instrument(skip(self), err(Debug))]
    async fn find_audit_events(
        &self,
        account_name: &AccountName,
        event_type: EventType,
        options: AuditEventOptions,
    ) -> Result<Vec<AuditEvent>, PostgresError> {
        debug!("Finding audit event(s)");

        let mut query = QueryBuilder::new(
            "SELECT audit_event_id, key_id, request_id, account_name, client_action_id, event_status, timestamp \
             FROM AuditEvents \
             WHERE ",
        );

        // Add filtering based on after_date if present.
        if let Some(after_date) = options.after_date {
            let _ = query
                .push("timestamp >= ")
                .push_bind(after_date)
                .push(" AND ");
        }
        // Add filtering based on before_date if present.
        if let Some(before_date) = options.before_date {
            let _ = query
                .push("timestamp <= ")
                .push_bind(before_date)
                .push(" AND ");
        }

        // Add filtering based on key_ids if present.
        if !options.key_ids.is_empty() {
            let _ = query.push("key_id IN ");
            // Turn the key ids into bytes that postgres understands.
            let key_id_bytes = options.key_ids.iter().map(KeyId::as_bytes);
            append_value_list(&mut query, key_id_bytes)?;
            let _ = query.push(" AND ");
        }

        if let Some(request_id) = options.request_id {
            let _ = query
                .push("request_id=")
                .push_bind(request_id)
                .push(" AND ");
        }

        // Add filtering based on actions.
        let _ = query.push("client_action_id IN ");
        // Turn the actions into their integer value for faster searching.
        let actions = event_type.client_actions();
        let actions = actions.iter().map(|a| *a as i64);

        append_value_list(&mut query, actions)?;

        // Ensure account name matches, otherwise a client could fetch anyone's audit
        // events if they guess the request_id.
        let _ = query
            .push("AND account_name=")
            .push_bind(account_name.as_ref());

        debug!("Dynamically generated query: {}", query.sql());

        let matches: Vec<AuditEventDB> = query
            .build_query_as::<AuditEventDB>()
            .fetch_all(&self.connection_pool)
            .await?;

        // Iterator will stop and the first error is returned if our conversion fails.
        let results: Result<Vec<_>, _> = matches.into_iter().map(TryFrom::try_from).collect();
        results
    }

    #[instrument(skip_all, err(Debug), fields(user_id, key_id, secret_type))]
    pub(crate) async fn add_secret(&self, secret: StoredSecret) -> Result<(), PostgresError> {
        logging::record_field("user_id", &secret.user_id);
        logging::record_field("key_id", &secret.key_id);
        logging::record_field("secret_type", &secret.secret_type);
        debug!("Adding user secret.");

        let secret_db: SecretDB = SecretDB::from(secret);

        let _ = sqlx::query!(
            "INSERT INTO Secrets (key_id, user_id, secret, secret_type_id, retrieved) \
             SELECT $1, $2, $3, SecretTypes.secret_type_id, $4 \
             FROM SecretTypes \
             WHERE SecretTypes.secret_type=$5",
            secret_db.key_id,
            secret_db.user_id,
            secret_db.secret,
            secret_db.retrieved,
            secret_db.secret_type,
        )
        .execute(&self.connection_pool)
        .await?;

        Ok(())
    }

    /// This function verifies the user_id and key type matches. Otherwise will
    /// return a IncorrectAssociatedKeyData error.
    #[instrument(skip(self), err(Debug))]
    pub(crate) async fn get_secret(
        &self,
        user_id: &UserId,
        key_id: &KeyId,
        filter: SecretFilter,
    ) -> Result<StoredSecret, PostgresError> {
        debug!("Fetching user secret.");

        // Join tables to map secret_type to the corresponding secret_type_id.
        // Update the retrieved value on Secrets.retrieved
        let secret_db: Option<SecretDB> = sqlx::query_as!(
            SecretDB,
            "UPDATE Secrets \
                SET retrieved=TRUE \
             FROM Secrets S LEFT JOIN SecretTypes ST \
                ON S.secret_type_id=ST.secret_type_id \
             WHERE S.key_id=$1 AND S.user_id=$2 AND ST.secret_type LIKE $3 \
             RETURNING S.key_id, S.user_id, ST.secret_type, S.secret, S.retrieved",
            key_id.as_bytes(),
            user_id.as_ref(),
            // We use the LIKE operator to support whether filter.secret_type is present or
            // not. In case it is not, we use a wildcard match for the secret_type
            // column.
            filter.secret_type.unwrap_or_else(|| "%".to_string())
        )
        .fetch_optional(&self.connection_pool)
        .await?;

        match secret_db {
            None => {
                // Entry not found. Check if the key exists but the user_id was wrong!
                // The "count!" syntax allows us to tell sqlx that the result of this expression
                // will not be null, and return type ((which is an anonymous record) of this
                // `query!` should have a record field called "count".
                let key_found = sqlx::query!(
                    r#"SELECT COUNT(1) as "count!" FROM Secrets WHERE key_id=$1"#,
                    key_id.as_bytes()
                )
                .fetch_one(&self.connection_pool)
                .await?;

                match key_found.count {
                    // The key doesn't even exist.
                    0 => Err(PostgresError::NoEntry),
                    // The key exists but the secret_type or user_id were incorrect.
                    1 => Err(PostgresError::IncorrectAssociatedKeyData),
                    _ => Err(PostgresError::InvalidRowCountFound),
                }
            }
            Some(secret_db) => Ok(secret_db.try_into()?),
        }
    }

    #[instrument(skip(self, server_registration), err(Debug))]
    pub(crate) async fn create_account(
        &self,
        user_id: &UserId,
        account_name: &AccountName,
        server_registration: &ServerRegistration<OpaqueCipherSuite>,
    ) -> Result<Account, PostgresError> {
        info!("Creating new user.");
        let serialized = bincode::serialize(server_registration)?;

        let _ = sqlx::query!(
            "INSERT INTO Accounts (user_id, account_name, server_registration)\
             VALUES ($1, $2, $3)",
            user_id.as_ref(),
            account_name.as_ref(),
            serialized,
        )
        .execute(&self.connection_pool)
        .await?;

        Ok(Account {
            user_id: user_id.clone(),
            account_name: account_name.clone(),
            storage_key: None,
            server_registration: server_registration.clone(),
        })
    }

    #[instrument(skip(self), err(Debug))]
    pub(crate) async fn find_account(
        &self,
        account_name: &AccountName,
    ) -> Result<Option<Account>, PostgresError> {
        debug!("Searching for user.");
        let user_db = sqlx::query_as!(
            AccountDB,
            "SELECT account_id, user_id, account_name, storage_key, server_registration \
            FROM Accounts \
            WHERE account_name=$1",
            account_name.as_ref()
        )
        .fetch_optional(&self.connection_pool)
        .await?;

        let user = user_db.map(Account::try_from).transpose()?;
        Ok(user)
    }

    #[instrument(skip(self), err(Debug))]
    pub(crate) async fn find_account_by_id(
        &self,
        user_id: &UserId,
    ) -> Result<Option<Account>, PostgresError> {
        debug!("Searching for user by ID");

        let user_db: Option<AccountDB> = sqlx::query_as!(
            AccountDB,
            "SELECT account_id, user_id, account_name, storage_key, server_registration \
            FROM Accounts \
            WHERE user_id=$1",
            user_id.as_ref()
        )
        .fetch_optional(&self.connection_pool)
        .await?;

        let user = user_db.map(Account::try_from).transpose()?;
        Ok(user)
    }

    #[instrument(skip(self), err(Debug))]
    pub(crate) async fn delete_account(&self, user_id: &UserId) -> Result<(), PostgresError> {
        info!("Deleting user.");

        // Delete the entry and
        let result = sqlx::query!(
            r#"WITH deleted AS (DELETE FROM Accounts WHERE user_id=$1 RETURNING *) SELECT count(*) AS "count!" FROM deleted"#,
            user_id.as_ref()
        )
        .fetch_one(&self.connection_pool)
        .await?;

        // No row was deleted.
        match result.count {
            0 => Err(PostgresError::NoEntry),
            1 => Ok(()),
            _ => Err(PostgresError::InvalidRowCountFound),
        }
    }

    #[instrument(skip(self, storage_key), err(Debug))]
    pub(crate) async fn set_storage_key(
        &self,
        user_id: &UserId,
        storage_key: Encrypted<StorageKey>,
    ) -> Result<(), PostgresError> {
        debug!("Setting storage key for");

        let storage_key = bincode::serialize(&storage_key)?;

        let _ = sqlx::query!(
            "UPDATE Accounts SET storage_key=$1 WHERE user_id=$2",
            storage_key,
            user_id.as_bytes(),
        )
        .execute(&self.connection_pool)
        .await?;

        Ok(())
    }
}

/// Create a SQL query list of the form (val1, val2, ...). Error is returned if
/// the iterator is empty
#[allow(unused_results)]
fn append_value_list<'a, I: 'a + Encode<'a, Postgres> + Send + Type<Postgres>>(
    query: &mut QueryBuilder<'a, Postgres>,
    values: impl Iterator<Item = I> + Clone,
) -> Result<(), PostgresError> {
    if values.clone().count() == 0 {
        return Err(PostgresError::EmptyIterator);
    }
    query.push("(");
    let mut separated = query.separated(", ");
    for v in values {
        separated.push_bind(v);
    }
    separated.push_unseparated(")");
    Ok(())
}
