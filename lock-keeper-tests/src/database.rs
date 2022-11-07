//! Database integration tests

pub mod audit_event;
pub mod secret;
pub mod user;

use generic_array::{typenum::U64, GenericArray};
use std::{ops::Deref, str::FromStr};

use crate::{error::Result, utils::report_test_results, Config};
use lock_keeper::{
    config::server::DatabaseSpec,
    crypto::{Encrypted, OpaqueExportKey, StorageKey},
    types::database::user::{AccountName, UserId},
};
use lock_keeper_key_server::database::Database;
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::utils::{server_registration, tagged};

pub const USERS_TABLE: &str = "users";

pub async fn run_tests(config: &Config) -> Result<()> {
    println!("Running database tests");

    let audit_event_results = audit_event::run_tests(config.clone()).await?;
    let user_results = user::run_tests(config.clone()).await?;
    let secret_results = secret::run_tests(config.clone()).await?;

    // Report results after all tests finish so results show up together
    println!(
        "audit event tests: {}",
        report_test_results(&audit_event_results)
    );
    println!("user tests: {}", report_test_results(&user_results));
    println!("secret tests: {}", report_test_results(&secret_results));

    println!();

    Ok(())
}

#[derive(Clone, Debug)]
pub struct TestDatabase {
    pub db: Database,
    pub spec: DatabaseSpec,
    /// Direct connection to MongoDB for actions that we don't provide in
    /// [`Database`]
    pub mongo: mongodb::Database,
}

impl Deref for TestDatabase {
    type Target = Database;

    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

impl TestDatabase {
    /// Create a new test database with random characters appended to name.
    /// This is what you probably want to use.
    pub async fn new(db_name: impl AsRef<str>) -> Result<Self> {
        Self::from_db_name(tagged(db_name)).await
    }

    /// Create a new test database with a specific name.
    /// Use this to reconnect to a [`TestDatabase`] created with the `new`
    /// function.
    pub async fn from_db_name(db_name: impl Into<String>) -> Result<Self> {
        use mongodb::{options::ClientOptions, Client};

        let mongodb_uri = "mongodb://localhost:27017";

        let spec = DatabaseSpec {
            mongodb_uri: mongodb_uri.to_string(),
            db_name: db_name.into(),
        };

        let db = Database::connect(&spec).await?;

        let client_options = ClientOptions::parse(&mongodb_uri).await?;
        let client = Client::with_options(client_options)?;
        let mongo = client.database(&spec.db_name);

        let result = TestDatabase { db, spec, mongo };

        Ok(result)
    }

    /// Drops the underlying database. Call this when you're done using the test
    /// database. Some day Rust will have async `Drop` and we can do this
    /// properly.
    pub async fn drop(self) -> Result<()> {
        self.mongo.drop(None).await?;
        Ok(())
    }

    /// Create an export key for testing using random bytes.
    fn create_test_export_key(rng: &mut StdRng) -> Result<OpaqueExportKey> {
        let mut key = [0_u8; 64];
        rng.try_fill(&mut key)?;

        // We can't create an export key directly from bytes so we convert it to a
        // GenericArray first.
        let key: GenericArray<u8, U64> = key.into();

        Ok(key.into())
    }

    /// Create a storage key for a test user.
    pub fn create_test_storage_key(
        &self,
        user_id: &UserId,
    ) -> Result<(Encrypted<StorageKey>, OpaqueExportKey)> {
        let mut rng = StdRng::from_entropy();

        // Create a storage key
        let export_key = Self::create_test_export_key(&mut rng)?;
        let storage_key = export_key
            .clone()
            .create_and_encrypt_storage_key(&mut rng, user_id)?;

        Ok((storage_key, export_key))
    }

    /// Creates a test user with a randomized name and returns the id and
    /// account name.
    pub async fn create_test_user(&self) -> Result<(UserId, AccountName)> {
        let mut rng = StdRng::from_entropy();

        let user_id = UserId::new(&mut rng)?;
        let account_name = AccountName::from_str(&tagged("user"))?;

        let server_registration = server_registration();
        let _ = self
            .db
            .create_user(&user_id, &account_name, &server_registration)
            .await?;

        Ok((user_id, account_name))
    }

    /// Retrieves a user from the database and ensures that it can be
    /// deserialized to the `User` type. Returns true if retrieval and
    /// deserialization were successful.
    pub async fn is_user_valid(&self, account_name: &AccountName) -> bool {
        match self.find_user(account_name).await {
            Ok(maybe_user) => maybe_user.is_some(),
            Err(_) => false,
        }
    }
}
