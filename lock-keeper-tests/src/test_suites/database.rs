//! Database integration tests

pub mod audit_event;
pub mod secret;
pub mod user;

use generic_array::{typenum::U64, GenericArray};
use std::{ops::Deref, str::FromStr};

use crate::{
    error::Result,
    utils::{report_test_results, TestResult},
    Config,
};
use lock_keeper::{
    crypto::{Encrypted, MasterKey, StorageKey},
    types::database::user::{AccountName, UserId},
};
use lock_keeper_key_server::{config::DatabaseSpec, database::DataStore};
use lock_keeper_mongodb::Database;
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::utils::{server_registration, tagged};

pub const USERS_TABLE: &str = "users";

pub async fn run_tests(config: &Config) -> Result<Vec<TestResult>> {
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

    let results = audit_event_results
        .into_iter()
        .chain(user_results)
        .chain(secret_results)
        .collect();

    Ok(results)
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
    fn create_test_master_key(rng: &mut StdRng) -> Result<MasterKey> {
        let mut key = [0_u8; 64];
        rng.try_fill(&mut key)?;

        // We can't create an export key directly from bytes so we convert it to a
        // GenericArray first.
        let key: GenericArray<u8, U64> = key.into();

        let master_key = MasterKey::derive_master_key(key)?;
        Ok(master_key)
    }

    /// Create a storage key for a test user.
    pub fn create_test_storage_key(
        &self,
        user_id: &UserId,
    ) -> Result<(Encrypted<StorageKey>, MasterKey)> {
        let mut rng = StdRng::from_entropy();

        // Create a storage key
        let master_key = Self::create_test_master_key(&mut rng)?;
        let storage_key = master_key
            .clone()
            .create_and_encrypt_storage_key(&mut rng, user_id)?;

        Ok((storage_key, master_key))
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
