//! Database integration tests

pub mod audit_event;
pub mod secret;
pub mod user;

use generic_array::{typenum::U64, GenericArray};
use std::{ops::Deref, str::FromStr};

use crate::{
    config::TestFilters,
    error::Result,
    utils::{report_test_results, TestResult},
};
use lock_keeper::{
    crypto::{Encrypted, MasterKey, StorageKey},
    types::database::user::{AccountName, UserId},
};
use lock_keeper_key_server::database::DataStore;
use lock_keeper_postgres::{Config, ConfigFile as DatabaseConfigFile, PostgresDB, PostgresError};
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::utils::{server_registration, tagged};

pub const USERS_TABLE: &str = "users";

pub async fn run_tests(filters: &TestFilters) -> Result<Vec<TestResult>> {
    println!("Running database tests");

    let audit_event_results = audit_event::run_tests(filters).await?;
    let user_results = user::run_tests(filters).await?;
    let secret_results = secret::run_tests(filters).await?;

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
    pub db: PostgresDB,
}

impl Deref for TestDatabase {
    type Target = PostgresDB;

    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

impl TestDatabase {
    pub async fn connect() -> Result<Self> {
        let config_str = r#"
            username = 'test' 
            password = 'test_password'
            address = 'localhost'
            db_name = 'test'
            max_connections = 5
            connection_timeout = "3s"
            "#;

        let config_file =
            DatabaseConfigFile::from_str(config_str).map_err(PostgresError::ConfigError)?;
        let config: Config = TryFrom::try_from(config_file).map_err(PostgresError::ConfigError)?;
        let db = PostgresDB::connect(config).await.unwrap();
        Ok(TestDatabase { db })
    }

    /// Create a master key for testing using random bytes.
    fn create_test_master_key(rng: &mut StdRng) -> Result<MasterKey> {
        let mut key = [0_u8; 64];
        rng.try_fill(&mut key)?;

        // We can't create a master key directly from bytes so we convert it to a
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
        let account_name = AccountName::from(tagged("user").as_str());

        let server_registration = server_registration();
        let _ = self
            .db
            .create_account(&user_id, &account_name, &server_registration)
            .await?;

        Ok((user_id, account_name))
    }

    /// Retrieves a user from the database and ensures that it can be
    /// deserialized to the `User` type. Returns true if retrieval and
    /// deserialization were successful.
    pub async fn is_user_valid(&self, account_name: &AccountName) -> bool {
        match self.find_account(account_name).await {
            Ok(maybe_user) => maybe_user.is_some(),
            Err(_) => false,
        }
    }
}
