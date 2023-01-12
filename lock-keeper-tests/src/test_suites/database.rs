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
    crypto::{
        Encrypted, Import, KeyId, MasterKey, RemoteStorageKey, Secret, SigningKeyPair, StorageKey,
    },
    types::database::{
        secrets::StoredSecret,
        user::{AccountName, UserId},
    },
};
use lock_keeper_key_server::database::DataStore;
use lock_keeper_postgres::{Config, ConfigFile as DatabaseConfigFile, PostgresDB, PostgresError};
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::utils::{server_registration, tagged};

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
        let config: Config = config_file.try_into().map_err(PostgresError::ConfigError)?;
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

    /// Generate and store `n` random secrets in our database.
    async fn create_random_arbitrary_secrets(
        &self,
        n: usize,
        user_id: &UserId,
    ) -> Result<Vec<KeyId>> {
        let (encrypted_storage_key, master_key) = self.create_test_storage_key(user_id)?;
        let storage_key = encrypted_storage_key.decrypt_storage_key(master_key, user_id)?;
        let mut rng = StdRng::from_entropy();

        let mut key_ids: Vec<KeyId> = vec![];
        for _ in 0..n {
            let key_id = self
                .add_arbitrary_secret(&mut rng, &storage_key, user_id)
                .await?;
            key_ids.push(key_id);
        }

        Ok(key_ids)
    }

    /// Store a new arbitrary secret in database.
    async fn add_arbitrary_secret(
        &self,
        rng: &mut StdRng,
        storage_key: &StorageKey,
        user_id: &UserId,
    ) -> Result<KeyId> {
        let key_id = KeyId::generate(rng, user_id)?;
        let (_, encrypted) = Secret::create_and_encrypt(rng, storage_key, user_id, &key_id)?;

        let secret =
            StoredSecret::from_arbitrary_secret(key_id.clone(), user_id.clone(), encrypted)?;
        self.db.add_secret(secret).await?;

        Ok(key_id)
    }

    async fn import_signing_key(&self, rng: &mut StdRng, user_id: &UserId) -> Result<KeyId> {
        let key_id = KeyId::generate(rng, user_id)?;
        let random_bytes = rand::thread_rng().gen::<[u8; 32]>().to_vec();
        let import = Import::new(random_bytes)?;
        let signing_key = import.into_signing_key(user_id, &key_id)?;

        let encryption_key = RemoteStorageKey::generate(rng);
        // encrypt key_pair
        let encrypted_key_pair = encryption_key.encrypt_signing_key_pair(rng, signing_key)?;

        let secret = StoredSecret::from_remote_signing_key_pair(
            key_id.clone(),
            encrypted_key_pair,
            user_id.clone(),
        )?;
        self.add_secret(secret).await?;

        Ok(key_id)
    }

    async fn remote_generate_signing_key(
        &self,
        rng: &mut StdRng,
        user_id: &UserId,
    ) -> Result<KeyId> {
        let key_id = KeyId::generate(rng, user_id)?;
        let signing_key = SigningKeyPair::remote_generate(rng, user_id, &key_id);

        let encryption_key = RemoteStorageKey::generate(rng);

        // encrypt key_pair
        let encrypted_key_pair = encryption_key.encrypt_signing_key_pair(rng, signing_key)?;

        let secret = StoredSecret::from_remote_signing_key_pair(
            key_id.clone(),
            encrypted_key_pair,
            user_id.clone(),
        )?;
        self.add_secret(secret).await?;
        Ok(key_id)
    }
}
