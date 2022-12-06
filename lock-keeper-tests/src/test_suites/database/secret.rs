//! Integration tests for secret objects in the database

use colored::Colorize;
use lock_keeper::{
    crypto::{
        Import, KeyId, PlaceholderEncryptedSigningKeyPair, Secret, SigningKeyPair, StorageKey,
    },
    types::database::{secrets::StoredSecret, user::UserId},
};
use lock_keeper_key_server::database::DataStore;
use lock_keeper_mongodb::Database;
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::{error::Result, run_parallel, utils::TestResult, Config};

use super::TestDatabase;

pub async fn run_tests(config: Config) -> Result<Vec<TestResult>> {
    println!("{}", "Running secret tests".cyan());

    let db = TestDatabase::new("secret_tests").await?;
    let result = run_parallel!(
        config.clone(),
        user_is_serializable_after_adding_secrets(db.clone()),
        cannot_get_another_users_secrets(db.clone()),
    )?;

    db.drop().await?;

    Ok(result)
}

async fn user_is_serializable_after_adding_secrets(db: TestDatabase) -> Result<()> {
    // Add a user and get their storage key
    let (user_id, account_name) = db.create_test_user().await?;
    let (encrypted_storage_key, master_key) = db.create_test_storage_key(&user_id)?;
    let storage_key = encrypted_storage_key.decrypt_storage_key(master_key, &user_id)?;

    // Init RNG for test
    let mut rng = StdRng::from_entropy();

    // Create secret of each type and make sure user is valid after each
    let _ = add_arbitrary_secret(&db, &mut rng, &storage_key, &user_id).await;
    assert!(db.is_user_valid(&account_name).await);

    let _ = import_signing_key(&db, &mut rng, &user_id).await;
    assert!(db.is_user_valid(&account_name).await);

    let _ = remote_generate_signing_key(&db, &mut rng, &user_id).await;
    assert!(db.is_user_valid(&account_name).await);

    Ok(())
}

async fn cannot_get_another_users_secrets(db: TestDatabase) -> Result<()> {
    // Init RNG for test
    let mut rng = StdRng::from_entropy();

    // Add a user and get their storage key
    let (user_id, _) = db.create_test_user().await?;
    let (encrypted_storage_key, master_key) = db.create_test_storage_key(&user_id)?;
    let storage_key = encrypted_storage_key.decrypt_storage_key(master_key, &user_id)?;

    // Add another user
    let (other_user, _) = db.create_test_user().await?;

    // Create secret of each type for first user
    let key_id1 = add_arbitrary_secret(&db, &mut rng, &storage_key, &user_id).await?;
    let key_id2 = import_signing_key(&db, &mut rng, &user_id).await?;
    let key_id3 = remote_generate_signing_key(&db, &mut rng, &user_id).await?;

    // Attempt to retrieve each secret using other user's ID
    assert!(db
        .db
        .get_user_secret(&other_user, &key_id1, Default::default())
        .await
        .is_err());
    assert!(db
        .db
        .get_user_secret(&other_user, &key_id2, Default::default())
        .await
        .is_err());
    assert!(db
        .db
        .get_user_secret(&other_user, &key_id3, Default::default())
        .await
        .is_err());

    Ok(())
}

async fn add_arbitrary_secret(
    db: &Database,
    rng: &mut StdRng,
    storage_key: &StorageKey,
    user_id: &UserId,
) -> Result<KeyId> {
    let key_id = KeyId::generate(rng, user_id)?;
    let (_, encrypted) = Secret::create_and_encrypt(rng, storage_key, user_id, &key_id)?;

    let secret = StoredSecret::from_arbitrary_secret(key_id.clone(), encrypted)?;
    db.add_user_secret(user_id, secret).await?;

    Ok(key_id)
}

async fn import_signing_key(db: &Database, rng: &mut StdRng, user_id: &UserId) -> Result<KeyId> {
    let key_id = KeyId::generate(rng, user_id)?;
    let random_bytes = rand::thread_rng().gen::<[u8; 32]>().to_vec();
    let import = Import::new(random_bytes)?;
    let signing_key = import.into_signing_key(user_id, &key_id)?;

    let secret = StoredSecret::from_remote_signing_key_pair(
        key_id.clone(),
        PlaceholderEncryptedSigningKeyPair::from(signing_key),
    )?;
    db.add_user_secret(user_id, secret).await?;

    Ok(key_id)
}

async fn remote_generate_signing_key(
    db: &Database,
    rng: &mut StdRng,
    user_id: &UserId,
) -> Result<KeyId> {
    let key_id = KeyId::generate(rng, user_id)?;
    let signing_key = SigningKeyPair::remote_generate(rng, user_id, &key_id);

    let secret = StoredSecret::from_remote_signing_key_pair(
        key_id.clone(),
        PlaceholderEncryptedSigningKeyPair::from(signing_key),
    )?;
    db.add_user_secret(user_id, secret).await?;
    Ok(key_id)
}
