//! Integration tests for secret objects in the database

use colored::Colorize;
use lock_keeper_key_server::database::{DataStore, SecretFilter};
use lock_keeper_postgres::PostgresError;
use rand::{rngs::StdRng, SeedableRng};

use crate::{config::TestFilters, error::Result, run_parallel, utils::TestResult};

use super::TestDatabase;

pub async fn run_tests(filters: &TestFilters) -> Result<Vec<TestResult>> {
    println!("{}", "Running secret tests".cyan());

    let db = TestDatabase::connect().await?;
    let result = run_parallel!(
        filters,
        user_is_serializable_after_adding_secrets(db.clone()),
        cannot_get_another_users_secrets(db.clone()),
        incorrect_key_type_specified(db.clone()),
    )?;

    Ok(result)
}

async fn user_is_serializable_after_adding_secrets(db: TestDatabase) -> Result<()> {
    // Add a user and get their storage key
    let (user_id, account_name) = db.create_test_user().await?;
    let (encrypted_storage_key, master_key) = db.create_test_storage_key(&user_id)?;
    let storage_key = encrypted_storage_key.decrypt_storage_key(master_key, &user_id)?;

    let mut rng = StdRng::from_entropy();

    // Create secret of each type and make sure user is valid after each
    let _ = db
        .add_arbitrary_secret(&mut rng, &storage_key, &user_id)
        .await?;
    assert!(db.is_user_valid(&account_name).await);

    let _ = db.import_signing_key(&mut rng, &user_id).await?;
    assert!(db.is_user_valid(&account_name).await);

    let _ = db.remote_generate_signing_key(&mut rng, &user_id).await?;
    assert!(db.is_user_valid(&account_name).await);

    Ok(())
}

async fn cannot_get_another_users_secrets(db: TestDatabase) -> Result<()> {
    let mut rng = StdRng::from_entropy();

    // Add a user and get their storage key
    let (user, _) = db.create_test_user().await?;
    let (encrypted_storage_key, master_key) = db.create_test_storage_key(&user)?;
    let storage_key = encrypted_storage_key.decrypt_storage_key(master_key, &user)?;

    // Add another user
    let (other_user, _) = db.create_test_user().await?;

    // Create secret of each type for first user
    let key_id1 = db
        .add_arbitrary_secret(&mut rng, &storage_key, &user)
        .await?;
    let key_id2 = db.import_signing_key(&mut rng, &user).await?;
    let key_id3 = db.remote_generate_signing_key(&mut rng, &user).await?;

    // Attempt to retrieve each secret using other user's ID. Rust does not support
    // async closures. So we do not refactor this code.
    assert!(matches!(
        db.db
            .get_secret(&other_user, &key_id1, Default::default())
            .await,
        Err(PostgresError::IncorrectAssociatedKeyData)
    ));
    assert!(matches!(
        db.db
            .get_secret(&other_user, &key_id2, Default::default())
            .await,
        Err(PostgresError::IncorrectAssociatedKeyData)
    ));
    assert!(matches!(
        db.db
            .get_secret(&other_user, &key_id3, Default::default())
            .await,
        Err(PostgresError::IncorrectAssociatedKeyData)
    ));

    Ok(())
}

/// An error is returned if a wrong key type is specified.
async fn incorrect_key_type_specified(db: TestDatabase) -> Result<()> {
    let mut rng = StdRng::from_entropy();

    // Add a user and get their storage key
    let (user, _) = db.create_test_user().await?;
    let key_id = db.import_signing_key(&mut rng, &user).await?;

    assert!(
        db.db
            .get_secret(&user, &key_id, Default::default())
            .await
            .is_ok(),
        "Failed to fetch just stored secret."
    );

    // Now fetch secret with wrong key type. ("Foo" key type does not exist).
    assert!(matches!(
        db.db
            .get_secret(&user, &key_id, SecretFilter::secret_type("Foo"))
            .await,
        Err(PostgresError::IncorrectAssociatedKeyData)
    ));

    Ok(())
}
