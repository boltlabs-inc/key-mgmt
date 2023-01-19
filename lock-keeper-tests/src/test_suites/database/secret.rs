//! Integration tests for secret objects in the database

use colored::Colorize;
use lock_keeper_key_server::server::database::{DataStore, DatabaseError, SecretFilter};
use rand::{rngs::StdRng, SeedableRng};

use crate::{config::TestFilters, error::Result, run_parallel, utils::TestResult};

use super::TestDatabase;

pub async fn run_tests(filters: &TestFilters) -> Result<Vec<TestResult>> {
    println!("{}", "Running secret tests".cyan());

    let db = TestDatabase::connect().await?;
    let result = run_parallel!(
        filters,
        cannot_get_another_users_secrets(db.clone()),
        incorrect_key_type_specified(db.clone()),
    )?;

    Ok(result)
}

async fn cannot_get_another_users_secrets(db: TestDatabase) -> Result<()> {
    let mut rng = StdRng::from_entropy();

    // Add a user and get their storage key
    let account = db.create_test_user().await?;
    let (encrypted_storage_key, master_key) = db.create_test_storage_key(&account.user_id)?;
    let storage_key = encrypted_storage_key.decrypt_storage_key(master_key, &account.user_id)?;

    // Add another user
    let other_account = db.create_test_user().await?;

    // Create secret of each type for first user
    let key_id1 = db
        .add_arbitrary_secret(&mut rng, &storage_key, &account)
        .await?;
    let key_id2 = db.import_signing_key(&mut rng, &account).await?;
    let key_id3 = db.remote_generate_signing_key(&mut rng, &account).await?;

    // Attempt to retrieve each secret using other user's ID. Rust does not support
    // async closures. So we do not refactor this code.
    assert!(matches!(
        db.db
            .get_secret(other_account.account_id, &key_id1, Default::default())
            .await,
        Err(DatabaseError::IncorrectKeyMetadata)
    ));
    assert!(matches!(
        db.db
            .get_secret(other_account.account_id, &key_id2, Default::default())
            .await,
        Err(DatabaseError::IncorrectKeyMetadata)
    ));
    assert!(matches!(
        db.db
            .get_secret(other_account.account_id, &key_id3, Default::default())
            .await,
        Err(DatabaseError::IncorrectKeyMetadata)
    ));

    Ok(())
}

/// An error is returned if a wrong key type is specified.
async fn incorrect_key_type_specified(db: TestDatabase) -> Result<()> {
    let mut rng = StdRng::from_entropy();

    // Add a user and get their storage key
    let account = db.create_test_user().await?;
    let key_id = db.import_signing_key(&mut rng, &account).await?;

    assert!(
        db.db
            .get_secret(account.id(), &key_id, Default::default())
            .await
            .is_ok(),
        "Failed to fetch just stored secret."
    );

    // Now fetch secret with wrong key type. ("Foo" key type does not exist).
    assert!(matches!(
        db.db
            .get_secret(account.id(), &key_id, SecretFilter::secret_type("Foo"))
            .await,
        Err(DatabaseError::IncorrectKeyMetadata)
    ));

    Ok(())
}
