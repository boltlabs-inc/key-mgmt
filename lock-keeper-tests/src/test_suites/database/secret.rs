//! Integration tests for secret objects in the database

use colored::Colorize;
use lock_keeper_client::lock_keeper::{
    crypto::{DataBlob, Encrypted},
    LockKeeperError,
};
use lock_keeper_key_server::server::database::{DataStore, DatabaseError, SecretFilter};
use rand::{rngs::StdRng, SeedableRng};

use crate::{config::TestFilters, error::Result, run_parallel, utils::TestResult};

use super::TestDatabase;
use lock_keeper_client::lock_keeper::types::database::secrets::secret_types::SERVER_ENCRYPTED_BLOB;

pub async fn run_tests(filters: &TestFilters) -> Result<Vec<TestResult>> {
    println!("{}", "Running secret tests".cyan());

    let db = TestDatabase::connect().await?;
    let result = run_parallel!(
        filters,
        cannot_get_another_users_secrets(db.clone()),
        incorrect_key_type_specified(db.clone()),
        store_data_blob_identity(db.clone())
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
    let (key_id4, _) = db.store_server_encrypted_blob(&mut rng, &account).await?;

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
    assert!(matches!(
        db.db
            .get_secret(other_account.account_id, &key_id4, Default::default())
            .await,
        Err(DatabaseError::IncorrectKeyMetadata)
    ));

    Ok(())
}

/// Storing and retrieving an encrypted data blob returns the same stored
/// secret.
async fn store_data_blob_identity(db: TestDatabase) -> Result<()> {
    let mut rng = StdRng::from_entropy();

    // Add a user and get their storage key
    let account = db.create_test_user().await?;
    let (key_id, remote_storage_key) = db.store_server_encrypted_blob(&mut rng, &account).await?;

    let stored_secret = db
        .get_server_encrypted_blob(account.account_id, &key_id)
        .await?;

    let encrypted_blob: Encrypted<DataBlob> =
        serde_json::from_slice(&stored_secret.bytes).map_err(LockKeeperError::SerdeJson)?;
    let blob: DataBlob = encrypted_blob.decrypt_data_blob(&remote_storage_key)?;
    assert_eq!(
        blob.blob_data(),
        TestDatabase::blob_test_data(),
        "Blob data matches after storing and retrieving."
    );
    assert_eq!(
        stored_secret.account_id, account.account_id,
        "Account ID matches after storing and retrieving."
    );
    assert_eq!(
        stored_secret.key_id, key_id,
        "Key ID matches after storing and retrieving."
    );
    assert_eq!(
        stored_secret.secret_type, SERVER_ENCRYPTED_BLOB,
        "Secret type matches after storing and retrieving."
    );

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
