//! Integration tests for user objects in the database

use colored::Colorize;
use lock_keeper::types::database::user::{AccountName, UserId};
use lock_keeper_key_server::database::DataStore;
use rand::{rngs::StdRng, SeedableRng};

use crate::{
    config::TestFilters,
    error::Result,
    run_parallel,
    utils::{server_registration, tagged, TestResult},
};

use super::TestDatabase;

pub async fn run_tests(filters: &TestFilters) -> Result<Vec<TestResult>> {
    println!("{}", "Running user tests".cyan());

    let db = TestDatabase::connect().await?;
    let result = run_parallel!(
        filters,
        user_findable_by_account_name(db.clone()),
        user_findable_by_id(db.clone()),
        unique_indices_enforced(db.clone()),
        user_is_deleted(db.clone()),
        storage_key_is_set(db.clone())
    )?;

    Ok(result)
}

async fn user_findable_by_account_name(db: TestDatabase) -> Result<()> {
    let (_, account_name) = db.create_test_user().await?;

    let user = db.find_account(&account_name).await?.unwrap();
    assert_eq!(user.account_name, account_name);

    Ok(())
}

async fn user_findable_by_id(db: TestDatabase) -> Result<()> {
    let (user_id, account_name) = db.create_test_user().await?;

    let user = db.find_account(&account_name).await?.unwrap();
    assert_eq!(user.user_id, user_id);

    let user = db.find_account_by_id(&user_id).await?;
    assert!(user.is_some());

    let user = user.unwrap();
    assert_eq!(user.user_id, user_id);

    Ok(())
}

async fn unique_indices_enforced(db: TestDatabase) -> Result<()> {
    let mut rng = StdRng::from_entropy();

    // Add the "baseline" user.
    let user_id = UserId::new(&mut rng)?;
    let account_name = AccountName::from(tagged("user").as_str());

    let server_registration = server_registration();
    let _ = db
        .create_account(&user_id, &account_name, &server_registration)
        .await?;

    // Matching UserIds can't be added.
    let different_an = AccountName::from(tagged("user").as_str());
    assert!(db
        .create_account(&user_id, &different_an, &server_registration)
        .await
        .is_err());

    // Matching AccountNames can't be added.
    let different_uid = UserId::new(&mut rng)?;
    assert!(db
        .create_account(&different_uid, &account_name, &server_registration)
        .await
        .is_err());

    // Matching both can't be added.
    assert!(db
        .create_account(&user_id, &account_name, &server_registration)
        .await
        .is_err());

    Ok(())
}

async fn user_is_deleted(db: TestDatabase) -> Result<()> {
    let (user_id, _) = db.create_test_user().await?;

    // Ensure that the user was created
    let user = db.find_account_by_id(&user_id).await?;
    assert!(user.is_some());

    // Delete the user
    db.delete_account(&user_id).await?;

    // Ensure that the user was deleted
    let user = db.find_account_by_id(&user_id).await?;
    assert!(user.is_none());

    // Ensure that an error is returned if the user is deleted again
    let result = db.delete_account(&user_id).await;
    assert!(result.is_err());

    Ok(())
}

/// Test that `set_storage_key` works correctly
async fn storage_key_is_set(db: TestDatabase) -> Result<()> {
    let (user_id, account_name) = db.create_test_user().await?;

    // Ensure that the user was created an no storage key is set
    let user = db.find_account(&account_name).await?.unwrap();
    assert!(user.storage_key.is_none());

    // Create a storage key
    let (storage_key, _) = db.create_test_storage_key(&user_id)?;

    // Set storage key and check that it is correct in the database
    db.set_storage_key(&user_id, storage_key.clone()).await?;

    let user = db.find_account(&account_name).await?.unwrap();
    assert_eq!(user.storage_key, Some(storage_key.clone()));

    Ok(())
}
