//! Integration tests for user objects in the database

use std::str::FromStr;

use colored::Colorize;
use lock_keeper::types::database::user::{AccountName, User, UserId};
use lock_keeper_key_server::database::DataStore;
use lock_keeper_mongodb::error::Error;
use rand::{rngs::StdRng, SeedableRng};

use crate::{
    config::TestFilters,
    error::Result,
    run_parallel,
    test_suites::database::USERS_TABLE,
    utils::{server_registration, tagged, TestResult},
};

use super::TestDatabase;

pub async fn run_tests(filters: &TestFilters) -> Result<Vec<TestResult>> {
    println!("{}", "Running user tests".cyan());

    let db = TestDatabase::new("user_tests").await?;
    let result = run_parallel!(
        filters,
        user_findable_by_account_name(db.clone()),
        user_findable_by_id(db.clone()),
        multiple_connections_do_not_overwrite_db(),
        unique_indices_enforced(db.clone()),
        user_is_deleted(db.clone()),
        storage_key_is_set(db.clone())
    )?;

    db.drop().await?;

    Ok(result)
}

async fn user_findable_by_account_name(db: TestDatabase) -> Result<()> {
    let (_, account_name) = db.create_test_user().await?;

    let user = db.find_user(&account_name).await?.unwrap();
    assert_eq!(user.account_name, account_name);

    Ok(())
}

async fn user_findable_by_id(db: TestDatabase) -> Result<()> {
    let (user_id, account_name) = db.create_test_user().await?;

    let user = db.find_user(&account_name).await?.unwrap();
    assert_eq!(user.user_id, user_id);

    let user = db.find_user_by_id(&user_id).await?;
    assert!(user.is_some());

    let user = user.unwrap();
    assert_eq!(user.user_id, user_id);

    Ok(())
}

async fn multiple_connections_do_not_overwrite_db() -> Result<()> {
    let db = TestDatabase::new("multiple_connections_do_not_overwrite_db").await?;

    let mut rng = StdRng::from_entropy();

    let server_registration = server_registration();

    // Add two users
    let uid1 = UserId::new(&mut rng)?;
    let _ = db
        .create_user(
            &uid1,
            &AccountName::from_str(&tagged("user"))?,
            &server_registration,
        )
        .await?;

    let uid2 = UserId::new(&mut rng)?;
    let _ = db
        .create_user(
            &uid2,
            &AccountName::from_str(&tagged("user"))?,
            &server_registration,
        )
        .await?;

    // Check that the database holds two users.
    assert_eq!(
        2,
        db.mongo
            .collection::<User>(USERS_TABLE)
            .estimated_document_count(None)
            .await?
    );

    // Reconnect and make sure it still has two users.
    let reconnected_db = TestDatabase::from_db_name(&db.config.db_name).await?;
    assert_eq!(
        2,
        reconnected_db
            .mongo
            .collection::<User>(USERS_TABLE)
            .estimated_document_count(None)
            .await?
    );

    Ok(())
}

async fn unique_indices_enforced(db: TestDatabase) -> Result<()> {
    let mut rng = StdRng::from_entropy();

    // Add the "baseline" user.
    let user_id = UserId::new(&mut rng)?;
    let account_name = AccountName::from_str(&tagged("user"))?;

    let server_registration = server_registration();
    let _ = db
        .create_user(&user_id, &account_name, &server_registration)
        .await?;

    // Matching UserIds can't be added.
    let different_an = AccountName::from_str(&tagged("user"))?;
    assert!(db
        .create_user(&user_id, &different_an, &server_registration)
        .await
        .is_err());

    // Matching AccountNames can't be added.
    let different_uid = UserId::new(&mut rng)?;
    assert!(db
        .create_user(&different_uid, &account_name, &server_registration)
        .await
        .is_err());

    // Matching both can't be added.
    assert!(db
        .create_user(&user_id, &account_name, &server_registration)
        .await
        .is_err());

    Ok(())
}

async fn user_is_deleted(db: TestDatabase) -> Result<()> {
    let (user_id, _) = db.create_test_user().await?;

    // Ensure that the user was created
    let user = db.find_user_by_id(&user_id).await?;
    assert!(user.is_some());

    // Delete the user
    db.delete_user(&user_id).await?;

    // Ensure that the user was deleted
    let user = db.find_user_by_id(&user_id).await?;
    assert!(user.is_none());

    // Ensure that an error is returned if the user is deleted again
    let result = db.delete_user(&user_id).await;
    assert!(matches!(result, Err(Error::InvalidAccount)));

    Ok(())
}

/// Test that `set_storage_key` works correctly
async fn storage_key_is_set(db: TestDatabase) -> Result<()> {
    let (user_id, account_name) = db.create_test_user().await?;

    // Ensure that the user was created an no storage key is set
    let user = db.find_user(&account_name).await?.unwrap();
    assert!(user.storage_key.is_none());

    // Create a storage key
    let (storage_key, _) = db.create_test_storage_key(&user_id)?;

    // Set storage key and check that it is correct in the database
    db.set_storage_key(&user_id, storage_key.clone()).await?;

    let user = db.find_user(&account_name).await?.unwrap();
    assert_eq!(user.storage_key, Some(storage_key.clone()));

    Ok(())
}
