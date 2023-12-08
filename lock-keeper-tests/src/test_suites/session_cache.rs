//! Session cache integration tests.

use crate::{
    config::TestFilters, error::Result, run_parallel, utils::report_test_results, TestResult,
};
use colored::Colorize;
use generic_array::GenericArray;
use lock_keeper_client::lock_keeper::{
    crypto::{OpaqueSessionKey, RemoteStorageKey},
    types::database::account::AccountId,
};
use lock_keeper_key_server::server::session_cache::{SessionCache, SessionCacheError};
use lock_keeper_session_cache_sql::{config::Config as SessionConfig, PostgresSessionCache};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{str::FromStr, time::Duration};
use uuid::Uuid;

const FILLER: u8 = 42;
const SEED: u64 = 1234;

struct TestState {
    remote_key: RemoteStorageKey,
    session_key: OpaqueSessionKey,
    account_id: AccountId,
}

pub async fn run_tests(filters: &TestFilters) -> Result<Vec<TestResult>> {
    println!("{}", "Running session cache tests".cyan());

    let results = run_parallel!(
        filters,
        key_does_not_exist(),
        get_key_back(),
        overwrite_existing_key(),
        key_expired(),
        key_expired2(),
    )?;

    println!("session cache tests: {}", report_test_results(&results));

    Ok(results)
}

/// Create a new test database with random characters appended to name.
/// This is what you probably want to use.
pub async fn new_cache(expiration: &str) -> Result<PostgresSessionCache> {
    let config_str = format!(
        r#"
        username = 'test'
        password = 'test_password'
        address = 'localhost:5432'
        db_name = 'test'
        min_connections = 2
        max_connections = 5
        connection_retries = 5
        connection_retry_delay = "5s"
        connection_timeout = "3s"
        session_expiration = "{expiration}"
        "#,
    );

    let config = SessionConfig::from_str(&config_str)?;
    let cache = PostgresSessionCache::connect(config).await?;

    Ok(cache)
}

fn test_state(rng: &mut StdRng) -> Result<TestState> {
    Ok(TestState {
        remote_key: get_temp_remote_key(rng)?,
        session_key: get_temp_session_key()?,
        account_id: get_temp_account_id(rng),
    })
}

async fn key_does_not_exist() -> Result<()> {
    let cache = new_cache("60s").await?;
    let session_id = get_temp_session_id();

    match cache.find_session(session_id).await {
        Ok(_) => {
            panic!("Key should not exist.")
        }
        Err(e) => {
            assert!(matches!(e, SessionCacheError::MissingSession));
        }
    }

    Ok(())
}

/// Ensure we can get the key back without encountering expiration error.
async fn get_key_back() -> Result<()> {
    let mut rng = StdRng::seed_from_u64(SEED);
    let cache = new_cache("60s").await?;
    let state = test_state(&mut rng)?;

    let encrypted_key = state
        .remote_key
        .encrypt_session_key(&mut rng, state.session_key)?;

    let session_id = cache
        .create_session(state.account_id, encrypted_key)
        .await?;

    // We got a key back.
    let _key_ref = cache.find_session(session_id).await?;
    Ok(())
}

/// Insert key twice and ensure code runs all the way.
async fn overwrite_existing_key() -> Result<()> {
    let mut rng = StdRng::seed_from_u64(SEED);
    let cache = new_cache("60s").await?;
    let state = test_state(&mut rng)?;

    let encrypted_key = state
        .remote_key
        .encrypt_session_key(&mut rng, state.session_key)?;
    cache
        .create_session(state.account_id, encrypted_key)
        .await?;

    let second_key = get_temp_session_key()?;
    let second_encrypted_key = state.remote_key.encrypt_session_key(&mut rng, second_key)?;
    cache
        .create_session(state.account_id, second_encrypted_key)
        .await?;

    Ok(())
}

/// Test key expiration logic when enough time has passed that the key
/// should be expired.
async fn key_expired() -> Result<()> {
    // Keys expire instantly
    let mut rng = StdRng::seed_from_u64(SEED);
    let cache = new_cache("0s").await?;
    let state = test_state(&mut rng)?;

    let encrypted_key = state
        .remote_key
        .encrypt_session_key(&mut rng, state.session_key)?;
    let session_id = cache
        .create_session(state.account_id, encrypted_key)
        .await?;

    // Verify key is expired.
    match cache.find_session(session_id).await {
        Ok(_) => panic!("Key should be expired"),
        Err(e) => {
            assert!(
                matches!(e, SessionCacheError::ExpiredSession),
                "Unexpected error returned"
            );
        }
    }
    Ok(())
}

/// Key expires after a short time.
async fn key_expired2() -> Result<()> {
    // Handle a longer timeout.
    let mut rng = StdRng::seed_from_u64(SEED);
    let cache = new_cache("1s").await?;
    let state = test_state(&mut rng)?;

    let encrypted_key = state
        .remote_key
        .encrypt_session_key(&mut rng, state.session_key)?;
    let session_id = cache
        .create_session(state.account_id, encrypted_key)
        .await?;

    // Sleep for a while so key expires.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Verify key is expired.
    match cache.find_session(session_id).await {
        Ok(_) => panic!("Key should be expired"),
        Err(e) => {
            assert!(
                matches!(e, SessionCacheError::ExpiredSession),
                "Unexpected error returned"
            );
        }
    }
    Ok(())
}

fn get_temp_session_key() -> Result<OpaqueSessionKey> {
    let key = OpaqueSessionKey::try_from(GenericArray::from([FILLER; 64]))?;
    Ok(key)
}

fn get_temp_session_id() -> Uuid {
    // Deterministic seed. No need for our test to be nondeterministic.
    Uuid::new_v4()
}

fn get_temp_account_id(rng: &mut StdRng) -> AccountId {
    let id = rng.next_u64() as i64;
    id.into()
}

fn get_temp_remote_key(rng: &mut StdRng) -> Result<RemoteStorageKey> {
    // Deterministic seed. No need for our test to be nondeterministic.
    Ok(RemoteStorageKey::generate(rng))
}
