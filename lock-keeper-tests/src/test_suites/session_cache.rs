//! Session cache integration tests.

use crate::{error::Result, run_parallel, utils::report_test_results, Config, TestResult};
use colored::Colorize;
use generic_array::GenericArray;
use lk_session_mongodb::{config::Config as SessionConfig, MongodbSessionCache};
use lock_keeper::{
    crypto::{OpaqueSessionKey, RemoteStorageKey},
    types::{database::user::UserId, operations::SessionId},
};
use lock_keeper_key_server::server::session_cache::{SessionCache, SessionCacheError};
use rand::{rngs::StdRng, SeedableRng};
use std::{str::FromStr, time::Duration};

const FILLER: u8 = 42;
const SEED: u64 = 1234;

struct TestState {
    remote_key: RemoteStorageKey,
    session_id: SessionId,
    session_key: OpaqueSessionKey,
    user_id: UserId,
}

pub async fn run_tests(config: &Config) -> Result<Vec<TestResult>> {
    println!("{}", "Running session cache tests".cyan());

    let results = run_parallel!(
        config.clone(),
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
pub async fn new_cache(db_name: &str, expiration: u32) -> Result<MongodbSessionCache> {
    let config_str = format!(
        r#"
mongodb_uri = "mongodb://localhost:27017"
db_name = "{}"
session_expiration = "{}s"
"#,
        db_name, expiration,
    );

    let config = SessionConfig::from_str(&config_str)?;
    let cache = MongodbSessionCache::new(config).await?;

    Ok(cache)
}

fn test_state(rng: &mut StdRng) -> Result<TestState> {
    Ok(TestState {
        remote_key: get_temp_remote_key(rng)?,
        session_id: get_temp_session_id(rng)?,
        session_key: get_temp_session_key()?,
        user_id: get_temp_user_id(rng)?,
    })
}

async fn key_does_not_exist() -> Result<()> {
    let mut rng = StdRng::seed_from_u64(SEED);
    let cache = new_cache("key_does_not_exist", 60).await?;
    let session_id = get_temp_session_id(&mut rng)?;
    let user_id = get_temp_user_id(&mut rng)?;

    match cache.find_session(session_id, user_id).await {
        Ok(_) => {
            panic!("Key should not exist.")
        }
        Err(e) => {
            assert_eq!(e, SessionCacheError::MissingSession);
        }
    }

    Ok(())
}

/// Ensure we can get the key back without encountering expiration error.
async fn get_key_back() -> Result<()> {
    let mut rng = StdRng::seed_from_u64(SEED);
    let cache = new_cache("get_key_back", 60).await?;
    let state = test_state(&mut rng)?;

    let encrypted_key = state
        .remote_key
        .encrypt_session_key(&mut rng, state.session_key)?;

    cache
        .create_session(
            state.session_id.clone(),
            state.user_id.clone(),
            encrypted_key,
        )
        .await?;

    // We got a key back.
    let _key_ref = cache.find_session(state.session_id, state.user_id).await?;
    Ok(())
}

/// Insert key twice and ensure code runs all the way.
async fn overwrite_existing_key() -> Result<()> {
    let mut rng = StdRng::seed_from_u64(SEED);
    let cache = new_cache("overwrite_existing_key", 60).await?;
    let state = test_state(&mut rng)?;

    let encrypted_key = state
        .remote_key
        .encrypt_session_key(&mut rng, state.session_key)?;
    cache
        .create_session(
            state.session_id.clone(),
            state.user_id.clone(),
            encrypted_key,
        )
        .await?;

    let second_key = get_temp_session_key()?;
    let second_encrypted_key = state.remote_key.encrypt_session_key(&mut rng, second_key)?;
    cache
        .create_session(state.session_id, state.user_id, second_encrypted_key)
        .await?;

    Ok(())
}

/// Test key expiration logic when enough time has passed that the key
/// should be expired.
async fn key_expired() -> Result<()> {
    // Keys expire instantly
    let mut rng = StdRng::seed_from_u64(SEED);
    let cache = new_cache("key_expired", 0).await?;
    let state = test_state(&mut rng)?;

    let encrypted_key = state
        .remote_key
        .encrypt_session_key(&mut rng, state.session_key)?;
    cache
        .create_session(
            state.session_id.clone(),
            state.user_id.clone(),
            encrypted_key,
        )
        .await?;

    // Verify key is expired.
    match cache.find_session(state.session_id, state.user_id).await {
        Ok(_) => panic!("Key should be expired"),
        Err(e) => {
            assert_eq!(
                e,
                SessionCacheError::ExpiredSession,
                "Unexpected error returned."
            )
        }
    }
    Ok(())
}

/// Key expires after a short time.
async fn key_expired2() -> Result<()> {
    // Handle a longer timeout.
    let mut rng = StdRng::seed_from_u64(SEED);
    let cache = new_cache("key_expired2", 1).await?;
    let state = test_state(&mut rng)?;

    let encrypted_key = state
        .remote_key
        .encrypt_session_key(&mut rng, state.session_key)?;
    cache
        .create_session(
            state.session_id.clone(),
            state.user_id.clone(),
            encrypted_key,
        )
        .await?;

    // Sleep for a while so key expires.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Verify key is expired.
    match cache.find_session(state.session_id, state.user_id).await {
        Ok(_) => panic!("Key should be expired"),
        Err(e) => {
            assert_eq!(
                e,
                SessionCacheError::ExpiredSession,
                "Unexpected error returned."
            )
        }
    }
    Ok(())
}

fn get_temp_session_key() -> Result<OpaqueSessionKey> {
    let key = OpaqueSessionKey::try_from(GenericArray::from([FILLER; 64]))?;
    Ok(key)
}

fn get_temp_session_id(rng: &mut StdRng) -> Result<SessionId> {
    // Deterministic seed. No need for our test to be nondeterministic.
    Ok(SessionId::new(rng)?)
}

fn get_temp_user_id(rng: &mut StdRng) -> Result<UserId> {
    // Deterministic seed. No need for our test to be nondeterministic.
    Ok(UserId::new(rng)?)
}

fn get_temp_remote_key(rng: &mut StdRng) -> Result<RemoteStorageKey> {
    // Deterministic seed. No need for our test to be nondeterministic.
    Ok(RemoteStorageKey::generate(rng))
}
