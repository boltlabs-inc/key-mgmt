use lock_keeper::{crypto::OpaqueSessionKey, types::database::user::UserId};
use lock_keeper_key_server::server::session_key_cache::{SessionCache, SessionCacheError};
use std::{
    collections::{hash_map::Entry, HashMap},
    time::{Duration, Instant},
};
use zeroize::Zeroize;

/// Cache holding session keys, per user, after authentication. Maps
/// [`UserId`]s to [`OpaqueSessionKey`]s. Keys are tagged with a timestamp. A
/// key is considered invalid after the `expiration` time has elapsed.
pub struct HashmapKeyCache {
    /// Map from user ids to (timestamp, keys).
    cache: HashMap<UserId, (Instant, OpaqueSessionKey)>,
    /// Time a key is considered valid for.
    expiration: Duration,
}

impl Drop for HashmapKeyCache {
    fn drop(&mut self) {
        for value in self.cache.values_mut() {
            value.1.zeroize();
        }
    }
}

impl HashmapKeyCache {
    /// Create a new [`HashmapKeyCache`] with the given `expiration` interval.
    pub fn new(expiration: Duration) -> Self {
        Self {
            cache: HashMap::new(),
            expiration,
        }
    }
}

#[allow(unused)]
impl SessionCache for HashmapKeyCache {
    /// Add a new session key for the specified user. The previous key for that
    /// will be overwritten.
    fn create_session(&mut self, user: UserId, key: OpaqueSessionKey) {
        let existing = self.cache.insert(user, (Instant::now(), key));

        if existing.is_some() {
            tracing::info!("Previous session key overwritten.");
        }
    }

    /// Get the session key for the specified user, if one exists.
    /// This function checks if the key has expired and returns an error
    /// instead.
    fn find_session(&mut self, user: UserId) -> Result<OpaqueSessionKey, SessionCacheError> {
        match self.cache.entry(user) {
            Entry::Occupied(entry) => {
                let (timestamp, key) = entry.get();

                // If key is expired remove it and report an error.
                if timestamp.elapsed() >= self.expiration {
                    tracing::info!("Session key is expired.");
                    // We don't care about this expired key.
                    let _ = entry.remove();
                    return Err(SessionCacheError::ExpiredSessionKey);
                }
                Ok(key.clone())
            }
            Entry::Vacant(_) => Err(SessionCacheError::MissingSessionKey),
        }
    }

    /// Remove the session key for this user from the hashmap.
    fn delete_session(&mut self, user_id: UserId) -> Result<(), SessionCacheError> {
        if let Entry::Occupied(entry) = self.cache.entry(user_id) {
            let _ = entry.remove();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::HashmapKeyCache;
    use generic_array::GenericArray;
    use lock_keeper::{crypto::OpaqueSessionKey, types::database::user::UserId};
    use lock_keeper_key_server::{
        server::session_key_cache::{SessionCache, SessionCacheError},
        LockKeeperServerError,
    };
    use rand::{prelude::StdRng, SeedableRng};
    use std::{thread, time::Duration};

    type Result<T> = std::result::Result<T, LockKeeperServerError>;

    const TEST_EXPIRATION_TIME: Duration = Duration::from_secs(60);

    #[test]
    fn key_does_not_exist() -> Result<()> {
        let mut cache = HashmapKeyCache::new(TEST_EXPIRATION_TIME);
        let id = get_temp_user_id()?;

        match cache.find_session(id) {
            Ok(_) => {
                panic!("Key should not exist.")
            }
            Err(e) => {
                assert_eq!(e, SessionCacheError::MissingSessionKey);
            }
        }

        Ok(())
    }

    /// Ensure we can get the key back without encountering expiration error.
    #[test]
    fn get_key_back() -> Result<()> {
        let mut cache = HashmapKeyCache::new(TEST_EXPIRATION_TIME);
        let id = get_temp_user_id()?;
        let key = get_temp_session_key()?;

        cache.create_session(id.clone(), key);

        // We got a key back.
        let _key_ref = cache.find_session(id)?;
        Ok(())
    }

    /// Insert key twice and ensure code runs all the way.
    #[test]
    fn overwrite_existing_key() -> Result<()> {
        let mut cache = HashmapKeyCache::new(TEST_EXPIRATION_TIME);
        let id = get_temp_user_id()?;
        let key = get_temp_session_key()?;

        cache.create_session(id.clone(), key);
        let second_key = get_temp_session_key()?;
        cache.create_session(id, second_key);

        Ok(())
    }

    /// Test key expiration logic when enough time has passed that the key
    /// should be expired.
    #[test]
    fn key_expired() -> Result<()> {
        // Keys expire instantly
        let mut cache = HashmapKeyCache::new(Duration::from_secs(0));
        let id = get_temp_user_id()?;
        let key = get_temp_session_key()?;
        cache.create_session(id.clone(), key);

        // Verify key is expired.
        match cache.find_session(id) {
            Ok(_) => panic!("Key should be expired"),
            Err(e) => {
                assert_eq!(
                    e,
                    SessionCacheError::ExpiredSessionKey,
                    "Unexpected error returned."
                )
            }
        }
        Ok(())
    }

    /// Longer running test. Don't always run.
    #[test]
    #[ignore]
    fn key_expired2() -> Result<()> {
        // Handle a longer timeout.
        let mut cache = HashmapKeyCache::new(Duration::from_millis(10));
        let id = get_temp_user_id()?;
        let key = get_temp_session_key()?;
        cache.create_session(id.clone(), key);

        // Sleep for a while so key expires.
        thread::sleep(Duration::from_millis(10));

        // Verify key is expired.
        match cache.find_session(id) {
            Ok(_) => panic!("Key should be expired"),
            Err(e) => {
                assert_eq!(
                    e,
                    SessionCacheError::ExpiredSessionKey,
                    "Unexpected error returned."
                )
            }
        }
        Ok(())
    }

    fn get_temp_session_key() -> Result<OpaqueSessionKey> {
        const FILLER: u8 = 42;
        let key = OpaqueSessionKey::try_from(GenericArray::from([FILLER; 64]))?;
        Ok(key)
    }

    fn get_temp_user_id() -> Result<UserId> {
        // Deterministic seed. No need for our test to be nondeterministic.
        const SEED: u64 = 1234;
        let mut rng = StdRng::seed_from_u64(SEED);
        Ok(UserId::new(&mut rng)?)
    }
}
