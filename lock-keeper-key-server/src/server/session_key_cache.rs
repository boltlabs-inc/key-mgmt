use lock_keeper::{
    crypto::OpaqueSessionKey,
    types::{database::user::UserId, operations::RequestMetadata},
};
use std::collections::hash_map::Entry;

use std::collections::HashMap;

use crate::{database::DataStore, LockKeeperServerError};
use lock_keeper::types::operations::ClientAction;
use std::time::{Duration, Instant};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error, PartialOrd, PartialEq, Eq)]
pub enum SessionKeyCacheError {
    #[error("TODO")]
    SessionKeyExists,
    #[error("Session key has expired.")]
    ExpiredSessionKey,
    #[error("No session key for this user.")]
    MissingSessionKey,
    #[error("An invariant of this type was not upheld.")]
    InternalInvariantError,
}

/// Cache holding our session keys, per user, after authentication. Maps
/// [`UserId`]s to [`OpaqueSessionKey`]s. Keys are tagged with a timestamp. A
/// key is considered invalid after [`Self::expiration`] time has elapsed.
#[derive(Debug)]
pub(crate) struct SessionKeyCache {
    /// Map from user ids to (timestamp, keys).
    cache: HashMap<UserId, (Instant, OpaqueSessionKey)>,
    /// Time a key is considered valid for.
    expiration: Duration,
}

impl Drop for SessionKeyCache {
    fn drop(&mut self) {
        for value in self.cache.values_mut() {
            value.1.zeroize();
        }
    }
}

#[allow(unused)]
impl SessionKeyCache {
    /// Amount of time a key is considered valid for. Sixty seconds for now. May
    /// change later.
    pub(crate) const DEFAULT_EXPIRATION_TIME: Duration = Duration::from_secs(60);

    /// Create a new [`SessionKeyCache`] with the given `expiration` interval.
    pub fn new(expiration: Duration) -> Self {
        Self {
            cache: HashMap::new(),
            expiration,
        }
    }

    /// Add a new session key for the specified user. The previous key for that
    /// will be overwritten.
    pub fn insert(&mut self, user: UserId, key: OpaqueSessionKey) {
        let existing = self.cache.insert(user, (Instant::now(), key));

        if existing.is_some() {
            tracing::info!("Previous session key overwritten.");
        }
    }

    /// Get the session key for the specified user, if one exists.
    /// This function checks if the key has expired and returns an error
    /// instead.
    pub fn get_key(&mut self, user: UserId) -> Result<OpaqueSessionKey, SessionKeyCacheError> {
        match self.cache.entry(user) {
            Entry::Occupied(entry) => {
                let (timestamp, key) = entry.get();

                // If key is expired remove it and report an error.
                if timestamp.elapsed() >= self.expiration {
                    tracing::info!("Session key is expired.");
                    // We don't care about this expired key.
                    let _ = entry.remove();
                    return Err(SessionKeyCacheError::ExpiredSessionKey);
                }
                Ok(key.clone())
            }
            Entry::Vacant(_) => Err(SessionKeyCacheError::MissingSessionKey),
        }
    }

    pub fn check_key<DB: DataStore>(
        &mut self,
        metadata: &RequestMetadata,
    ) -> Result<(), LockKeeperServerError> {
        match metadata.action() {
            // These actions are unauthenticated
            ClientAction::Authenticate | ClientAction::Register => Ok(()),
            // The rest of the actions must be authenticated
            _ => {
                let user_id = metadata
                    .user_id()
                    .as_ref()
                    .ok_or(LockKeeperServerError::InvalidAccount)?;
                let server_session_key = self.get_key(user_id.clone())?;
                Ok(())
            }
        }
    }
}

impl Default for SessionKeyCache {
    fn default() -> Self {
        SessionKeyCache::new(SessionKeyCache::DEFAULT_EXPIRATION_TIME)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        server::session_key_cache::{SessionKeyCache, SessionKeyCacheError},
        LockKeeperServerError,
    };
    use generic_array::GenericArray;
    use lock_keeper::{crypto::OpaqueSessionKey, types::database::user::UserId};
    use rand::{prelude::StdRng, SeedableRng};
    use std::{thread, time::Duration};

    type Result<T> = std::result::Result<T, LockKeeperServerError>;

    #[test]
    fn key_does_not_exist() -> Result<()> {
        let mut cache = SessionKeyCache::default();
        let id = get_temp_user_id()?;

        match cache.get_key(id) {
            Ok(_) => {
                panic!("Key should not exist.")
            }
            Err(e) => {
                assert_eq!(e, SessionKeyCacheError::MissingSessionKey);
            }
        }

        Ok(())
    }

    /// Ensure we can get the key back without encountering expiration error.
    #[test]
    fn get_key_back() -> Result<()> {
        let mut cache = SessionKeyCache::default();
        let id = get_temp_user_id()?;
        let key = get_temp_session_key();

        cache.insert(id.clone(), key);

        // We got a key back.
        let _key_ref = cache.get_key(id)?;
        Ok(())
    }

    /// Insert key twice and ensure code runs all the way.
    #[test]
    fn overwrite_existing_key() -> Result<()> {
        let mut cache = SessionKeyCache::default();
        let id = get_temp_user_id()?;
        let key = get_temp_session_key();

        cache.insert(id.clone(), key);
        let second_key = get_temp_session_key();
        cache.insert(id, second_key);

        Ok(())
    }

    /// Test key expiration logic when enough time has passed that the key
    /// should be expired.
    #[test]
    fn key_expired() -> Result<()> {
        // Keys expire instantly
        let mut cache = SessionKeyCache::new(Duration::from_secs(0));
        let id = get_temp_user_id()?;
        let key = get_temp_session_key();
        cache.insert(id.clone(), key);

        // Verify key is expired.
        match cache.get_key(id) {
            Ok(_) => panic!("Key should be expired"),
            Err(e) => {
                assert_eq!(
                    e,
                    SessionKeyCacheError::ExpiredSessionKey,
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
        let mut cache = SessionKeyCache::new(Duration::from_millis(10));
        let id = get_temp_user_id()?;
        let key = get_temp_session_key();
        cache.insert(id.clone(), key);

        // Sleep for a while so key expires.
        thread::sleep(Duration::from_millis(10));

        // Verify key is expired.
        match cache.get_key(id) {
            Ok(_) => panic!("Key should be expired"),
            Err(e) => {
                assert_eq!(
                    e,
                    SessionKeyCacheError::ExpiredSessionKey,
                    "Unexpected error returned."
                )
            }
        }
        Ok(())
    }

    fn get_temp_session_key() -> OpaqueSessionKey {
        const FILLER: u8 = 42;
        OpaqueSessionKey::from(GenericArray::from([FILLER; 64]))
    }

    fn get_temp_user_id() -> Result<UserId> {
        // Deterministic seed. No need for our test to be nondeterministic.
        const SEED: u64 = 1234;
        let mut rng = StdRng::seed_from_u64(SEED);
        Ok(UserId::new(&mut rng)?)
    }
}
