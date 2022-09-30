//! Local storage types for in-memory and on-disk storage of key information.

use std::{
    collections::HashMap,
    fmt::Display,
    fs,
    path::{Path, PathBuf},
};

use anyhow::anyhow;
use lock_keeper::crypto::KeyId;
use lock_keeper_client::api::arbitrary_secrets::{LocalStorage, RetrieveResult};
use serde::{Deserialize, Serialize};

/// Container for all locally stored key data.
/// This type handles both in-memory storage and persistent storage on the disk.
#[derive(Debug, Serialize, Deserialize)]
pub struct Storage {
    /// Directory for persistent storage files
    path: PathBuf,
    /// Mapping from account_name to key data
    data: HashMap<String, UserStore>,
}

impl Storage {
    /// Create a new [`Storage`] with local data in the given path.
    pub fn new(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        let data = Self::load(&path)?;

        Ok(Self { path, data })
    }

    /// Get a key from local storage
    pub fn get(
        &self,
        account_name: impl AsRef<str>,
        name: impl AsRef<str>,
    ) -> anyhow::Result<Option<&Entry>> {
        Ok(self
            .data
            .get(account_name.as_ref())
            .and_then(|user_store| user_store.get(name)))
    }

    /// Store a key in local storage. Key names are automatically generated as
    /// sequential integers.
    pub fn store(
        &mut self,
        account_name: impl Into<String>,
        data: impl Into<Entry>,
    ) -> anyhow::Result<String> {
        let account_name = account_name.into();

        let user_store = self
            .data
            .entry(account_name.clone())
            .or_insert_with(UserStore::new);

        let name = user_store.store(data);

        self.save(account_name)?;
        Ok(name)
    }

    /// Store a key in local storage with the specified key name.
    pub fn store_named(
        &mut self,
        account_name: impl Into<String>,
        name: impl Into<String>,
        data: impl Into<Entry>,
    ) -> anyhow::Result<()> {
        let account_name = account_name.into();

        let user_store = self
            .data
            .entry(account_name.clone())
            .or_insert_with(UserStore::new);

        user_store.store_named(name.into(), data.into());

        self.save(account_name)?;
        Ok(())
    }

    /// List all keys in storage for the given account.
    pub fn list(&self, account_name: impl AsRef<str>) -> anyhow::Result<()> {
        let user_store = self
            .data
            .get(account_name.as_ref())
            .ok_or_else(|| anyhow!("User not found"))?;

        user_store.list();
        Ok(())
    }

    /// Save all key data for the given account.
    fn save(&self, account_name: impl AsRef<str>) -> anyhow::Result<()> {
        let user_store = self
            .data
            .get(account_name.as_ref())
            .ok_or_else(|| anyhow!("User not found"))?;

        fs::create_dir_all(&self.path)?;
        let json = serde_json::to_string_pretty(&user_store)?;

        let mut file_name = self.path.clone();
        file_name.push(format!("{}.json", account_name.as_ref()));

        fs::write(file_name, json)?;
        Ok(())
    }

    /// Load all key data from the filesystem in the given path.
    fn load(path: impl AsRef<Path>) -> anyhow::Result<HashMap<String, UserStore>> {
        let mut result = HashMap::new();

        let paths = fs::read_dir(path.as_ref())?;

        for path in paths {
            let path = path?;
            if path.file_type()?.is_file() {
                let file_name = path
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow!("Invalid file name"))?;

                let account_name = file_name
                    .split(".json")
                    .next()
                    .ok_or_else(|| anyhow!("Invalid file name: {file_name}"))?
                    .to_string();

                let json = fs::read(path.path())?;
                let user_store = serde_json::from_slice(&json)?;

                result.insert(account_name, user_store);
            }
        }

        Ok(result)
    }
}

/// Key data for an individual account.
#[derive(Debug, Serialize, Deserialize)]
pub struct UserStore {
    /// Mapping from key name to key data
    keys: HashMap<String, Entry>,
    /// Next key name for keys that are stored without a custom name
    next_index: usize,
}

impl UserStore {
    /// Create a new [`UserStore`].
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            next_index: 1,
        }
    }

    /// Get a key with the given name.
    pub fn get(&self, name: impl AsRef<str>) -> Option<&Entry> {
        self.keys.get(name.as_ref())
    }

    /// Store a key. Key names are automatically generated as sequential
    /// integers.
    pub fn store(&mut self, data: impl Into<Entry>) -> String {
        let index = self.next_index.to_string();
        self.next_index += 1;

        self.store_named(index.clone(), data);

        index
    }

    /// Store a key with the specified key name.
    pub fn store_named(&mut self, name: impl Into<String>, data: impl Into<Entry>) {
        let data = data.into();
        let index = name.into();
        self.keys.insert(index, data);
    }

    /// List all keys stored for this account.
    pub fn list(&self) {
        for (name, entry) in &self.keys {
            println!("name: {name}");
            println!("{entry}");
            println!();
        }
    }
}

/// Key data returned from a key server.
#[derive(Debug, Serialize, Deserialize)]
pub struct Entry {
    pub key_id: KeyId,
    pub data: RetrieveResult,
}

impl Display for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "key_id: {:?}", self.key_id)?;
        writeln!(f, "data: {:?}", self.data)?;
        Ok(())
    }
}

impl From<(KeyId, RetrieveResult)> for Entry {
    fn from((key_id, data): (KeyId, RetrieveResult)) -> Self {
        Self { key_id, data }
    }
}

impl From<(KeyId, LocalStorage)> for Entry {
    fn from((key_id, local_storage): (KeyId, LocalStorage)) -> Self {
        let data = RetrieveResult::ArbitraryKey(local_storage);
        Self { key_id, data }
    }
}
