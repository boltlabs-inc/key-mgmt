pub mod client {
    use crate::crypto::{Encrypted, StorageKey};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    pub struct SendStorageKey {
        pub storage_key: Encrypted<StorageKey>,
    }
}

pub mod server {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// Return true if successful
    pub struct CreateStorageKeyResult {
        pub success: bool,
    }
}
