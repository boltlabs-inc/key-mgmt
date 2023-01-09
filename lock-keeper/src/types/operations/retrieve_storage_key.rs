pub mod server {
    use crate::crypto::{Encrypted, StorageKey};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// return encrypted storage key
    pub struct Response {
        pub ciphertext: Encrypted<StorageKey>,
    }
}
