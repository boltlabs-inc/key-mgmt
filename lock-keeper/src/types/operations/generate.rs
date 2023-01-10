pub mod client {
    use crate::crypto::{Encrypted, Secret};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// pass user ID and encrypted secret
    pub struct Store {
        pub ciphertext: Encrypted<Secret>,
    }
}

pub mod server {
    use crate::crypto::KeyId;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// return new requested key ID
    pub struct Generate {
        pub key_id: KeyId,
    }

    #[derive(Debug, Deserialize, Serialize)]
    /// Return true if successful
    pub struct Store {
        pub success: bool,
    }
}
