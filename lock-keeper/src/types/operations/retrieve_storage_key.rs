pub mod client {
    use crate::types::database::user::UserId;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// pass user ID to server
    pub struct Request {
        pub user_id: UserId,
    }
}

pub mod server {
    use crate::crypto::{Encrypted, StorageKey};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// return encrypted storage key
    pub struct Response {
        pub ciphertext: Encrypted<StorageKey>,
    }
}
