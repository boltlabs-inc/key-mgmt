pub mod client {
    use crate::{
        crypto::{Encrypted, StorageKey},
        types::database::user::{AccountName, UserId},
    };
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    pub struct RequestUserId {
        pub account_name: AccountName,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct SendStorageKey {
        pub user_id: UserId,
        pub storage_key: Encrypted<StorageKey>,
    }
}

pub mod server {
    use crate::types::database::user::UserId;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    pub struct SendUserId {
        pub user_id: UserId,
    }

    #[derive(Debug, Deserialize, Serialize)]
    /// Return true if successful
    pub struct CreateStorageKeyResult {
        pub success: bool,
    }
}
