pub mod client {
    use crate::{
        crypto::{Encrypted, StorageKey},
        impl_authenticated_message_conversion,
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

    // TODO #186: These messages need to be authenticated
    impl_authenticated_message_conversion!(RequestUserId, SendStorageKey);
}

pub mod server {
    use crate::{impl_authenticated_message_conversion, types::database::user::UserId};
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

    // TODO #186: These messages need to be authenticated
    impl_authenticated_message_conversion!(SendUserId, CreateStorageKeyResult);
}
