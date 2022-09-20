pub mod client {
    use crate::{impl_message_conversion, user::UserId};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// pass user ID to server
    pub struct Request {
        pub user_id: UserId,
    }

    impl_message_conversion!(Request);
}

pub mod server {
    use crate::{
        crypto::{Encrypted, StorageKey},
        impl_message_conversion,
    };
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// return encrypted storage key
    pub struct Response {
        pub ciphertext: Encrypted<StorageKey>,
    }

    impl_message_conversion!(Response);
}
