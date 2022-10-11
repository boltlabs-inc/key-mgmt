pub mod client {
    use crate::{
        crypto::{Encrypted, Secret},
        impl_message_conversion,
        types::user::UserId,
    };
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// pass user ID to server
    pub struct Generate {
        pub user_id: UserId,
    }

    #[derive(Debug, Deserialize, Serialize)]
    /// pass user ID and encrypted secret
    pub struct Store {
        pub ciphertext: Encrypted<Secret>,
        pub user_id: UserId,
    }

    impl_message_conversion!(Generate, Store);
}

pub mod server {
    use crate::{crypto::KeyId, impl_message_conversion};
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

    impl_message_conversion!(Generate, Store);
}
