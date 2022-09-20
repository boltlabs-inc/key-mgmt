pub mod client {
    use crate::{crypto::KeyId, impl_message_conversion, user::UserId, RetrieveContext};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// pass user ID and key ID to server
    pub struct Request {
        pub user_id: UserId,
        pub key_id: KeyId,
        pub context: RetrieveContext,
    }

    impl_message_conversion!(Request);
}

pub mod server {
    use crate::{impl_message_conversion, user::StoredSecret};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// return new requested key and key ID
    pub struct Response {
        pub stored_secret: StoredSecret,
    }

    impl_message_conversion!(Response);
}
