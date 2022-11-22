pub mod client {
    use crate::{impl_message_conversion, types::database::user::UserId};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// send user ID and material to import
    pub struct Request {
        pub user_id: UserId,
    }

    impl_message_conversion!(Request);
}

pub mod server {
    use crate::impl_message_conversion;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// return new requested key ID
    pub struct Response {
        pub success: bool,
    }

    impl_message_conversion!(Response);
}
