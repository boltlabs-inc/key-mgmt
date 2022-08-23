pub mod client {
    use crate::impl_message_conversion;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// pass user ID and registration-start message from OPAQUE
    pub struct AuthenticateStart {
        pub message: Vec<u8>,
        pub user_id: Vec<u8>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    /// pass user ID and registration-finish message from OPAQUE
    pub struct AuthenticateFinish {
        pub message: Vec<u8>,
        pub user_id: Vec<u8>,
    }

    impl_message_conversion!(AuthenticateStart, AuthenticateFinish);
}

pub mod server {
    use crate::impl_message_conversion;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// Check if user exists and return successful if not
    pub struct AuthenticateStart {
        pub message: Vec<u8>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    /// return true if successful
    pub struct AuthenticateFinish {
        pub success: bool,
    }

    impl_message_conversion!(AuthenticateStart, AuthenticateFinish);
}
