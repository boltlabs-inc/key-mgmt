pub mod client {
    use crate::impl_message_conversion;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// pass user ID and registration-start message from OPAQUE
    pub struct RegisterStart {
        pub message: Vec<u8>,
        pub user_id: Vec<u8>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    /// pass user ID and registration-finish message from OPAQUE
    pub struct RegisterFinish {
        pub message: Vec<u8>,
        pub user_id: Vec<u8>,
    }

    impl_message_conversion!(RegisterStart, RegisterFinish);
}

pub mod server {
    use crate::impl_message_conversion;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// Check if user exists and return successful if not
    pub struct RegisterStart {
        pub message: Vec<u8>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    /// Return true if successful
    pub struct RegisterFinish {
        pub success: bool,
    }

    impl_message_conversion!(RegisterStart, RegisterFinish);
}
