pub mod client {
    use crate::types::database::user::UserId;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// send user ID and material to import
    pub struct Request {
        pub user_id: UserId,
    }
}

pub mod server {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// return new requested key ID
    pub struct Response {
        pub success: bool,
    }
}
