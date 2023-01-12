pub mod server {
    use crate::types::database::account::UserId;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Response {
        pub user_id: UserId,
    }
}
