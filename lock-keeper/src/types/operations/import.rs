pub mod client {
    use crate::{crypto::Import, types::database::user::UserId};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// send user ID and material to import
    pub struct Request {
        pub user_id: UserId,
        pub key_material: Import,
    }
}

pub mod server {
    use crate::crypto::KeyId;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// return new requested key ID
    pub struct Response {
        pub key_id: KeyId,
    }
}
