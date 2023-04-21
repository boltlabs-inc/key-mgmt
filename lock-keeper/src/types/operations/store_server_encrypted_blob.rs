pub mod client {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Request {
        pub data_blob: Vec<u8>,
    }
}

pub mod server {
    use crate::crypto::KeyId;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// Return new requested key ID.
    pub struct Response {
        pub key_id: KeyId,
    }
}
