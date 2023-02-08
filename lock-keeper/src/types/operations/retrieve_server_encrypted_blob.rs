pub mod client {
    use crate::crypto::KeyId;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Request {
        pub key_id: KeyId,
    }
}

pub mod server {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// Response from server returning the requested data blob.
    pub struct Response {
        pub data_blob: Vec<u8>,
    }
}
