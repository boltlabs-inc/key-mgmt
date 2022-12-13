pub mod client {
    use crate::types::database::user::UserId;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    pub struct RequestRemoteGenerate {
        pub user_id: UserId,
    }
}

pub mod server {
    use crate::crypto::{KeyId, SigningPublicKey};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    pub struct ReturnKeyId {
        pub key_id: KeyId,
        pub public_key: SigningPublicKey,
    }
}
