pub mod client {
    use crate::{
        crypto::{KeyId, SignableBytes},
        types::database::user::UserId,
    };
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    pub struct RequestRemoteSign {
        pub user_id: UserId,
        pub key_id: KeyId,
        pub data: SignableBytes,
    }
}

pub mod server {
    use crate::crypto::Signature;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    pub struct ReturnSignature {
        pub signature: Signature,
    }
}
