pub mod client {
    use crate::crypto::{KeyId, SignableBytes};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    pub struct RequestRemoteSign {
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
