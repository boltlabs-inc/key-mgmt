pub mod client {
    use crate::{
        crypto::{KeyId, SignableBytes},
        impl_authenticated_message_conversion,
        types::database::user::UserId,
    };
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    pub struct RequestRemoteSign {
        pub user_id: UserId,
        pub key_id: KeyId,
        pub data: SignableBytes,
    }

    impl_authenticated_message_conversion!(RequestRemoteSign);
}

pub mod server {
    use crate::{crypto::Signature, impl_authenticated_message_conversion};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    pub struct ReturnSignature {
        pub signature: Signature,
    }

    impl_authenticated_message_conversion!(ReturnSignature);
}
