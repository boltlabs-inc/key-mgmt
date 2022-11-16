pub mod client {
    use crate::{impl_message_conversion, types::database::user::UserId};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    pub struct RequestRemoteGenerate {
        pub user_id: UserId,
    }

    impl_message_conversion!(RequestRemoteGenerate);
}

pub mod server {
    use crate::{
        crypto::{KeyId, SigningPublicKey},
        impl_message_conversion,
    };
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    pub struct ReturnKeyId {
        pub key_id: KeyId,
        pub public_key: SigningPublicKey,
    }

    impl_message_conversion!(ReturnKeyId);
}
