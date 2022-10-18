use serde::{Deserialize, Serialize};

/// Options for the asset owner's intended use of a secret
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum RetrieveContext {
    Null,
    LocalOnly,
}

pub mod client {
    use crate::{crypto::KeyId, impl_message_conversion, types::database::user::UserId};
    use serde::{Deserialize, Serialize};

    use super::RetrieveContext;

    #[derive(Debug, Deserialize, Serialize)]
    /// pass user ID and key ID to server
    pub struct Request {
        pub user_id: UserId,
        pub key_id: KeyId,
        pub context: RetrieveContext,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct RequestSigningKey {
        pub user_id: UserId,
        pub key_id: KeyId,
        pub context: RetrieveContext,
    }

    impl_message_conversion!(Request, RequestSigningKey);
}

pub mod server {
    use crate::{
        crypto::Export, impl_message_conversion, types::database::secrets::StoredEncryptedSecret,
    };
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// return requested key and key ID
    pub struct Response {
        pub stored_secret: StoredEncryptedSecret,
    }

    #[derive(Debug, Deserialize, Serialize)]
    /// return exported signing key material
    pub struct ResponseSigningKey {
        pub exported_signing_key: Export,
    }

    impl_message_conversion!(Response, ResponseSigningKey);
}
