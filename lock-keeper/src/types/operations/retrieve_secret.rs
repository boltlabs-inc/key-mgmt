use serde::{Deserialize, Serialize};

/// Options for the asset owner's intended use of a secret
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum RetrieveContext {
    Null,
    LocalOnly,
}

pub mod client {
    use crate::{
        crypto::KeyId, impl_authenticated_message_conversion, types::database::user::UserId,
    };
    use serde::{Deserialize, Serialize};

    use super::RetrieveContext;

    #[derive(Debug, Deserialize, Serialize)]
    /// pass user ID and key ID to server
    pub struct Request {
        pub user_id: UserId,
        pub key_id: KeyId,
        pub context: RetrieveContext,
        pub secret_type: Option<String>,
    }

    impl_authenticated_message_conversion!(Request);
}

pub mod server {
    use crate::{impl_authenticated_message_conversion, types::database::secrets::StoredSecret};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// return requested key and key ID
    pub struct Response {
        pub secret: StoredSecret,
    }
    impl_authenticated_message_conversion!(Response);
}
