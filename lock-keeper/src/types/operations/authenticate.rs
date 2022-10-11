pub mod client {
    use crate::{
        config::opaque::OpaqueCipherSuite, impl_message_conversion, types::user::AccountName,
    };
    use opaque_ke::{CredentialFinalization, CredentialRequest};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// Pass account name and registration-start message from OPAQUE.
    pub struct AuthenticateStart {
        pub credential_request: CredentialRequest<OpaqueCipherSuite>,
        pub account_name: AccountName,
    }

    #[derive(Debug, Deserialize, Serialize)]
    /// Pass account name and registration-finish message from OPAQUE.
    pub struct AuthenticateFinish {
        pub credential_finalization: CredentialFinalization<OpaqueCipherSuite>,
        pub account_name: AccountName,
    }

    impl_message_conversion!(AuthenticateStart, AuthenticateFinish);
}

pub mod server {
    use crate::{config::opaque::OpaqueCipherSuite, impl_message_conversion, types::user::UserId};
    use opaque_ke::CredentialResponse;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// Check if user exists and return OPAQUE message if so
    pub struct AuthenticateStart {
        pub credential_response: CredentialResponse<OpaqueCipherSuite>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    /// Return true if successful.
    pub struct AuthenticateFinish {
        pub success: bool,
    }

    #[derive(Debug, Deserialize, Serialize)]
    /// Return authenticated user id if authentication worked.
    pub struct SendUserId {
        pub user_id: UserId,
    }

    impl_message_conversion!(AuthenticateStart, AuthenticateFinish);

    // TODO #186: This struct should be authenticated! Update message conversion to
    // authenticate on serialization and check authentication on
    // deserialization.
    impl_message_conversion!(SendUserId);
}
