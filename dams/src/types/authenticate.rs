pub mod client {
    use crate::{config::opaque::OpaqueCipherSuite, impl_message_conversion, user::UserId};
    use opaque_ke::{CredentialFinalization, CredentialRequest};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// pass user ID and registration-start message from OPAQUE
    pub struct AuthenticateStart {
        pub credential_request: CredentialRequest<OpaqueCipherSuite>,
        pub user_id: UserId,
    }

    #[derive(Debug, Deserialize, Serialize)]
    /// pass user ID and registration-finish message from OPAQUE
    pub struct AuthenticateFinish {
        pub credential_finalization: CredentialFinalization<OpaqueCipherSuite>,
        pub user_id: UserId,
    }

    impl_message_conversion!(AuthenticateStart, AuthenticateFinish);
}

pub mod server {
    use crate::{config::opaque::OpaqueCipherSuite, impl_message_conversion};
    use opaque_ke::CredentialResponse;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// Check if user exists and return successful if not
    pub struct AuthenticateStart {
        pub credential_response: CredentialResponse<OpaqueCipherSuite>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    /// return true if successful
    pub struct AuthenticateFinish {
        pub success: bool,
    }

    impl_message_conversion!(AuthenticateStart, AuthenticateFinish);
}
