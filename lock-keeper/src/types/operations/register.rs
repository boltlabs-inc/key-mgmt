pub mod client {
    use crate::{config::opaque::OpaqueCipherSuite, types::database::account::AccountName};
    use opaque_ke::{RegistrationRequest, RegistrationUpload};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// pass user ID and registration-start message from OPAQUE
    pub struct RegisterStart {
        pub registration_request: RegistrationRequest<OpaqueCipherSuite>,
        pub account_name: AccountName,
    }

    #[derive(Debug, Deserialize, Serialize)]
    /// pass user ID and registration-finish message from OPAQUE
    pub struct RegisterFinish {
        pub registration_upload: RegistrationUpload<OpaqueCipherSuite>,
    }
}

pub mod server {
    use crate::config::opaque::OpaqueCipherSuite;
    use opaque_ke::RegistrationResponse;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// Check if user exists and return successful if not
    pub struct RegisterStart {
        pub registration_response: RegistrationResponse<OpaqueCipherSuite>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    /// Return true if successful
    pub struct RegisterFinish {
        pub success: bool,
    }
}
