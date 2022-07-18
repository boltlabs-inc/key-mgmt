use crate::key_mgmt::client::{CreateSecretRequest, SecretInfo, SecretRetrieveRequest};
use dialectic::prelude::*;
use dialectic::types::Done;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, CredentialResponse, RegistrationRequest,
    RegistrationResponse, RegistrationUpload,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

type OfferAbort<Next, Err> = Session! {
    offer {
        0 => recv Err,
        1 => Next,
    }
};

#[macro_export]
macro_rules! offer_abort {
    (in $chan:ident as $party:expr) => {
        let $chan = ::anyhow::Context::context(dialectic::offer!(in $chan {
            0 => {
                let party_ctx = || format!("{:?} chose to abort the session", $party.opposite());
                let (err, $chan) = ::anyhow::Context::with_context(
                    ::anyhow::Context::context(
                        $chan.recv().await,
                        "Failed to receive error after receiving abort"
                    ),
                    party_ctx)?;
                $chan.close();
                return ::anyhow::Context::with_context(Err(err), party_ctx);
            }
            1 => $chan,
        }), "Failure while receiving choice of continue/abort")?;
    }
}

type _ChooseAbort<Next, Err> = Session! {
    choose {
        0 => send Err,
        1 => Next,
    }
};

#[macro_export]
macro_rules! abort {
    (in $chan:ident return $err:expr ) => {{
        let $chan = ::anyhow::Context::context(
            $chan.choose::<0>().await,
            "Failure while choosing to abort",
        )?;
        let err = $err;
        let $chan = ::anyhow::Context::context(
            $chan.send(err.clone()).await,
            "Failed to send error after choosing to abort",
        )?;
        $chan.close();
        return ::anyhow::Context::context(Err(err), "Protocol aborted");
    }};
}

#[macro_export]
macro_rules! proceed {
    (in $chan:ident) => {
        let $chan = ::anyhow::Context::context(
            $chan.choose::<1>().await,
            "Failure while choosing to continue",
        )?;
    };
}

/// The object that the client sends to the server when registering using OPAQUE
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterStart {
    request: RegistrationRequest<OpaqueCipherSuite>,
    user_id: UserId,
}

impl RegisterStart {
    pub fn new(request: RegistrationRequest<OpaqueCipherSuite>, user_id: UserId) -> Self {
        Self { request, user_id }
    }
    pub fn into_parts(self) -> (RegistrationRequest<OpaqueCipherSuite>, UserId) {
        (self.request, self.user_id)
    }
}

/// The object that the server responds with to the client when ['RegisterStart'] has been received
pub type RegisterStartReceived = RegistrationResponse<OpaqueCipherSuite>;
/// The object that the client sends to the server to finish registration using OPAQUE
pub type RegisterFinish = RegistrationUpload<OpaqueCipherSuite>;

/// The object that the client sends to the server when registering using OPAQUE
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthStart {
    request: CredentialRequest<OpaqueCipherSuite>,
    user_id: UserId,
}

impl AuthStart {
    pub fn new(request: CredentialRequest<OpaqueCipherSuite>, user_id: UserId) -> Self {
        Self { request, user_id }
    }
    pub fn into_parts(self) -> (CredentialRequest<OpaqueCipherSuite>, UserId) {
        (self.request, self.user_id)
    }
}

/// The object that the server responds with to the client when ['RegisterStart'] has been received
pub type AuthStartReceived = CredentialResponse<OpaqueCipherSuite>;
/// The object that the client sends to the server to finish registration using OPAQUE
pub type AuthFinish = CredentialFinalization<OpaqueCipherSuite>;

/// The two parties in the protocol.
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize, Deserialize)]
pub enum Party {
    /// The client.
    Client,
    /// The server.
    Server,
}

impl fmt::Display for Party {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Party {
    /// Get the other party.
    ///
    /// # Examples
    ///
    /// ```
    /// use da_mgmt::protocol::Party::*;
    ///
    /// assert_eq!(Client.opposite(), Server);
    /// assert_eq!(Server.opposite(), Client);
    /// ```
    pub const fn opposite(self) -> Self {
        use Party::*;
        match self {
            Client => Server,
            Server => Client,
        }
    }
}

// All protocols are from the perspective of the client.
use crate::config::opaque::OpaqueCipherSuite;
use crate::keys::UserId;
pub use authenticate::Authenticate;
pub use create::Create;
pub use register::Register;
pub use retrieve::Retrieve;

/// The key-mgmt session type from the perspective of the client
pub type KeyMgmt = Session! {
    choose {
        0 => Create,
        1 => Register,
        2 => Retrieve,
        3 => Authenticate,
    }
};

/// The protocol to create a secret
pub mod create {
    use super::*;

    /// Possible errors of the protocol
    #[derive(Debug, Clone, Error, Serialize, Deserialize)]
    pub enum Error {}

    /// The actual sessionType for the create protocol
    pub type Create = InitiateCreateSecret;

    /// The internals of the Create sessionType
    pub type InitiateCreateSecret = Session! {
        send CreateSecretRequest;
        recv SecretInfo;
    };
}

/// The protocol to register using OPAQUE
pub mod register {
    use super::*;

    /// Possible errors of the protocol
    #[derive(Debug, Clone, Error, Serialize, Deserialize)]
    pub enum Error {
        #[error("User ID already exists")]
        UserIdAlreadyExists,
    }

    /// The actual sessionType for the registration protocol
    pub type Register = DoRegister;

    /// The internals of the registration protocol
    pub type DoRegister = Session! {
        send RegisterStart;
        OfferAbort<RegisterStartReceivedSessNoAbort, Error>;
    };

    pub type RegisterStartReceivedSessNoAbort = Session! {
        recv RegisterStartReceived;
        send RegisterFinish;
    };
}

/// The protocol to retrieve a secret
pub mod retrieve {
    use super::*;

    /// Possible errors of the protocol
    #[derive(Debug, Clone, Error, Serialize, Deserialize)]
    pub enum Error {}

    /// The actual sessionType for the retrieve protocol
    pub type Retrieve = RetrieveSecret;

    /// The internals of the Retrieve sessionType
    pub type RetrieveSecret = Session! {
        send SecretRetrieveRequest;
        recv SecretInfo;
    };
}

/// The protocol to authenticate using OPAQUE
pub mod authenticate {
    use super::*;

    /// Possible errors of the protocol
    #[derive(Debug, Clone, Error, Serialize, Deserialize)]
    pub enum Error {
        #[error("User ID does not exist")]
        UserIdDoesNotExist,
        #[error("The server encountered an unexpected error")]
        ServerError,
        #[error("Wrong username or password")]
        CouldNotAuthenticate,
    }

    /// The actual sessionType for the registration protocol
    pub type Authenticate = Session! {
        send AuthStart;
        OfferAbort<AuthStartReceivedSessNoAbort, Error>;
    };

    pub type AuthStartReceivedSessNoAbort = Session! {
        recv AuthStartReceived;
        send AuthFinish;
        OfferAbort<Done, Error>;
    };
}
