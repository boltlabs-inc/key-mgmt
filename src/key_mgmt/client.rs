use crate::config::opaque::OpaqueCipherSuite;
use crate::{client::Config, protocol, transport::KeyMgmtAddress};
#[cfg(feature = "allow_explicit_certificate_trust")]
use anyhow::Context;
use async_trait::async_trait;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, CredentialResponse, RegistrationRequest,
    RegistrationResponse, RegistrationUpload,
};
use serde::{Deserialize, Serialize};
#[cfg(not(feature = "allow_explicit_certificate_trust"))]
use tracing::warn;
use transport::client::{Chan, Client, SessionKey};

mod authenticate;
mod create;
mod register;
mod retrieve;

/// The object that the client sends to the server when registering using OPAQUE
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterStart {
    pub request: RegistrationRequest<OpaqueCipherSuite>,
    pub username: String,
}
/// The object that the server responds with to the client when ['RegisterStart'] has been received
pub type RegisterStartReceived = RegistrationResponse<OpaqueCipherSuite>;
/// The object that the client sends to the server to finish registration using OPAQUE
pub type RegisterFinish = RegistrationUpload<OpaqueCipherSuite>;

/// The object that the client sends to the server when registering using OPAQUE
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthStart {
    pub request: CredentialRequest<OpaqueCipherSuite>,
    pub username: String,
}
/// The object that the server responds with to the client when ['RegisterStart'] has been received
pub type AuthStartReceived = CredentialResponse<OpaqueCipherSuite>;
/// The object that the client sends to the server to finish registration using OPAQUE
pub type AuthFinish = CredentialFinalization<OpaqueCipherSuite>;

/// The object that the client sends to the server when creating a secret
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSecretRequest;
/// The object containing info about a secret
#[derive(Debug, Serialize, Deserialize)]
pub struct SecretInfo;
/// The object that the client sends to the server when retrieving a secret
#[derive(Debug, Serialize, Deserialize)]
pub struct SecretRetrieveRequest;

/// A single client-side command, parameterized by the currently loaded
/// configuration.
///
/// All subcommands of [`cli::Client`](crate::client::cli::Client) should
/// implement this.
#[async_trait]
pub trait Command {
    type Output;

    /// Run the command to completion using the given random number generator
    /// for all randomness and the given customer configuration.
    async fn run(self, config: Config) -> Result<Self::Output, anyhow::Error>;
}

/// Connect to a given [`KeyMgmtAddress`], configured using the parameters in
/// the [`Config`].
pub async fn connect(
    config: &Config,
    address: &KeyMgmtAddress,
) -> Result<(SessionKey, Chan<protocol::KeyMgmt>), anyhow::Error> {
    let Config {
        backoff,
        connection_timeout,
        max_pending_connection_retries,
        max_message_length,
        trust_certificate,
        ..
    } = config;

    let mut client: Client<protocol::KeyMgmt> = Client::new(*backoff);
    let _ = client
        .max_length(*max_message_length)
        .timeout(*connection_timeout)
        .max_pending_retries(*max_pending_connection_retries);

    if let Some(path) = trust_certificate {
        #[cfg(feature = "allow_explicit_certificate_trust")]
        let _ = client.trust_explicit_certificate(path).with_context(|| {
            format!(
                "Failed to enable explicitly trusted certificate at {:?}",
                path
            )
        })?;

        #[cfg(not(feature = "allow_explicit_certificate_trust"))]
        warn!(
            "Ignoring explicitly trusted certificate at {:?} because \
            this binary was built to only trust webpki roots of trust",
            path
        );
    }

    Ok(client.connect_zkchannel(address).await?)
}
