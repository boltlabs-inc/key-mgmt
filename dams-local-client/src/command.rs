#[cfg(feature = "allow_explicit_certificate_trust")]
use anyhow::Context;
use async_trait::async_trait;
use dams::{config::client::Config, protocol, transport::KeyMgmtAddress};
use serde::{Deserialize, Serialize};
#[cfg(not(feature = "allow_explicit_certificate_trust"))]
use tracing::warn;
use transport::client::{Chan, Client, SessionKey};

mod create;
mod retrieve;

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
/// All subcommands of [`cli::Client`](crate::cli::Client) should
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
