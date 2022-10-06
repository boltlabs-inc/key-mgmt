//! Full implementation of the public API for the Lock Keeper client library.
//!
//! This API is designed for use with a local client application - that is, an
//! application running directly on the device of an asset owner. The inputs
//! the asset owner provides should be passed directly to this API without being
//! sent to a separate machine.

mod authenticate;
mod create_storage_key;
mod generate;
mod register;
mod retrieve;
mod retrieve_audit_events;

use crate::{client::Password, LockKeeperClient, LockKeeperClientError};
use lock_keeper::{
    audit_event::{AuditEvent, AuditEventOptions, EventType},
    config::client::Config,
    crypto::{KeyId, Secret},
    user::AccountName,
    ClientAction, RetrieveContext,
};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use tracing::error;

/// Ways of returning a key from the retrieval process based on usage
/// [`RetrieveContext`]
#[derive(Debug, Deserialize, Serialize)]
pub enum RetrieveResult {
    None,
    ArbitraryKey(LocalStorage),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LocalStorage {
    pub secret: Secret,
}

impl LockKeeperClient {
    /// Ping the server to make sure it is running and reachable
    pub async fn health(config: &Config) -> Result<(), LockKeeperClientError> {
        use lock_keeper::rpc::HealthCheck;

        let mut client = Self::connect(config).await?;
        match client.health(HealthCheck { check: true }).await {
            Ok(response) => {
                if response.into_inner() == (HealthCheck { check: true }) {
                    Ok(())
                } else {
                    Err(LockKeeperClientError::HealthCheckFailed)
                }
            }
            Err(_) => Err(LockKeeperClientError::HealthCheckFailed),
        }
    }

    /// Authenticate to the Lock Keeper key server as a previously registered
    /// user.
    ///
    /// Output: If successful, returns a [`LockKeeperClient`].
    pub async fn authenticated_client(
        account_name: &AccountName,
        password: &Password,
        config: &Config,
    ) -> Result<Self, LockKeeperClientError> {
        let client = Self::connect(config).await?;
        Self::authenticate(client, account_name, password, config).await
    }

    /// Register a new user who has not yet interacted with the service.
    ///
    /// This only needs to be called once per user; future sessions can be
    /// created with [`LockKeeperClient::authenticated_client()`].
    ///
    /// Output: Returns Ok if successful. To perform further operations, use
    /// [`Self::authenticated_client()`].
    pub async fn register(
        account_name: &AccountName,
        password: &Password,
        config: &Config,
    ) -> Result<(), LockKeeperClientError> {
        let mut rng = StdRng::from_entropy();
        let mut client = Self::connect(config).await?;
        let client_channel =
            Self::create_channel(&mut client, ClientAction::Register, account_name).await?;
        let result =
            Self::handle_registration(client_channel, &mut rng, account_name, password).await;
        match result {
            Ok(export_key) => {
                let client = Self::authenticate(client, account_name, password, config).await?;

                // After authenticating we can create the storage key
                let client_channel = Self::create_channel(
                    &mut client.tonic_client(),
                    ClientAction::CreateStorageKey,
                    account_name,
                )
                .await?;
                Self::handle_create_storage_key(client_channel, &mut rng, account_name, export_key)
                    .await?;

                Ok(())
            }
            Err(e) => {
                error!("{:?}", e);
                Err(e)
            }
        }
    }

    /// Export key material from the key servers.
    ///
    /// Output: If successful, returns the requested key material in byte form.
    pub async fn export_key(&self, key_id: &KeyId) -> Result<Vec<u8>, LockKeeperClientError> {
        // Create channel: this will internally be a `retrieve` channel
        let mut client_channel = Self::create_channel(
            &mut self.tonic_client(),
            ClientAction::Export,
            self.account_name(),
        )
        .await?;
        // Get local-only secret
        let secret = self
            .handle_retrieve(&mut client_channel, key_id, RetrieveContext::LocalOnly)
            .await?;
        // Return secret as bytes
        match secret {
            RetrieveResult::None => Err(LockKeeperClientError::ExportFailed),
            RetrieveResult::ArbitraryKey(local_storage) => Ok(local_storage.secret.into()),
        }
    }

    /// Generate and store an arbitrary secret at the key server
    pub async fn generate_and_store(&self) -> Result<(KeyId, LocalStorage), LockKeeperClientError> {
        let mut client_channel = Self::create_channel(
            &mut self.tonic_client(),
            ClientAction::Generate,
            self.account_name(),
        )
        .await?;
        self.handle_generate(&mut client_channel).await
    }

    /// Retrieve an arbitrary secret from the key server by [`KeyId`]
    pub async fn retrieve(
        &self,
        key_id: &KeyId,
        context: RetrieveContext,
    ) -> Result<RetrieveResult, LockKeeperClientError> {
        let mut client_channel = Self::create_channel(
            &mut self.tonic_client(),
            ClientAction::Retrieve,
            self.account_name(),
        )
        .await?;
        self.handle_retrieve(&mut client_channel, key_id, context)
            .await
    }

    /// Retrieve the log of audit events from the key server for the
    /// authenticated asset owner; optionally, filter for audit events
    /// associated with the specified [`KeyId`].
    ///
    /// The log of audit events includes context
    /// about any action requested and/or taken on the digital asset key,
    /// including which action was requested and by whom, the date, details
    /// about approval or rejection from each key server, the policy engine,
    /// and each asset fiduciary (if relevant), and any other relevant
    /// details.
    ///
    /// The [`lock_keeper::user::UserId`] must match the asset owner
    /// authenticated in the [`crate::LockKeeperClient`], and if specified,
    /// the [`KeyId`] must correspond to a key owned by the
    /// [`lock_keeper::user::UserId`].
    ///
    /// Output: if successful, returns a [`String`] representation of the logs.
    pub async fn retrieve_audit_event_log(
        &self,
        event_type: EventType,
        options: AuditEventOptions,
    ) -> Result<Vec<AuditEvent>, LockKeeperClientError> {
        let mut client_channel = Self::create_channel(
            &mut self.tonic_client(),
            ClientAction::RetrieveAuditEvents,
            self.account_name(),
        )
        .await?;
        self.handle_retrieve_audit_events(&mut client_channel, event_type, options)
            .await
    }
}