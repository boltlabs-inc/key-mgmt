//! Full implementation of the public API for the Lock Keeper client library.
//!
//! This API is designed for use with a local client application - that is, an
//! application running directly on the device of an asset owner. The inputs
//! the asset owner provides should be passed directly to this API without being
//! sent to a separate machine.

mod authenticate;
mod create_storage_key;
mod generate;
mod import;
mod register;
mod remote_generate;
mod remote_sign_bytes;
mod retrieve;
mod retrieve_audit_events;

use crate::{
    client::Password, config::Config, LockKeeperClient, LockKeeperClientError, LockKeeperResponse,
};
use lock_keeper::{
    crypto::{Export, Import, KeyId, Secret, Signable, Signature},
    types::{
        audit_event::{AuditEvent, AuditEventOptions, EventType},
        database::user::AccountName,
        operations::{retrieve::RetrieveContext, ClientAction, RequestMetadata},
    },
};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use tracing::error;

pub use self::{generate::GenerateResult, remote_generate::RemoteGenerateResult};

/// Wrapper for secrets prepared for local storage
#[derive(Debug, Deserialize, Serialize)]
pub struct LocalStorage<T> {
    pub material: T,
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
                    Err(LockKeeperClientError::HealthCheckFailed(
                        "Invalid response from health check method.".to_string(),
                    ))
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Expire the current session and session key for this user.
    pub async fn logout(&self) -> Result<LockKeeperResponse<()>, LockKeeperClientError> {
        // Create channel to send messages to server
        let metadata = self.create_metadata(ClientAction::Logout);
        let client_channel = Self::create_channel(&mut self.tonic_client(), &metadata).await?;

        self.handle_logout(client_channel).await
    }

    /// Authenticate to the Lock Keeper key server as a previously registered
    /// user.
    ///
    /// Output: If successful, returns a [`LockKeeperClient`].
    pub async fn authenticated_client(
        account_name: &AccountName,
        password: &Password,
        config: &Config,
    ) -> Result<LockKeeperResponse<Self>, LockKeeperClientError> {
        let rpc_client = Self::connect(config).await?;
        Self::authenticate(rpc_client, account_name, password, config).await
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
    ) -> Result<LockKeeperResponse<()>, LockKeeperClientError> {
        let mut rng = StdRng::from_entropy();
        let mut client = Self::connect(config).await?;
        let metadata = RequestMetadata::new(account_name, ClientAction::Register, None);
        let client_channel = Self::create_channel(&mut client, &metadata).await?;
        let result =
            Self::handle_registration(client_channel, &mut rng, account_name, password).await;
        match result {
            Ok(master_key) => {
                let LockKeeperResponse {
                    data: client,
                    metadata: response_metadata,
                } = Self::authenticate(client, account_name, password, config).await?;

                // After authenticating we can create the storage key
                let request_metadata = client.create_metadata(ClientAction::CreateStorageKey);
                let client_channel =
                    Self::create_channel(&mut client.tonic_client(), &request_metadata).await?;
                Self::handle_create_storage_key(client_channel, &mut rng, account_name, master_key)
                    .await?;

                Ok(LockKeeperResponse {
                    data: (),
                    metadata: response_metadata,
                })
            }
            Err(e) => {
                error!("{:?}", e);
                Err(e)
            }
        }
    }

    /// Export an arbitrary key from the key servers.
    ///
    /// Calling this function on a signing key will generate an error.
    /// Output: If successful, returns the requested key material in byte form.
    pub async fn export_key(
        &self,
        key_id: &KeyId,
    ) -> Result<LockKeeperResponse<Export>, LockKeeperClientError> {
        // Create channel: this will internally be a `retrieve` channel
        let metadata = self.create_metadata(ClientAction::Export);
        let client_channel = Self::create_channel(&mut self.tonic_client(), &metadata).await?;
        // Get local-only secret
        let LockKeeperResponse { data, metadata } = self
            .handle_retrieve(client_channel, key_id, RetrieveContext::LocalOnly)
            .await?;

        let local_storage = data.ok_or(LockKeeperClientError::ExportFailed)?;
        let exported_secret = Export::from(local_storage.material);

        Ok(LockKeeperResponse {
            data: exported_secret,
            metadata,
        })
    }

    /// Export signing key pair material from the key servers.
    ///
    /// Calling this function on an arbitrary key will generated an error.
    /// Output: If successful, returns the requested key material in byte form.
    pub async fn export_signing_key(
        &self,
        key_id: &KeyId,
    ) -> Result<LockKeeperResponse<Export>, LockKeeperClientError> {
        // Create channel: this will internally be a `retrieve` channel
        let metadata = self.create_metadata(ClientAction::ExportSigningKey);
        let client_channel = Self::create_channel(&mut self.tonic_client(), &metadata).await?;

        // Get local-only secret
        let LockKeeperResponse { data, metadata } = self
            .handle_retrieve_signing_key(client_channel, key_id, RetrieveContext::LocalOnly)
            .await?;

        let local_storage = data.ok_or(LockKeeperClientError::ExportFailed)?;
        let exported_signing_key = Export::from(local_storage.material);

        Ok(LockKeeperResponse {
            data: exported_signing_key,
            metadata,
        })
    }

    /// Generate an arbitrary secret client-side, store this secret in the key
    /// server.
    pub async fn generate_and_store(
        &self,
    ) -> Result<LockKeeperResponse<GenerateResult>, LockKeeperClientError> {
        let metadata = self.create_metadata(ClientAction::Generate);
        let client_channel = Self::create_channel(&mut self.tonic_client(), &metadata).await?;

        self.handle_generate(client_channel).await
    }

    /// Import signing key material to the key server
    pub async fn import_signing_key(
        &self,
        key_material: Import,
    ) -> Result<LockKeeperResponse<KeyId>, LockKeeperClientError> {
        let metadata = self.create_metadata(ClientAction::ImportSigningKey);
        let client_channel = Self::create_channel(&mut self.tonic_client(), &metadata).await?;

        self.handle_import_signing_key(client_channel, key_material)
            .await
    }

    /// Retrieve an arbitrary secret from the key server by [`KeyId`]
    ///
    /// This operation will fail if it is called on a signing key.
    pub async fn retrieve(
        &self,
        key_id: &KeyId,
        context: RetrieveContext,
    ) -> Result<LockKeeperResponse<Option<LocalStorage<Secret>>>, LockKeeperClientError> {
        let metadata = self.create_metadata(ClientAction::Retrieve);
        let client_channel = Self::create_channel(&mut self.tonic_client(), &metadata).await?;

        self.handle_retrieve(client_channel, key_id, context).await
    }

    /// Request that the server generate a new signing key.
    pub async fn remote_generate(
        &self,
    ) -> Result<LockKeeperResponse<RemoteGenerateResult>, LockKeeperClientError> {
        let metadata = self.create_metadata(ClientAction::RemoteGenerate);
        let client_channel = Self::create_channel(&mut self.tonic_client(), &metadata).await?;

        self.handle_remote_generate(client_channel).await
    }

    /// Sign an arbitrary blob of bytes with a remotely generated
    /// [`SigningKeyPair`][lock_keeper::crypto::SigningKeyPair] and return the
    /// resulting [`Signature`].
    pub async fn remote_sign_bytes(
        &self,
        key_id: KeyId,
        bytes: impl Signable,
    ) -> Result<LockKeeperResponse<Signature>, LockKeeperClientError> {
        let metadata = self.create_metadata(ClientAction::RemoteSignBytes);
        let client_channel = Self::create_channel(&mut self.tonic_client(), &metadata).await?;

        self.handle_remote_sign_bytes(client_channel, key_id, bytes)
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
    /// The [`lock_keeper::types::database::user::UserId`] must match the asset
    /// owner authenticated in the [`crate::LockKeeperClient`], and if
    /// specified, the [`KeyId`] must correspond to a key owned by the
    /// [`lock_keeper::types::database::user::UserId`].
    ///
    /// Output: if successful, returns a [`String`] representation of the logs.
    pub async fn retrieve_audit_event_log(
        &self,
        event_type: EventType,
        options: AuditEventOptions,
    ) -> Result<LockKeeperResponse<Vec<AuditEvent>>, LockKeeperClientError> {
        let metadata = self.create_metadata(ClientAction::RetrieveAuditEvents);
        let client_channel = Self::create_channel(&mut self.tonic_client(), &metadata).await?;

        self.handle_retrieve_audit_events(client_channel, event_type, options)
            .await
    }
}
