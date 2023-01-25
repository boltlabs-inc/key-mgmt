//! Full implementation of the public API for the Lock Keeper client library.
//!
//! This API is designed for use with a local client application - that is, an
//! application running directly on the device of an asset owner. The inputs
//! the asset owner provides should be passed directly to this API without being
//! sent to a separate machine.

mod authenticate;
mod create_storage_key;
mod generate_secret;
mod get_user_id;
mod import;
mod register;
mod remote_generate_signing_key;
mod remote_sign_bytes;
mod retrieve;
mod retrieve_audit_events;

use crate::{
    client::Password, config::Config, response::Metadata, LockKeeperClient, LockKeeperClientError,
    LockKeeperResponse,
};
use lock_keeper::{
    crypto::{Export, Import, KeyId, Secret, Signable, Signature},
    types::{
        audit_event::{AuditEvent, AuditEventOptions, EventType},
        database::account::AccountName,
        operations::{retrieve_secret::RetrieveContext, ClientAction, RequestMetadata},
    },
};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

pub use self::{
    generate_secret::GenerateResult, remote_generate_signing_key::RemoteGenerateResult,
};

/// Wrapper for secrets prepared for local storage
#[derive(Debug, Deserialize, Serialize)]
pub struct LocalStorage<T> {
    pub material: T,
}

impl<T> LockKeeperClient<T>
where
    T: Clone,
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<tonic::codegen::StdError>,
    T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
    <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
{
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
    pub async fn logout(&self) -> LockKeeperResponse<()> {
        // Create channel to send messages to server
        let request_id = Uuid::new_v4();
        LockKeeperResponse {
            result: self.handle_logout(request_id).await,
            metadata: Some(Metadata { request_id }),
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
    ) -> LockKeeperResponse<Self> {
        let request_id = Uuid::new_v4();
        LockKeeperResponse {
            result: Self::authenticate(None, account_name, password, config, request_id).await,
            metadata: Some(Metadata { request_id }),
        }
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
    ) -> LockKeeperResponse<()> {
        let request_id = Uuid::new_v4();
        LockKeeperResponse {
            result: Self::register_helper(account_name, password, config, request_id).await,
            metadata: Some(Metadata { request_id }),
        }
    }

    async fn register_helper(
        account_name: &AccountName,
        password: &Password,
        config: &Config,
        request_id: Uuid,
    ) -> Result<(), LockKeeperClientError> {
        let rng = StdRng::from_entropy();
        let mut client = Self::connect(config).await?;
        let metadata = RequestMetadata::new(account_name, ClientAction::Register, None, request_id);
        let rng_arc_mutex = Arc::new(Mutex::new(rng));
        let client_channel = Self::create_channel(&mut client, &metadata).await?;
        let master_key = Self::handle_registration(
            client_channel,
            rng_arc_mutex.clone(),
            account_name,
            password,
        )
        .await?;
        let client =
            Self::authenticate(Some(client), account_name, password, config, request_id).await?;
        // After authenticating we can create the storage key
        let request_metadata = client.create_metadata(ClientAction::CreateStorageKey, request_id);
        let client_channel = LockKeeperClient::create_authenticated_channel(
            &mut client.tonic_client(),
            &request_metadata,
            client.session_key().clone(),
            rng_arc_mutex.clone(),
        )
        .await?;
        client
            .handle_create_storage_key(client_channel, rng_arc_mutex, master_key)
            .await?;

        Ok(())
    }

    /// Export an arbitrary key from the key servers.
    ///
    /// Calling this function on a signing key will generate an error.
    /// Output: If successful, returns the requested key material in byte form.
    pub async fn export_secret(&self, key_id: &KeyId) -> LockKeeperResponse<Export> {
        let request_id = Uuid::new_v4();
        LockKeeperResponse {
            result: self.export_secret_helper(key_id, request_id).await,
            metadata: Some(Metadata { request_id }),
        }
    }

    async fn export_secret_helper(
        &self,
        key_id: &KeyId,
        request_id: Uuid,
    ) -> Result<Export, LockKeeperClientError> {
        let metadata = self.create_metadata(ClientAction::ExportSecret, request_id);
        let client_channel = Self::create_authenticated_channel(
            &mut self.tonic_client(),
            &metadata,
            self.session_key().clone(),
            self.rng.clone(),
        )
        .await?;
        // Get local-only secret
        let local_storage = self
            .handle_retrieve_secret(
                client_channel,
                key_id,
                RetrieveContext::LocalOnly,
                request_id,
            )
            .await?
            .ok_or(LockKeeperClientError::ExportFailed)?;

        Ok(Export::from(local_storage.material))
    }

    /// Export signing key pair material from the key servers.
    ///
    /// Calling this function on an arbitrary key will generated an error.
    /// Output: If successful, returns the requested key material in byte form.
    pub async fn export_signing_key(&self, key_id: &KeyId) -> LockKeeperResponse<Export> {
        let request_id = Uuid::new_v4();
        LockKeeperResponse {
            result: self.export_signing_key_helper(key_id, request_id).await,
            metadata: Some(Metadata { request_id }),
        }
    }

    async fn export_signing_key_helper(
        &self,
        key_id: &KeyId,
        request_id: Uuid,
    ) -> Result<Export, LockKeeperClientError> {
        let metadata = self.create_metadata(ClientAction::ExportSigningKey, request_id);
        let client_channel = Self::create_authenticated_channel(
            &mut self.tonic_client(),
            &metadata,
            self.session_key().clone(),
            self.rng.clone(),
        )
        .await?;
        // Get local-only secret
        let local_storage = self
            .handle_retrieve_signing_key(client_channel, key_id, RetrieveContext::LocalOnly)
            .await?
            .ok_or(LockKeeperClientError::ExportFailed)?;

        Ok(Export::from(local_storage.material))
    }

    /// Generate an arbitrary secret client-side, store this secret in the key
    /// server.
    pub async fn generate_secret(&self) -> LockKeeperResponse<GenerateResult> {
        let request_id = Uuid::new_v4();
        LockKeeperResponse {
            result: self.generate_secret_helper(request_id).await,
            metadata: Some(Metadata { request_id }),
        }
    }

    async fn generate_secret_helper(
        &self,
        request_id: Uuid,
    ) -> Result<GenerateResult, LockKeeperClientError> {
        let metadata = self.create_metadata(ClientAction::GenerateSecret, request_id);
        let client_channel = Self::create_authenticated_channel(
            &mut self.tonic_client(),
            &metadata,
            self.session_key().clone(),
            self.rng.clone(),
        )
        .await?;

        self.handle_generate_secret(client_channel, request_id)
            .await
    }

    /// Import signing key material to the key server
    pub async fn import_signing_key(&self, key_material: Import) -> LockKeeperResponse<KeyId> {
        let request_id = Uuid::new_v4();
        LockKeeperResponse {
            result: self
                .import_signing_key_helper(key_material, request_id)
                .await,
            metadata: Some(Metadata { request_id }),
        }
    }

    async fn import_signing_key_helper(
        &self,
        key_material: Import,
        request_id: Uuid,
    ) -> Result<KeyId, LockKeeperClientError> {
        let metadata = self.create_metadata(ClientAction::ImportSigningKey, request_id);
        let client_channel = Self::create_authenticated_channel(
            &mut self.tonic_client(),
            &metadata,
            self.session_key().clone(),
            self.rng.clone(),
        )
        .await?;
        self.handle_import_signing_key(client_channel, key_material)
            .await
    }

    /// Retrieve a secret from the key server by [`KeyId`]
    ///
    /// This operation will fail if it is called on a signing key.
    pub async fn retrieve_secret(
        &self,
        key_id: &KeyId,
        context: RetrieveContext,
    ) -> LockKeeperResponse<Option<LocalStorage<Secret>>> {
        let request_id = Uuid::new_v4();
        LockKeeperResponse {
            result: self
                .retrieve_secret_helper(key_id, context, request_id)
                .await,
            metadata: Some(Metadata { request_id }),
        }
    }

    async fn retrieve_secret_helper(
        &self,
        key_id: &KeyId,
        context: RetrieveContext,
        request_id: Uuid,
    ) -> Result<Option<LocalStorage<Secret>>, LockKeeperClientError> {
        let metadata = self.create_metadata(ClientAction::RetrieveSecret, request_id);
        let client_channel = Self::create_authenticated_channel(
            &mut self.tonic_client(),
            &metadata,
            self.session_key().clone(),
            self.rng.clone(),
        )
        .await?;

        self.handle_retrieve_secret(client_channel, key_id, context, request_id)
            .await
    }

    /// Request that the server generate a new signing key.
    pub async fn remote_generate(&self) -> LockKeeperResponse<RemoteGenerateResult> {
        let request_id = Uuid::new_v4();
        LockKeeperResponse {
            result: self.remote_generate_helper(request_id).await,
            metadata: Some(Metadata { request_id }),
        }
    }

    async fn remote_generate_helper(
        &self,
        request_id: Uuid,
    ) -> Result<RemoteGenerateResult, LockKeeperClientError> {
        let metadata = self.create_metadata(ClientAction::RemoteGenerateSigningKey, request_id);
        let client_channel = Self::create_authenticated_channel(
            &mut self.tonic_client(),
            &metadata,
            self.session_key().clone(),
            self.rng.clone(),
        )
        .await?;

        self.handle_remote_generate_signing_key(client_channel)
            .await
    }

    /// Sign an arbitrary blob of bytes with a remotely generated
    /// [`SigningKeyPair`][lock_keeper::crypto::SigningKeyPair] and return the
    /// resulting [`Signature`].
    pub async fn remote_sign_bytes(
        &self,
        key_id: KeyId,
        bytes: impl Signable,
    ) -> LockKeeperResponse<Signature> {
        let request_id = Uuid::new_v4();
        LockKeeperResponse {
            result: self
                .remote_sign_bytes_helper(key_id, bytes, request_id)
                .await,
            metadata: Some(Metadata { request_id }),
        }
    }

    async fn remote_sign_bytes_helper(
        &self,
        key_id: KeyId,
        bytes: impl Signable,
        request_id: Uuid,
    ) -> Result<Signature, LockKeeperClientError> {
        let metadata = self.create_metadata(ClientAction::RemoteSignBytes, request_id);
        let client_channel = Self::create_authenticated_channel(
            &mut self.tonic_client(),
            &metadata,
            self.session_key().clone(),
            self.rng.clone(),
        )
        .await?;
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
    /// If specified, the [`KeyId`] must correspond to a key owned by the
    /// authenticated account.
    ///
    /// Output: if successful, returns a [`String`] representation of the logs.
    pub async fn retrieve_audit_event_log(
        &self,
        event_type: EventType,
        options: AuditEventOptions,
    ) -> LockKeeperResponse<Vec<AuditEvent>> {
        let request_id = Uuid::new_v4();
        LockKeeperResponse {
            result: self
                .retrieve_audit_event_log_helper(event_type, options, request_id)
                .await,
            metadata: Some(Metadata { request_id }),
        }
    }

    async fn retrieve_audit_event_log_helper(
        &self,
        event_type: EventType,
        options: AuditEventOptions,
        request_id: Uuid,
    ) -> Result<Vec<AuditEvent>, LockKeeperClientError> {
        let metadata = self.create_metadata(ClientAction::RetrieveAuditEvents, request_id);
        let client_channel = Self::create_authenticated_channel(
            &mut self.tonic_client(),
            &metadata,
            self.session_key().clone(),
            self.rng.clone(),
        )
        .await?;
        self.handle_retrieve_audit_events(client_channel, event_type, options)
            .await
    }
}
