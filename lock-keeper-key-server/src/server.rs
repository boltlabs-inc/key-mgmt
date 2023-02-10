pub(crate) mod channel;
pub(crate) mod context;
pub mod database;
pub(crate) mod opaque_storage;
mod operation;
mod service;
pub mod session_cache;

pub(crate) use context::Context;
pub(crate) use operation::Operation;
pub use service::start_lock_keeper_server;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, instrument};

use crate::{config::Config, error::LockKeeperServerError, operations};

use lock_keeper::{
    rpc::{lock_keeper_rpc_server::LockKeeperRpc, HealthCheck},
    types::{Message, MessageStream},
};

use crate::server::{database::DataStore, session_cache::SessionCache};
use rand::{rngs::StdRng, SeedableRng};
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status, Streaming};

use self::{
    channel::{Authenticated, Channel, Unauthenticated},
    operation::{handle_authenticated_request, handle_unauthenticated_request},
};

pub struct LockKeeperKeyServer<DB: DataStore> {
    config: Arc<Config>,
    db: Arc<DB>,
    rng: Arc<Mutex<StdRng>>,
    session_cache: Arc<Mutex<dyn SessionCache>>,
}

impl<DB: DataStore> LockKeeperKeyServer<DB> {
    pub fn new(
        db: Arc<DB>,
        session_key_cache: Arc<Mutex<dyn SessionCache>>,
        config: Config,
    ) -> Result<Self, LockKeeperServerError> {
        let rng = StdRng::from_entropy();

        Ok(Self {
            config: Arc::new(config),
            db,
            rng: Arc::new(Mutex::new(rng)),
            session_cache: session_key_cache,
        })
    }

    pub(crate) fn context(&self) -> Context<DB> {
        Context {
            config: self.config.clone(),
            db: self.db.clone(),
            rng: self.rng.clone(),
            key_id: None,
            session_cache: self.session_cache.clone(),
        }
    }
}

#[tonic::async_trait]
impl<DB: DataStore> LockKeeperRpc for LockKeeperKeyServer<DB> {
    type AuthenticateStream = MessageStream;
    type CreateStorageKeyStream = MessageStream;
    type GenerateSecretStream = MessageStream;
    type GetUserIdStream = MessageStream;
    type ImportSigningKeyStream = MessageStream;
    type LogoutStream = MessageStream;
    type StoreServerEncryptedBlobStream = MessageStream;
    type RegisterStream = MessageStream;
    type RemoteGenerateStream = MessageStream;
    type RemoteSignBytesStream = MessageStream;
    type RetrieveServerEncryptedBlobStream = MessageStream;
    type RetrieveSecretStream = MessageStream;
    type RetrieveAuditEventsStream = MessageStream;
    type RetrieveStorageKeyStream = MessageStream;

    async fn health(&self, _: Request<HealthCheck>) -> Result<Response<HealthCheck>, Status> {
        Ok(Response::new(HealthCheck { check: true }))
    }

    async fn register(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RegisterStream>, Status> {
        let (channel, response) = self.create_unauthenticated_channel(request).await?;
        handle_unauthenticated_request(operations::Register, self.context(), channel).await?;
        Ok(response)
    }

    async fn authenticate(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::AuthenticateStream>, Status> {
        let (channel, response) = self.create_unauthenticated_channel(request).await?;
        handle_unauthenticated_request(operations::Authenticate, self.context(), channel).await?;
        Ok(response)
    }

    async fn logout(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::LogoutStream>, Status> {
        let (channel, response) = self.create_authenticated_channel(request).await?;
        handle_authenticated_request(operations::Logout, self.context(), channel).await?;
        Ok(response)
    }

    async fn create_storage_key(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::CreateStorageKeyStream>, Status> {
        let (channel, response) = self.create_authenticated_channel(request).await?;
        handle_authenticated_request(operations::CreateStorageKey, self.context(), channel).await?;
        Ok(response)
    }

    async fn generate_secret(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::GenerateSecretStream>, Status> {
        let (channel, response) = self.create_authenticated_channel(request).await?;
        handle_authenticated_request(operations::GenerateSecret, self.context(), channel).await?;
        Ok(response)
    }

    async fn get_user_id(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::GetUserIdStream>, Status> {
        let (channel, response) = self.create_authenticated_channel(request).await?;
        handle_authenticated_request(operations::GetUserId, self.context(), channel).await?;
        Ok(response)
    }

    async fn import_signing_key(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::ImportSigningKeyStream>, Status> {
        let (channel, response) = self.create_authenticated_channel(request).await?;
        handle_authenticated_request(operations::ImportSigningKey, self.context(), channel).await?;
        Ok(response)
    }

    async fn store_server_encrypted_blob(
        &self,
        request: Request<Streaming<Message>>,
    ) -> Result<Response<Self::StoreServerEncryptedBlobStream>, Status> {
        let (channel, response) = self.create_authenticated_channel(request).await?;
        handle_authenticated_request(
            operations::StoreServerEncryptedBlob,
            self.context(),
            channel,
        )
        .await?;
        Ok(response)
    }

    async fn remote_generate(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RemoteGenerateStream>, Status> {
        let (channel, response) = self.create_authenticated_channel(request).await?;
        handle_authenticated_request(
            operations::RemoteGenerateSigningKey,
            self.context(),
            channel,
        )
        .await?;
        Ok(response)
    }

    async fn remote_sign_bytes(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RemoteSignBytesStream>, Status> {
        let (channel, response) = self.create_authenticated_channel(request).await?;
        handle_authenticated_request(operations::RemoteSignBytes, self.context(), channel).await?;
        Ok(response)
    }

    async fn retrieve_server_encrypted_blob(
        &self,
        request: Request<Streaming<Message>>,
    ) -> Result<Response<Self::RetrieveServerEncryptedBlobStream>, Status> {
        let (channel, response) = self.create_authenticated_channel(request).await?;
        handle_authenticated_request(
            operations::RetrieveServerEncryptedBlob,
            self.context(),
            channel,
        )
        .await?;
        Ok(response)
    }

    async fn retrieve_secret(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RetrieveSecretStream>, Status> {
        let (channel, response) = self.create_authenticated_channel(request).await?;
        handle_authenticated_request(operations::RetrieveSecret, self.context(), channel).await?;
        Ok(response)
    }

    async fn retrieve_audit_events(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RetrieveAuditEventsStream>, Status> {
        let (channel, response) = self.create_authenticated_channel(request).await?;
        handle_authenticated_request(operations::RetrieveAuditEvents, self.context(), channel)
            .await?;

        Ok(response)
    }

    async fn retrieve_storage_key(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RetrieveStorageKeyStream>, Status> {
        let (channel, response) = self.create_authenticated_channel(request).await?;
        handle_authenticated_request(operations::RetrieveStorageKey, self.context(), channel)
            .await?;
        Ok(response)
    }
}

impl<DB: DataStore> LockKeeperKeyServer<DB> {
    #[instrument(skip_all, err(Debug))]
    async fn create_unauthenticated_channel(
        &self,
        request: Request<Streaming<Message>>,
    ) -> Result<(Channel<Unauthenticated>, Response<MessageStream>), LockKeeperServerError> {
        debug!("Creating new unauthenticated channel.");
        let (channel, rx) = Channel::new(request)?;
        let response = Response::new(ReceiverStream::new(rx));

        Ok((channel, response))
    }

    /// Server-side instantiation of our channels. The `request` argument
    /// contains the receiving end of a channel which the client sent us
    /// with its gRPC call.
    ///
    /// Returns our tuple containing a [`Channel`] for the server to use and a
    /// [`Response`] to send back to the client via the return value of the
    /// gRPC call.
    #[instrument(skip_all, err(Debug))]
    async fn create_authenticated_channel(
        &self,
        request: Request<Streaming<Message>>,
    ) -> Result<(Channel<Authenticated<StdRng>>, Response<MessageStream>), LockKeeperServerError>
    {
        debug!("Creating new authenticated channel.");
        let (channel, response) = self.create_unauthenticated_channel(request).await?;

        // Upgrade channel to be authenticated
        let session_id = channel
            .metadata()
            .session_id()
            .ok_or(LockKeeperServerError::SessionIdNotFound)?;
        let context = self.context();

        let session = {
            let session_cache = context.session_cache.lock().await;
            session_cache.find_session(*session_id).await?
        };

        let session_key = session.session_key(&context)?;

        // Validate that there is an account for the given session ID and store it in
        // the channel so that operations can use it.
        let account = context
            .db
            .find_account(session.account_id)
            .await?
            .ok_or(LockKeeperServerError::InvalidAccount)?;

        let channel = channel.into_authenticated(account, session_key, context.rng.clone());

        Ok((channel, response))
    }
}
