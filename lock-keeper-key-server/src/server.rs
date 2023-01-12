pub(crate) mod opaque_storage;
mod operation;
mod service;
pub mod session_cache;

pub(crate) use operation::Operation;
pub use service::start_lock_keeper_server;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, instrument};

use crate::{config::Config, error::LockKeeperServerError, operations};

use lock_keeper::{
    constants::METADATA,
    crypto::KeyId,
    infrastructure::channel::{Authenticated, ServerChannel, Unauthenticated},
    rpc::{lock_keeper_rpc_server::LockKeeperRpc, HealthCheck},
    types::{operations::RequestMetadata, Message, MessageStream},
};

use crate::{database::DataStore, server::session_cache::SessionCache};
use rand::{rngs::StdRng, SeedableRng};
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status, Streaming};

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

pub(crate) struct Context<DB: DataStore> {
    pub db: Arc<DB>,
    pub config: Arc<Config>,
    pub rng: Arc<Mutex<StdRng>>,
    pub key_id: Option<KeyId>,
    /// Our user session keys are held in this cache after authentication.
    pub session_cache: Arc<Mutex<dyn SessionCache>>,
}

#[tonic::async_trait]
impl<DB: DataStore> LockKeeperRpc for LockKeeperKeyServer<DB> {
    type AuthenticateStream = MessageStream;
    type CreateStorageKeyStream = MessageStream;
    type GenerateSecretStream = MessageStream;
    type GetUserIdStream = MessageStream;
    type ImportSigningKeyStream = MessageStream;
    type LogoutStream = MessageStream;
    type RegisterStream = MessageStream;
    type RemoteGenerateStream = MessageStream;
    type RemoteSignBytesStream = MessageStream;
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
        operations::Register
            .handle_request(self.context(), channel)
            .await?;
        Ok(response)
    }

    async fn authenticate(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::AuthenticateStream>, Status> {
        let (channel, response) = self.create_unauthenticated_channel(request).await?;
        operations::Authenticate
            .handle_request(self.context(), channel)
            .await?;
        Ok(response)
    }

    async fn logout(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::LogoutStream>, Status> {
        let (channel, response) = self.create_authenticated_channel(request).await?;
        operations::Logout
            .handle_request(self.context(), channel)
            .await?;
        Ok(response)
    }

    async fn create_storage_key(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::CreateStorageKeyStream>, Status> {
        let (channel, response) = self.create_authenticated_channel(request).await?;
        operations::CreateStorageKey
            .handle_request(self.context(), channel)
            .await?;
        Ok(response)
    }

    async fn generate_secret(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::GenerateSecretStream>, Status> {
        let (channel, response) = self.create_authenticated_channel(request).await?;
        operations::GenerateSecret
            .handle_request(self.context(), channel)
            .await?;
        Ok(response)
    }

    async fn get_user_id(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::GetUserIdStream>, Status> {
        // `create_authenticated_channel` gets the `user_id` out of the request metadata
        // in order to retrieve the session key. Since the client doesn't know
        // its `user_id` before the `GetUserId` operation is called, we can't call the
        // normal `create_authenticated_channel` method. Instead, we'll look up
        // the user ID ourselves and upgrade an unauthenticated channel manually.
        let context = self.context();

        // Get the user ID before `create_unauthenticated_channel` consumes the request
        let metadata: RequestMetadata = request
            .metadata()
            .get(METADATA)
            // We'll just use the existing error in the `lock_keeper` crate since this is a weird
            // case.
            .ok_or(lock_keeper::LockKeeperError::MetadataNotFound)?
            .try_into()?;

        let session_id = metadata
            .session_id()
            .ok_or(LockKeeperServerError::SessionIdNotFound)?;

        let user_id = context
            .db
            .find_account(metadata.account_name())
            .await
            .map_err(LockKeeperServerError::database)?
            .ok_or(LockKeeperServerError::InvalidAccount)?
            .user_id;

        // Now work through the normal process to create an authenticated channel
        let (channel, response) = self.create_unauthenticated_channel(request).await?;

        let session_key = {
            let session_cache = context.session_cache.lock().await;
            let session = session_cache
                .find_session(*session_id, user_id.clone())
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            session.session_key(&context)?
        };

        let mut channel = channel.into_authenticated(session_key, context.rng.clone());
        // Manually set the user_id in the channel since it's not in the metadata
        channel.set_user_id(user_id);

        operations::GetUserId
            .handle_request(self.context(), channel)
            .await?;

        Ok(response)
    }

    async fn import_signing_key(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::ImportSigningKeyStream>, Status> {
        let (channel, response) = self.create_authenticated_channel(request).await?;
        operations::ImportSigningKey
            .handle_request(self.context(), channel)
            .await?;
        Ok(response)
    }

    async fn remote_generate(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RemoteGenerateStream>, Status> {
        let (channel, response) = self.create_authenticated_channel(request).await?;
        operations::RemoteGenerateSigningKey
            .handle_request(self.context(), channel)
            .await?;
        Ok(response)
    }

    async fn remote_sign_bytes(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RemoteSignBytesStream>, Status> {
        let (channel, response) = self.create_authenticated_channel(request).await?;
        operations::RemoteSignBytes
            .handle_request(self.context(), channel)
            .await?;
        Ok(response)
    }

    async fn retrieve_secret(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RetrieveSecretStream>, Status> {
        let (channel, response) = self.create_authenticated_channel(request).await?;
        operations::RetrieveSecret
            .handle_request(self.context(), channel)
            .await?;
        Ok(response)
    }

    async fn retrieve_audit_events(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RetrieveAuditEventsStream>, Status> {
        let (channel, response) = self.create_authenticated_channel(request).await?;
        operations::RetrieveAuditEvents
            .handle_request(self.context(), channel)
            .await?;
        Ok(response)
    }

    async fn retrieve_storage_key(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RetrieveStorageKeyStream>, Status> {
        let (channel, response) = self.create_authenticated_channel(request).await?;
        operations::RetrieveStorageKey
            .handle_request(self.context(), channel)
            .await?;
        Ok(response)
    }
}

impl<DB: DataStore> LockKeeperKeyServer<DB> {
    #[instrument(skip_all, err(Debug))]
    async fn create_unauthenticated_channel(
        &self,
        request: Request<Streaming<Message>>,
    ) -> Result<(ServerChannel<Unauthenticated>, Response<MessageStream>), LockKeeperServerError>
    {
        debug!("Creating new unauthenticated channel.");
        let (channel, rx) = ServerChannel::new(request)?;
        let response = Response::new(ReceiverStream::new(rx));

        Ok((channel, response))
    }

    #[instrument(skip_all, err(Debug))]
    async fn create_authenticated_channel(
        &self,
        request: Request<Streaming<Message>>,
    ) -> Result<
        (
            ServerChannel<Authenticated<StdRng>>,
            Response<MessageStream>,
        ),
        LockKeeperServerError,
    > {
        debug!("Creating new authenticated channel.");
        let (channel, response) = self.create_unauthenticated_channel(request).await?;

        // Upgrade channel to be authenticated
        let user_id = channel
            .metadata()
            .user_id()
            .ok_or(LockKeeperServerError::InvalidAccount)?
            .clone();
        let session_id = channel
            .metadata()
            .session_id()
            .ok_or(LockKeeperServerError::SessionIdNotFound)?;
        let context = self.context();

        let session_key = {
            let session_cache = context.session_cache.lock().await;
            let session = session_cache.find_session(*session_id, user_id).await?;
            session.session_key(&context)?
        };

        let channel = channel.into_authenticated(session_key, context.rng.clone());

        Ok((channel, response))
    }
}
