pub(crate) mod opaque_storage;
mod operation;
mod service;
pub(crate) mod session_key_cache;

pub(crate) use operation::Operation;
pub use service::start_lock_keeper_server;

use crate::{config::Config, error::LockKeeperServerError, operations};

use lock_keeper::{
    crypto::KeyId,
    rpc::{lock_keeper_rpc_server::LockKeeperRpc, HealthCheck},
    types::{Message, MessageStream},
};

use crate::{database::DataStore, server::session_key_cache::SessionKeyCache};
use rand::{rngs::StdRng, SeedableRng};
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

pub struct LockKeeperKeyServer<DB: DataStore> {
    config: Arc<Config>,
    db: Arc<DB>,
    rng: Arc<Mutex<StdRng>>,
    session_key_cache: Arc<Mutex<SessionKeyCache>>,
}

impl<DB: DataStore> LockKeeperKeyServer<DB> {
    pub fn new(db: Arc<DB>, config: Config) -> Result<Self, LockKeeperServerError> {
        let rng = StdRng::from_entropy();

        Ok(Self {
            config: Arc::new(config.clone()),
            db,
            rng: Arc::new(Mutex::new(rng)),
            session_key_cache: Arc::new(Mutex::new(SessionKeyCache::new(config.session_timeout))),
        })
    }

    pub(crate) fn context(&self) -> Context<DB> {
        Context {
            config: self.config.clone(),
            db: self.db.clone(),
            rng: self.rng.clone(),
            key_id: None,
            session_key_cache: self.session_key_cache.clone(),
        }
    }
}

pub(crate) struct Context<DB: DataStore> {
    pub db: Arc<DB>,
    pub config: Arc<Config>,
    pub rng: Arc<Mutex<StdRng>>,
    pub key_id: Option<KeyId>,
    /// Our user session keys are held in this cache after authentication.
    pub session_key_cache: Arc<Mutex<SessionKeyCache>>,
}

#[tonic::async_trait]
impl<DB: DataStore> LockKeeperRpc for LockKeeperKeyServer<DB> {
    type AuthenticateStream = MessageStream;
    type CreateStorageKeyStream = MessageStream;
    type GenerateStream = MessageStream;
    type ImportSigningKeyStream = MessageStream;
    type LogoutStream = MessageStream;
    type RegisterStream = MessageStream;
    type RemoteGenerateStream = MessageStream;
    type RemoteSignBytesStream = MessageStream;
    type RetrieveStream = MessageStream;
    type RetrieveAuditEventsStream = MessageStream;
    type RetrieveSigningKeyStream = MessageStream;
    type RetrieveStorageKeyStream = MessageStream;

    async fn health(&self, _: Request<HealthCheck>) -> Result<Response<HealthCheck>, Status> {
        Ok(Response::new(HealthCheck { check: true }))
    }

    async fn register(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RegisterStream>, Status> {
        Ok(operations::Register
            .handle_request(self.context(), request)
            .await?)
    }

    async fn authenticate(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::AuthenticateStream>, Status> {
        Ok(operations::Authenticate
            .handle_request(self.context(), request)
            .await?)
    }

    async fn logout(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::LogoutStream>, Status> {
        Ok(operations::Logout
            .handle_request(self.context(), request)
            .await?)
    }

    async fn create_storage_key(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::CreateStorageKeyStream>, Status> {
        Ok(operations::CreateStorageKey
            .handle_authenticated_request(self.context(), request)
            .await?)
    }

    async fn generate(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::GenerateStream>, Status> {
        Ok(operations::Generate
            .handle_authenticated_request(self.context(), request)
            .await?)
    }

    async fn import_signing_key(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::ImportSigningKeyStream>, Status> {
        Ok(operations::ImportSigningKey
            .handle_authenticated_request(self.context(), request)
            .await?)
    }

    async fn remote_generate(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RemoteGenerateStream>, Status> {
        Ok(operations::RemoteGenerate
            .handle_authenticated_request(self.context(), request)
            .await?)
    }

    async fn remote_sign_bytes(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RemoteSignBytesStream>, Status> {
        Ok(operations::RemoteSignBytes
            .handle_authenticated_request(self.context(), request)
            .await?)
    }

    async fn retrieve(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RetrieveStream>, Status> {
        Ok(operations::Retrieve
            .handle_authenticated_request(self.context(), request)
            .await?)
    }

    async fn retrieve_audit_events(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RetrieveAuditEventsStream>, Status> {
        Ok(operations::RetrieveAuditEvents
            .handle_authenticated_request(self.context(), request)
            .await?)
    }

    async fn retrieve_storage_key(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RetrieveStorageKeyStream>, Status> {
        Ok(operations::RetrieveStorageKey
            .handle_authenticated_request(self.context(), request)
            .await?)
    }

    async fn retrieve_signing_key(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RetrieveSigningKeyStream>, Status> {
        Ok(operations::RetrieveSigningKey
            .handle_authenticated_request(self.context(), request)
            .await?)
    }
}
