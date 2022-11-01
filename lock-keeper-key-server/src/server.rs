pub(crate) mod opaque_storage;
mod operation;
mod service;
pub(crate) mod session_key_cache;

pub(crate) use operation::Operation;
pub use service::start_lock_keeper_server;

use crate::{database::Database, error::LockKeeperServerError, operations};

use lock_keeper::{
    config::server::{Config, Service},
    constants::METADATA,
    crypto::KeyId,
    rpc::{lock_keeper_rpc_server::LockKeeperRpc, HealthCheck},
    types::{Message, MessageStream},
};

use crate::server::session_key_cache::SessionKeyCache;
use lock_keeper::types::operations::RequestMetadata;
use rand::{rngs::StdRng, SeedableRng};
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

///
#[allow(unused)]
#[derive(Debug)]
pub struct LockKeeperKeyServer {
    config: Config,
    db: Arc<Database>,
    service: Arc<Service>,
    rng: Arc<Mutex<StdRng>>,
    session_key_cache: Arc<Mutex<SessionKeyCache>>,
}

impl LockKeeperKeyServer {
    pub fn new(
        db: Database,
        config: Config,
        service: Arc<Service>,
    ) -> Result<Self, LockKeeperServerError> {
        let rng = StdRng::from_entropy();

        Ok(Self {
            config,
            db: Arc::new(db),
            service,
            rng: Arc::new(Mutex::new(rng)),
            session_key_cache: Arc::new(Mutex::new(SessionKeyCache::default())),
        })
    }

    pub(crate) fn context(
        &self,
        request: &Request<tonic::Streaming<Message>>,
    ) -> Result<Context, LockKeeperServerError> {
        // Parse RequestMetadata
        let metadata = Self::parse_metadata(request)?;

        Ok(Context {
            db: self.db.clone(),
            service: self.service.clone(),
            rng: self.rng.clone(),
            metadata,
            key_id: None,
            session_key_cache: self.session_key_cache.clone(),
        })
    }

    fn parse_metadata(
        request: &Request<tonic::Streaming<Message>>,
    ) -> Result<RequestMetadata, Status> {
        let val_bytes = request
            .metadata()
            .get(METADATA)
            .ok_or_else(|| Status::invalid_argument("No metadata found"))?
            .as_bytes();
        let metadata = RequestMetadata::from_slice(val_bytes)?;
        Ok(metadata)
    }
}

#[derive(Debug)]
pub(crate) struct Context {
    pub db: Arc<Database>,
    pub service: Arc<Service>,
    pub rng: Arc<Mutex<StdRng>>,
    pub metadata: RequestMetadata,
    pub key_id: Option<KeyId>,
    /// Our user session keys are held in this cache after authentication.
    pub session_key_cache: Arc<Mutex<SessionKeyCache>>,
}

#[tonic::async_trait]
impl LockKeeperRpc for LockKeeperKeyServer {
    type AuthenticateStream = MessageStream;
    type CreateStorageKeyStream = MessageStream;
    type GenerateStream = MessageStream;
    type ImportSigningKeyStream = MessageStream;
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
        let context = self.context(&request)?;
        Ok(operations::Register
            .handle_request(context, request)
            .await?)
    }

    async fn authenticate(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::AuthenticateStream>, Status> {
        let context = self.context(&request)?;
        Ok(operations::Authenticate
            .handle_request(context, request)
            .await?)
    }

    async fn create_storage_key(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::CreateStorageKeyStream>, Status> {
        let context = self.context(&request)?;
        Ok(operations::CreateStorageKey
            .handle_request(context, request)
            .await?)
    }

    async fn generate(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::GenerateStream>, Status> {
        let context = self.context(&request)?;
        Ok(operations::Generate
            .handle_request(context, request)
            .await?)
    }

    async fn import_signing_key(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::ImportSigningKeyStream>, Status> {
        let context = self.context(&request)?;
        Ok(operations::ImportSigningKey
            .handle_request(context, request)
            .await?)
    }

    async fn remote_generate(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RemoteGenerateStream>, Status> {
        let context = self.context(&request)?;
        Ok(operations::RemoteGenerate
            .handle_request(context, request)
            .await?)
    }

    async fn remote_sign_bytes(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RemoteSignBytesStream>, Status> {
        let context = self.context(&request)?;
        Ok(operations::RemoteSignBytes
            .handle_request(context, request)
            .await?)
    }

    async fn retrieve(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RetrieveStream>, Status> {
        let context = self.context(&request)?;
        Ok(operations::Retrieve
            .handle_request(context, request)
            .await?)
    }

    async fn retrieve_audit_events(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RetrieveAuditEventsStream>, Status> {
        let context = self.context(&request)?;
        Ok(operations::RetrieveAuditEvents
            .handle_request(context, request)
            .await?)
    }

    async fn retrieve_storage_key(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RetrieveStorageKeyStream>, Status> {
        let context = self.context(&request)?;
        Ok(operations::RetrieveStorageKey
            .handle_request(context, request)
            .await?)
    }

    async fn retrieve_signing_key(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RetrieveSigningKeyStream>, Status> {
        let context = self.context(&request)?;
        Ok(operations::RetrieveSigningKey
            .handle_request(context, request)
            .await?)
    }
}
