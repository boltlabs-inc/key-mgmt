mod operation;
mod service;

pub(crate) use operation::Operation;
pub use service::start_dams_server;

use crate::{database::Database, error::DamsServerError, operations};

use dams::{
    config::server::{Config, Service},
    dams_rpc::dams_rpc_server::DamsRpc,
    types::{Message, MessageStream},
};

use rand::{rngs::StdRng, SeedableRng};
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

#[allow(unused)]
#[derive(Debug)]
pub struct DamsKeyServer {
    config: Config,
    db: Arc<Database>,
    service: Arc<Service>,
    rng: Arc<Mutex<StdRng>>,
}

impl DamsKeyServer {
    pub fn new(
        db: Database,
        config: Config,
        service: Arc<Service>,
    ) -> Result<Self, DamsServerError> {
        let rng = StdRng::from_entropy();

        Ok(Self {
            config,
            db: Arc::new(db),
            service,
            rng: Arc::new(Mutex::new(rng)),
        })
    }

    pub fn context(&self) -> Context {
        Context {
            db: self.db.clone(),
            service: self.service.clone(),
            rng: self.rng.clone(),
        }
    }
}

#[derive(Debug)]
pub struct Context {
    pub db: Arc<Database>,
    pub service: Arc<Service>,
    pub rng: Arc<Mutex<StdRng>>,
}

#[tonic::async_trait]
impl DamsRpc for DamsKeyServer {
    type RegisterStream = MessageStream;
    type AuthenticateStream = MessageStream;
    type CreateStorageKeyStream = MessageStream;
    type GenerateStream = MessageStream;
    type RetrieveStream = MessageStream;
    type RetrieveStorageKeyStream = MessageStream;

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

    async fn create_storage_key(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::CreateStorageKeyStream>, Status> {
        Ok(operations::CreateStorageKey
            .handle_request(self.context(), request)
            .await?)
    }

    async fn generate(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::GenerateStream>, Status> {
        Ok(operations::Generate
            .handle_request(self.context(), request)
            .await?)
    }

    async fn retrieve(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RetrieveStream>, Status> {
        Ok(operations::Retrieve
            .handle_request(self.context(), request)
            .await?)
    }

    async fn retrieve_storage_key(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RetrieveStorageKeyStream>, Status> {
        Ok(operations::RetrieveStorageKey
            .handle_request(self.context(), request)
            .await?)
    }
}
