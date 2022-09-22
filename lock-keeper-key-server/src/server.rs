mod operation;
mod service;

pub(crate) use operation::Operation;
pub use service::start_lock_keeper_server;
use std::str::FromStr;

use crate::{database::Database, error::LockKeeperServerError, operations};

use lock_keeper::{
    config::server::{Config, Service},
    rpc::lock_keeper_rpc_server::LockKeeperRpc,
    types::{Message, MessageStream},
    ClientAction,
};

use lock_keeper::{crypto::KeyId, user::AccountName};
use rand::{rngs::StdRng, SeedableRng};
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

#[allow(unused)]
#[derive(Debug)]
pub struct LockKeeperKeyServer {
    config: Config,
    db: Arc<Database>,
    service: Arc<Service>,
    rng: Arc<Mutex<StdRng>>,
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
        })
    }

    pub fn context(
        &self,
        request: &Request<tonic::Streaming<Message>>,
        action: ClientAction,
    ) -> Result<Context, Status> {
        let account_name_str = request
            .metadata()
            .get("account_name")
            .ok_or_else(|| Status::unauthenticated("Account name not found"))?
            .to_str()
            .map_err(|_| Status::unauthenticated("Invalid account name"))?;
        let account_name = AccountName::from_str(account_name_str)?;

        Ok(Context {
            db: self.db.clone(),
            service: self.service.clone(),
            rng: self.rng.clone(),
            account_name,
            action,
            key_id: None,
        })
    }
}

#[derive(Debug)]
pub struct Context {
    pub db: Arc<Database>,
    pub service: Arc<Service>,
    pub rng: Arc<Mutex<StdRng>>,
    pub account_name: AccountName,
    pub action: ClientAction,
    pub key_id: Option<KeyId>,
}

#[tonic::async_trait]
impl LockKeeperRpc for LockKeeperKeyServer {
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
        let context = self.context(&request, ClientAction::Register)?;
        Ok(operations::Register
            .handle_request(context, request)
            .await?)
    }

    async fn authenticate(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::AuthenticateStream>, Status> {
        let context = self.context(&request, ClientAction::Authenticate)?;
        Ok(operations::Authenticate
            .handle_request(context, request)
            .await?)
    }

    async fn create_storage_key(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::CreateStorageKeyStream>, Status> {
        let context = self.context(&request, ClientAction::CreateStorageKey)?;
        Ok(operations::CreateStorageKey
            .handle_request(context, request)
            .await?)
    }

    async fn generate(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::GenerateStream>, Status> {
        let context = self.context(&request, ClientAction::Generate)?;
        Ok(operations::Generate
            .handle_request(context, request)
            .await?)
    }

    async fn retrieve(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RetrieveStream>, Status> {
        let context = self.context(&request, ClientAction::Retrieve)?;
        Ok(operations::Retrieve
            .handle_request(context, request)
            .await?)
    }

    async fn retrieve_storage_key(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RetrieveStorageKeyStream>, Status> {
        let context = self.context(&request, ClientAction::RetrieveStorageKey)?;
        Ok(operations::RetrieveStorageKey
            .handle_request(context, request)
            .await?)
    }
}
