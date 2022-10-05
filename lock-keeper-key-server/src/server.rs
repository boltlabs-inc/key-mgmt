pub(crate) mod opaque_storage;
mod operation;
mod service;

pub(crate) use operation::Operation;
pub use service::start_lock_keeper_server;
use std::str::FromStr;

use crate::{database::Database, error::LockKeeperServerError, operations};

use lock_keeper::{
    config::server::{Config, Service},
    constants::headers::ACCOUNT_NAME,
    crypto::KeyId,
    rpc::{lock_keeper_rpc_server::LockKeeperRpc, HealthCheck},
    types::{operations::ClientAction, user::AccountName, Message, MessageStream},
};

use lock_keeper::constants::headers::ACTION;
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

    pub fn context(&self, request: &Request<tonic::Streaming<Message>>) -> Result<Context, Status> {
        // Parse AccountName from metadata
        let account_name_str = Self::str_from_metadata(
            request,
            ACCOUNT_NAME,
            Status::unauthenticated("Account name not found"),
            Status::unauthenticated("Invalid account name"),
        )?;
        let account_name = AccountName::from_str(account_name_str)?;

        // Parse ClientAction from metadata
        let action_str = Self::str_from_metadata(
            request,
            ACTION,
            Status::invalid_argument("Client action not found"),
            Status::invalid_argument("Invalid client action"),
        )?;
        eprintln!("ACTION: {:?}", action_str);
        let action = ClientAction::from_str(action_str)?;

        Ok(Context {
            db: self.db.clone(),
            service: self.service.clone(),
            rng: self.rng.clone(),
            account_name,
            action,
            key_id: None,
        })
    }

    fn str_from_metadata<'a>(
        request: &'a Request<tonic::Streaming<Message>>,
        key: &'a str,
        option_err: Status,
        str_err: Status,
    ) -> Result<&'a str, Status> {
        let val_str = request
            .metadata()
            .get(key)
            .ok_or(option_err)?
            .to_str()
            .map_err(|_| str_err)?;
        Ok(val_str)
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
    type RetrieveAuditEventsStream = MessageStream;
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

    async fn retrieve(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RetrieveStream>, Status> {
        let context = self.context(&request)?;
        Ok(operations::Retrieve
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

    async fn retrieve_audit_events(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RetrieveAuditEventsStream>, Status> {
        let context = self.context(&request)?;
        Ok(operations::RetrieveAuditEvents
            .handle_request(context, request)
            .await?)
    }
}
