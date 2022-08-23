use crate::{cli::Cli, command, database};

use anyhow::{anyhow, Context as ErrorContext};
use dams::{
    config::server::{Config, Service},
    dams_rpc::dams_rpc_server::{DamsRpc, DamsRpcServer},
    defaults::server::config_path,
    types::Message,
    TestLogs,
};
use futures::FutureExt;
use mongodb::Database;
use rand::{rngs::StdRng, SeedableRng};
use std::{
    convert::identity,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tonic::{transport::Server, Request, Response, Status};
use tracing::info;

#[allow(unused)]
#[derive(Debug)]
pub struct DamsKeyServer {
    config: Config,
    db: Arc<Database>,
    service: Arc<Service>,
    rng: Arc<Mutex<StdRng>>,
}

impl DamsKeyServer {
    pub fn new(db: Database, config: Config) -> Result<Self, anyhow::Error> {
        let service = config
            .services
            .get(0)
            .ok_or_else(|| anyhow!("Could not get service."))?;
        let rng = StdRng::from_entropy();

        Ok(Self {
            config: config.clone(),
            db: Arc::new(db),
            service: Arc::new(service.clone()),
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
    type RegisterStream = dams::types::MessageStream;
    type AuthenticateStream = dams::types::MessageStream;

    async fn register(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RegisterStream>, Status> {
        command::register::Register
            .run(request, self.context())
            .await
    }

    async fn authenticate(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::AuthenticateStream>, Status> {
        command::authenticate::Authenticate
            .run(request, self.context())
            .await
    }
}

pub async fn start_tonic_server(config: Config) -> Result<(), anyhow::Error> {
    let db =
        database::connect_to_mongo(&config.database.mongodb_uri, &config.database.db_name).await?;

    let dams_rpc_server = DamsKeyServer::new(db, config)?;
    let addr = dams_rpc_server.service.address;
    let port = dams_rpc_server.service.port;
    info!("{}", TestLogs::ServerSpawned(format!("{}:{}", addr.to_string(), port.to_string())));
    Server::builder()
        .add_service(DamsRpcServer::new(dams_rpc_server))
        .serve(SocketAddr::new(addr, port))
        .await
        .map_err(|e| anyhow!("Cannot start server: {:?}", e))
}

pub async fn main_with_cli(cli: Cli) -> Result<(), anyhow::Error> {
    let config_path = cli.config.ok_or_else(config_path).or_else(identity)?;
    let config = Config::load(&config_path).map(|result| {
        result
            .with_context(|| format!("Could not load server configuration from {:?}", config_path))
    });
    start_tonic_server(config.await?).await
}
