use crate::{cli::Cli, command, database};

use anyhow::{anyhow, Context};
use dams::{
    config::server::{Config, Service},
    dams_rpc::{
        dams_rpc_server::{DamsRpc, DamsRpcServer},
        ClientRegister,
    },
    defaults::server::config_path,
};
use futures::FutureExt;
use mongodb::Database;
use rand::{rngs::StdRng, SeedableRng};
use std::{
    convert::identity,
    sync::{Arc, Mutex},
};
use tonic::{transport::Server, Request, Response, Status};

#[allow(unused)]
#[derive(Debug)]
pub struct DamsKeyServer {
    db: Database,
    config: Config,
    service: Service,
    rng: Arc<Mutex<StdRng>>,
}

impl DamsKeyServer {
    pub fn new(db: Database, config: Config) -> Self {
        let service = config.services.get(0).unwrap();
        let rng = StdRng::from_entropy();
        Self {
            db,
            config: config.clone(),
            service: service.clone(),
            rng: Arc::new(Mutex::new(rng)),
        }
    }
}

#[tonic::async_trait]
impl DamsRpc for DamsKeyServer {
    type RegisterStream = command::register::RegisterStream;

    async fn register(
        &self,
        request: Request<tonic::Streaming<ClientRegister>>,
    ) -> Result<Response<Self::RegisterStream>, Status> {
        command::register::Register
            .run(request, &self.db, &self.rng, &self.service)
            .await
    }
}

pub async fn main_with_cli(cli: Cli) -> Result<(), anyhow::Error> {
    let config_path = cli.config.ok_or_else(config_path).or_else(identity)?;
    let config = Config::load(&config_path).map(|result| {
        result
            .with_context(|| format!("Could not load server configuration from {:?}", config_path))
    });

    let db = database::connect_to_mongo().await?;

    let dams_rpc_server = DamsKeyServer::new(db, config.await?);
    let addr = "[::1]:50051".parse()?;

    Server::builder()
        .add_service(DamsRpcServer::new(dams_rpc_server))
        .serve(addr)
        .await
        .map_err(|_| anyhow!("Cannot start server"))
}
