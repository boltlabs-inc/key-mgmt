use crate::{cli::Cli, command, database, error::DamsServerError};

use dams::{
    config::server::{Config, Service},
    dams_rpc::dams_rpc_server::{DamsRpc, DamsRpcServer},
    defaults::server::config_path,
    types::Message,
    TestLogs,
};
use futures::stream::{FuturesUnordered, StreamExt};
use mongodb::Database;
use rand::{rngs::StdRng, SeedableRng};
use std::{convert::identity, net::SocketAddr, sync::Arc};
use tokio::{signal, sync::Mutex};
use tonic::{transport::Server, Request, Response, Status};
use tracing::{error, info};

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
    type RegisterStream = dams::types::MessageStream;
    type AuthenticateStream = dams::types::MessageStream;

    async fn register(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::RegisterStream>, Status> {
        Ok(command::register::Register
            .run(request, self.context())
            .await?)
    }

    async fn authenticate(
        &self,
        request: Request<tonic::Streaming<Message>>,
    ) -> Result<Response<Self::AuthenticateStream>, Status> {
        Ok(command::authenticate::Authenticate
            .run(request, self.context())
            .await?)
    }
}

pub async fn start_tonic_server(config: Config) -> Result<(), DamsServerError> {
    let db = database::connect_to_mongo(&config.database).await?;
    // Collect the futures for the result of running each specified server
    let mut server_futures: FuturesUnordered<_> = config
        .services
        .iter()
        .map(|service| {
            // Clone `Arc`s for the various resources we need in this server
            let config = config.clone();
            let db = db.clone();
            let service = Arc::new(service.clone());

            async move {
                let dams_rpc_server = DamsKeyServer::new(db, config, service)?;
                let addr = dams_rpc_server.service.address;
                let port = dams_rpc_server.service.port;
                info!("{}", TestLogs::ServerSpawned(format!("{}:{}", addr, port)));
                Server::builder()
                    .add_service(DamsRpcServer::new(dams_rpc_server))
                    .serve(SocketAddr::new(addr, port))
                    .await?;

                Ok::<_, DamsServerError>(())
            }
        })
        .collect();

    // Wait for the server to finish
    tokio::select! {
        _ = signal::ctrl_c() => info!("Terminated by user"),
        Some(Err(e)) = server_futures.next() => {
            error!("Error: {}", e);
        },
        else => {
            info!("Shutting down...")
        }
    }
    Ok(())
}

pub async fn main_with_cli(cli: Cli) -> Result<(), DamsServerError> {
    let config_path = cli.config.ok_or_else(config_path).or_else(identity)?;
    let config = Config::load(&config_path).await?;
    start_tonic_server(config).await
}
