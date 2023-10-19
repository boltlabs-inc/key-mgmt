use std::{net::SocketAddr, sync::Arc};

use hyper::server::conn::Http;
use tokio::{
    net::{TcpListener, TcpStream},
    signal,
};
use tonic::{
    transport::{server::Routes, Server},
    Request, Response, Status,
};
use tracing::{error, info};

use crate::{
    rpc::{
        blob_server_rpc_server::{BlobServerRpc, BlobServerRpcServer},
        RetrieveBlobRequest, RetrieveBlobResponse, StoreBlobRequest, StoreBlobResponse,
    },
    BlobServerError, Config, database::BlobServerDatabase,
};

pub struct BlobServer {
    config: Arc<Config>,
    db: Arc<BlobServerDatabase>,
}

impl BlobServer {
    pub fn new(
        config: Arc<Config>,
        db: Arc<BlobServerDatabase>,
    ) -> Self {
        Self {
            config,
            db,
        }
    }
}

#[tonic::async_trait]
impl BlobServerRpc for BlobServer {
    async fn store_blob(
        &self,
        request: Request<StoreBlobRequest>,
    ) -> Result<Response<StoreBlobResponse>, Status> {
        let blob_id = self.db.store_blob("ok", &[1, 2, 3]).await?;
    
        Ok(Response::new(StoreBlobResponse { 
            blob_id,
        }))
    }

    async fn retrieve_blob(
        &self,
        request: Request<RetrieveBlobRequest>,
    ) -> Result<Response<RetrieveBlobResponse>, Status> {
        let blob = self.db.retrieve_blob(1).await?;

        Ok(Response::new(RetrieveBlobResponse { 
            blob,
        }))
    }
}

pub async fn start_blob_server(
    config: Config,
    db: BlobServerDatabase,
) -> Result<(), BlobServerError> {
    info!("Starting blob server");
    let db = Arc::new(db);
    let server_future = create_server_future(config, db);

    info!("Blob server started");

    // Wait for the server to finish
    tokio::select! {
        _ = signal::ctrl_c() => info!("Terminated by user"),
        Err(e) = server_future => {
            error!("Error: {}", e);
        },
        else => {
            info!("Shutting down...")
        }
    }

    Ok(())
}

async fn create_server_future(
    config: Config,
    db: Arc<BlobServerDatabase>,
) -> Result<(), BlobServerError> {
    // Clone `Arc`s for the various resources we need in this server
    let config = Arc::new(config);
    let db = db.clone();

    let rpc_server = BlobServer::new(config, db);
    let addr = rpc_server.config.address;
    let port = rpc_server.config.port;
    info!(?addr, ?port, "Starting server with:");

    let svc = Server::builder()
        .add_service(BlobServerRpcServer::new(rpc_server))
        .into_service();

    let mut http = Http::new();
    let _ = http.http2_only(true);

    let listener = TcpListener::bind(SocketAddr::new(addr, port)).await?;

    // Spawn a task to accept connections
    let handle = tokio::spawn(async move {
        loop {
            let (conn, client) = match listener.accept().await {
                Ok(incoming) => incoming,
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                    continue;
                }
            };
            info!(?client, "Accepted Connection from:");
            let http = http.clone();
            let svc = svc.clone();

            // Spawn a task to handle each connection
            let handle = tokio::spawn(async move {
                if let Err(e) = handle_connection(http, conn, svc).await {
                    // Log the error but don't bother returning it since it has nowhere to go.
                    error!("{}", e);
                }
            });

            // We don't want to await this so we'll just drop the handle to make `clippy`
            // happy.
            std::mem::drop(handle);
        }
    });

    // We don't want to await this so we'll just drop the handle to make `clippy`
    // happy.
    std::mem::drop(handle);

    Ok(())
}

/// Processes an individual connection through our service stack including TLS
/// and our `tonic` handler.
async fn handle_connection(
    http: Http,
    connection: TcpStream,
    service: Routes,
) -> Result<(), BlobServerError> {
    let svc = tower::ServiceBuilder::new().service(service);
    http.serve_connection(connection, svc).await?;

    Ok(())
}
