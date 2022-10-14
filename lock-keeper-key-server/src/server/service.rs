use crate::{database::Database, error::LockKeeperServerError, server::LockKeeperKeyServer};

use futures::stream::{FuturesUnordered, StreamExt};
use hyper::server::conn::Http;
use lock_keeper::{
    config::server::{Config, Service},
    rpc::lock_keeper_rpc_server::LockKeeperRpcServer,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    net::{TcpListener, TcpStream},
    signal,
};
use tokio_rustls::TlsAcceptor;
use tonic::transport::{server::Routes, Server};
use tracing::{error, info};

/// Starts a full Lock Keeper server stack based on the given config.
pub async fn start_lock_keeper_server(config: Config) -> Result<(), LockKeeperServerError> {
    tracing::info!("Starting Lock Keeper key server");
    let db = Database::connect(&config.database).await?;
    // Collect the futures for the result of running each specified server
    let mut server_futures: FuturesUnordered<_> = config
        .services
        .iter()
        .map(|service| start_service(service, &config, &db))
        .collect();

    tracing::info!("Lock Keeper key server started");

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

/// Starts a new thread that accepts connections and sends them through our
/// service stack.
async fn start_service(
    service: &Service,
    config: &Config,
    db: &Database,
) -> Result<(), LockKeeperServerError> {
    // Clone `Arc`s for the various resources we need in this server
    let config = config.clone();
    let db = db.clone();
    let service = Arc::new(service.clone());

    let tls = service.tls_config()?;

    let rpc_server = LockKeeperKeyServer::new(db, config, service)?;
    let addr = rpc_server.service.address;
    let port = rpc_server.service.port;

    let svc = Server::builder()
        .add_service(LockKeeperRpcServer::new(rpc_server))
        .into_service();

    let mut http = Http::new();
    let _ = http.http2_only(true);

    let listener = TcpListener::bind(SocketAddr::new(addr, port)).await?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls));

    // Spawn a task to accept connections
    let _ = tokio::spawn(async move {
        loop {
            let (conn, _) = match listener.accept().await {
                Ok(incoming) => incoming,
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                    continue;
                }
            };

            let http = http.clone();
            let tls_acceptor = tls_acceptor.clone();
            let svc = svc.clone();

            // Spawn a task to handle each connection
            let _ = tokio::spawn(async move {
                if let Err(e) = handle_connection(http, conn, tls_acceptor, svc).await {
                    // Log the error but don't bother returning it since it has nowhere to go.
                    error!("{}", e);
                }
            });
        }
    });

    Ok(())
}

/// Processes an individual connection through our service stack including TLS
/// and our `tonic` handler.
async fn handle_connection(
    http: Http,
    connection: TcpStream,
    tls_acceptor: TlsAcceptor,
    service: Routes,
) -> Result<(), LockKeeperServerError> {
    let conn = tls_acceptor.accept(connection).await?;
    let svc = tower::ServiceBuilder::new().service(service);
    http.serve_connection(conn, svc).await?;

    Ok(())
}
