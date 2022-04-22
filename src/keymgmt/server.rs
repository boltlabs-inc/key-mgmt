use crate::{cli::server::Run, config::server::Config, protocol::KeyMgmt, TestLogs};
use async_trait::async_trait;
use dialectic::offer;
use futures::stream::{FuturesUnordered, StreamExt};
use rand::{rngs::StdRng, SeedableRng};
use std::sync::Arc;
use tokio::{signal, sync::broadcast};
use tracing::{error, info};
use transport::server::{Chan, Server};

mod create;
mod retrieve;

use create::Create;
use retrieve::Retrieve;

/// A single server-side command, parameterized by the currently loaded configuration.
///
/// All subcommands of [`cli::Server`](crate::server::cli::Server) should implement this.
#[async_trait]
pub trait Command {
    /// Output type of the server
    type Output;

    /// Run the server
    async fn run(self, config: Config) -> Result<Self::Output, anyhow::Error>;
}

#[async_trait]
impl Command for Run {
    type Output = ();
    async fn run(self, config: Config) -> Result<Self::Output, anyhow::Error> {
        // Share the configuration between all server threads
        let client = reqwest::Client::new();
        let config = config.clone();

        // Sender and receiver to indicate graceful shutdown should occur
        let (terminate, _) = broadcast::channel(1);

        // Collect the futures for the result of running each specified server
        let mut server_futures: FuturesUnordered<_> = config
            .services
            .iter()
            .map(|service| {
                // Clone `Arc`s for the various resources we need in this server
                let client = client.clone();
                let config = config.clone();
                let service = Arc::new(service.clone());
                let mut wait_terminate = terminate.subscribe();

                async move {
                    // Initialize a new `Server` with parameters taken from the configuration
                    let mut server: Server<KeyMgmt> = Server::new();
                    let _ = server
                        .timeout(service.connection_timeout)
                        .max_pending_retries(Some(service.max_pending_connection_retries))
                        .max_length(service.max_message_length);

                    // Serve on this address
                    let address = (service.address, service.port);
                    let certificate = service.certificate.clone();
                    let private_key = service.private_key.clone();

                    // There is no meaningful initialization necessary per request
                    let initialize = || async { Some(()) };

                    // For each request, dispatch to the appropriate method, defined elsewhere
                    let interact = move |session_key, (), chan: Chan<KeyMgmt>| {
                        // Clone `Arc`s for the various resources we need in this request
                        let client = client.clone();
                        let service = service.clone();
                        let config = config.clone();

                        // TODO: permit configuration option to make this deterministic for testing
                        let rng = StdRng::from_entropy();

                        async move {
                            offer!(in chan {
                                0 => Create.run(
                                    rng,
                                    &client,
                                    &config,
                                    &service,
                                    session_key,
                                    chan,
                                ).await?,
                                1 => Retrieve.run(
                                    rng,
                                    &client,
                                    &config,
                                    &service,
                                    session_key,
                                    chan,
                                ).await?,
                            })?;
                            Ok::<_, anyhow::Error>(())
                        }
                    };

                    // Future that completes on graceful shutdown
                    let wait_terminate = async move { wait_terminate.recv().await.unwrap_or(()) };

                    // Run the server until graceful shutdown
                    server
                        .serve_while(
                            address,
                            Some((&certificate, &private_key)),
                            initialize,
                            interact,
                            wait_terminate,
                            |address| info!("{}", TestLogs::ServerSpawned(address)),
                        )
                        .await?;
                    Ok::<_, anyhow::Error>(())
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
}
