mod blobs;

use std::sync::Arc;

use sqlx::{PgPool, postgres::PgPoolOptions};
use tracing::{info, error, instrument};

use crate::{BlobServerError, config::DatabaseConfig};

#[derive(Clone)]
pub struct BlobServerDatabase {
    config: Arc<DatabaseConfig>,
    connection_pool: PgPool,
}

impl BlobServerDatabase {
    #[instrument(err(Debug))]
    pub async fn connect(config: DatabaseConfig) -> Result<Self, BlobServerError> {
        info!("Connecting to database");

        let mut attempts = 0;

        // We have to use `loop` instead of `while` here so that we can return a value
        // after a successful connection.
        let pool = loop {
            if attempts > config.connection_retries {
                return Err(BlobServerError::ExceededMaxConnectionAttempts);
            }

            // Create a connection pool based on our config.
            let pool = PgPoolOptions::new()
                .max_connections(config.max_connections)
                .acquire_timeout(config.connection_timeout)
                .connect(&config.uri())
                .await;

            match pool {
                Ok(pool) => break pool,
                Err(e) => {
                    attempts += 1;
                    error!("{e}");
                    error!(
                        "Failed to connect to db. Attempts: {attempts}. Retrying in {:?}",
                        config.connection_retry_delay
                    );
                    tokio::time::sleep(config.connection_retry_delay).await;
                }
            }
        };

        Ok(BlobServerDatabase {
            config: Arc::new(config),
            connection_pool: pool,
        })
    }
}
