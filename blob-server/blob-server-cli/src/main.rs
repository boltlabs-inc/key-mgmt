mod config;

use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
};

use config::Config;

use blob_server_backend::{start_blob_server, BlobServerError, Config as ServerConfig, BlobServerDatabase, DatabaseConfig};
use clap::Parser;

use tracing::{info, Level};
use tracing_appender::{self, non_blocking::WorkerGuard};

use tracing_subscriber::{filter::Targets, prelude::*};

#[derive(Parser)] //Should not derive debug, contains secrets
pub struct Cli {
    /// Path to the server config file
    pub config: PathBuf,

    /// Database username.
    #[clap(long, env=DatabaseConfig::DB_USERNAME)]
    pub database_username: Option<String>,
    /// Database password.
    #[clap(long, env=DatabaseConfig::DB_PASSWORD)]
    pub database_password: Option<String>,
}

#[tokio::main]
pub async fn main() {
    if let Err(e) = run_main().await {
        eprintln!("Server error: {e}");
    }
}

pub async fn run_main() -> Result<(), BlobServerError> {
    let cli = Cli::parse();
    let config = Config::from_file(&cli.config)?;
    let server_config = ServerConfig::from_file(config.server, cli.database_username, cli.database_password)?;

    // We keep `_logging` around for the lifetime of the server. On drop, this value
    // will ensure that our logs are flushed.
    let _logging = init_logging(&server_config)?;

    info!("Sever started!");
    info!("Logging config settings: {:?}", server_config.logging);

    let postgres = BlobServerDatabase::connect(server_config.database.clone())
        .await
        .expect("Failed connecting to database.");

    start_blob_server(server_config, postgres).await?;
    Ok(())
}

/// Object representing our logging. Should be kept around as our logging
/// writers return guards that should live for the lifetime of the program. Do
/// not do anything with the guards. Just make sure they are not dropped!
#[derive(Default)]
struct LoggingGuards {
    _all_layer_guard: Option<WorkerGuard>,
    _server_layer_guard: Option<WorkerGuard>,
}

/// Initialize our logging with different logging layers:
/// 1) Log all INFO-level messages (or higher) from our key_server* crates to
/// standard out.
/// 2) (OPTIONAL) Log all messages (TRACE or higher) from our key_server*
/// crates to the path specified by `server_logs`.
/// 3) (OPTIONAL) Log all messages ((TRACE or higher) from any crate to the path
/// specified by `all_logs`.
///
/// Returns an object which should be kept around for the lifetime of the
/// program.
fn init_logging(config: &ServerConfig) -> Result<LoggingGuards, BlobServerError> {
    // Log info level events generated from lock keeper into stdout.
    let stdout_layer = tracing_subscriber::fmt::layer()
        .pretty()
        .with_filter(our_targets_filter(config.logging.stdout_log_level));

    let logging_guards = match &config.logging.log_files {
        Some(file_config) => {
            let (all_logs_dir, all_logs_file) = get_paths(&file_config.all_logs_file_name)?;
            let (server_logs_dir, server_logs_file) =
                get_paths(&file_config.blob_server_logs_file_name)?;

            // This layers logs all events into a file.
            let all_appender = tracing_appender::rolling::hourly(all_logs_dir, all_logs_file);
            let (non_blocking, _all_layer_guard) = tracing_appender::non_blocking(all_appender);
            let all_layer = tracing_subscriber::fmt::layer()
                .json()
                .with_writer(non_blocking);

            // Log all events generated from lock keeper into a file.
            let server_appender =
                tracing_appender::rolling::hourly(server_logs_dir, server_logs_file);
            let (non_blocking, _server_layer_guard) =
                tracing_appender::non_blocking(server_appender);
            let server_layer = tracing_subscriber::fmt::layer()
                .json()
                .with_writer(non_blocking)
                .with_filter(our_targets_filter(Level::TRACE));

            // Build our logging subscriber with all three of our layers.
            tracing_subscriber::registry()
                .with(stdout_layer)
                .with(server_layer)
                .with(all_layer)
                .init();

            LoggingGuards {
                _all_layer_guard: Some(_all_layer_guard),
                _server_layer_guard: Some(_server_layer_guard),
            }
        }
        None => {
            // Build our logging subscriber with just the stdout layer.
            tracing_subscriber::registry().with(stdout_layer).init();

            LoggingGuards::default()
        }
    };

    Ok(logging_guards)
}

/// Return the path directory and the file name. Needed for passing to
/// tracing_appender.
fn get_paths(path: &Path) -> Result<(&Path, &OsStr), BlobServerError> {
    let dir = path
        .parent()
        .ok_or_else(|| BlobServerError::InvalidLogFilePath(path.into()))?;

    let file_name = path
        .file_name()
        .ok_or_else(|| BlobServerError::InvalidLogFilePath(path.into()))?;
    Ok((dir, file_name))
}

/// Create filters for logging events originating from our lock_keeper*
/// crates.
fn our_targets_filter(level: Level) -> Targets {
    Targets::new()
        // List our different targets here. Anything under our server.
        .with_target("key_server_cli", level)
        .with_target("lock_keeper_key_server", level)
        .with_target("lock_keeper", level)
        .with_target("lock_keeper_session_cache_sql", level)
}
