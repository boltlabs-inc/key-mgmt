//! Implementation of our LockKeeper server.
//!
//! ## Logging
//! Our server supports logging using the [`tracing`](https://docs.rs/tracing/latest/tracing/)
//! crate.
//!
//! ### Main `tracing` Concepts.
//! We utilize the following concept from `tracing`:
//!
//! - **Events**: These are the individual logging events that are called as our
//!   program executes.
//! Events have an info level attached to them. You may create a new event by
//! using the appropriate macro event macro from `tracing`, e.g:
//! ```
//! info!("This is a logging event!");
//! ```
//!   You may add runtime values to our events as well:
//! ```
//! info!("Logging config settings: {:?}", config.logging);
//! ```
//! This uses the same syntax as Rust string formatting.
//!
//! - **Spans** represent logical regions of code, usually a function. All
//!   _event_s within a span
//! will have additional span data attached to the event. This allows us to add
//! context-relevant data to an event without having to explicitly add this data
//! to our event. For example an event like `info!(This operation completed
//! successfully!)` within our span will look like:
//! ```text
//!   2022-12-06T18:57:40.022422Z  INFO lock_keeper_key_server::server::operation: This operation completed successfully!
//!     at lock-keeper-key-server/src/server/operation.rs:72
//!     in lock_keeper_key_server::server::operation::handle_request with request_id: "52ad8008-1eb9-4ad5-8bce-0344a958fd1e", action: "Authenticate"
//! ```
//! This event has the `handle_request` span attached to it. Additionally, spans
//! may contain _fields_. These fields attached relevant data to all events
//! within our span. In the log message above, we see our span has fields
//! `request_id` and `action` attached.
//!
//! #### Adding your Own Span.
//! The best way to create your own span is using the
//! [`instrument`](https://docs.rs/tracing/0.1.37/tracing/attr.instrument.html) macro. This macro
//! will automatically create a new span when the instrumented function is
//! called. This span will have the name of the function and the module path as
//! the `target` (this can be used for filtering by certain targets).
//!
//! Please follow the following template for instrumenting your function with
//! spans:
//! ```text
//! #[instrument(skip(sensitive_arg), err(Debug))]
//! fn foo(arg1: _, arg2: _, sensitive_arg SuperSecret) -> _ {}
//! ```
//! By default, `instrument` will create a new span where every argument to a
//! function is a span field. *This is not desirable for our key server as we
//! want to avoid logging sensitive data!* Make sure to skip sensitive arguments
//! with the `skip(sensitive_arg_1, sensitive_arg_2)` option. You can also use
//! the `skip_all` option if none of the function arguments need to be logged.
//!
//! Finally, the `err(Debug)` option tells `tracing` that any `Result::Err(_)`
//! returned from this function should be logged as events (with the default
//! level of `INFO`). This is useful for logging where errors originated from in
//! our code. The `Debug` part tells tracing to use the `Debug` implementation
//! of this type for formatting, instead of the default `Display`.
//!
//! Note that by default, return values of functions are not recorded. You can
//! add the `ret` option to `instrument` if you wish to record the Ok(_) return
//! value as a field.
//!
//! `tracing` relies on the `Debug` implementation of types for printing values.
//! Your type must implement `Debug` if you wish to include it as a field.
//!
//! #### Recording Fields Not Immediately Available as Arguments.
//! Sometimes we want to add a field to a span where the field data isn't
//! immediately available as an argument to the function. Consider the following
//! example:
//! ```text
//! #[instrument(skip_all, err(Debug), fields(action, user_id, request_id))]
//!     async fn handle_request(
//!         self,
//!         mut context: Context<DB>,
//!         request: Request<Streaming<Message>>,
//!     ) -> Result<_, _> {
//!
//!         let request_id = Uuid::new_v4();
//!         logging::record_field("request_id", &request_id);
//!         info!("Handling new client request.");
//!
//!         ... // Lots more things happen afterwards.
//!     }
//! ```
//! Here we specify the fields `action`, `user_id`, `request_id` even though
//! none of these are function arguments! When the function body executes, we
//! create a `request_id` which we _record_
//! using our [record_field][lock_keeper::infrastructure::logging::record_field]
//! function. So our event `info!("Handling new client request.");` will have
//! the `request_id` field attached:
//! ```text
//!   2022-12-06T18:57:39.667194Z  INFO
//! lock_keeper_key_server::server::operation: Handling new client request.
//!     at lock-keeper-key-server/src/server/operation.rs:48
//!     in lock_keeper_key_server::server::operation::handle_request with request_id: "52ad8008-1eb9-4ad5-8bce-0344a958fd1e"
//! ```
//!
//! Notice we have not recorded the `action` and `request_id` fields by the time
//! this event is logged, so these fields are not included. Span fields can be
//! recorded later as long as they are declared along with the span.
//!
//! Note: While it is possible to create your own spans, it is not recommended.
//! The `instrument` macro handles spans for asynchronous functions. Ensuring
//! spans are properly kept track of, even when `.await`ing across spans.
//!
//! #### Which Arguments Should be Recorded as Fields?
//! In general, we should only include fields for our span that provide
//! important information that should be attached to every event that happens
//! within that span.
//!
//! Fields are useful for attaching data to every event without having to
//! explicitly pass that data to the event.
//!
//! Note: *We should be careful to avoid recording any sensitive data as
//! fields!*
//!
//! #### Which Function Should be `instrument`ed?
//! We want to instrument functions which either:
//! 1) Logically represent an important step in our server processing.
//! 2) Record useful fields to be attached to event within that span.
//! 3) Have return values which are useful to log.
//!
//! Instrumenting multiple functions which call each other will create a useful
//! "backtrace-like" context which allows us to understand the calling context
//! of an event. For example:
//! ```text
//!   2022-12-06T18:57:39.669808Z  INFO
//! lock_keeper_key_server::operations::authenticate: Starting authentication protocol.
//!     at lock-keeper-key-server/src/operations/authenticate.rs:38
//!     in lock_keeper_key_server::operations::authenticate::operation
//!     in lock_keeper_key_server::server::operation::handle_request with request_id: "52ad8008-1eb9-4ad5-8bce-0344a958fd1e", action: "Authenticate"
//! ```
//! We want to avoid instrumenting uninteresting functions, e.g. functions which
//! represent an implementation detail instead of a logical step in our server
//! execution.
//!
//! ### Logging Levels
//! So far our logging documentation has focused on the default tracing level of
//! `INFO`. Events may be added for the following tracing levels: `error`,
//! `warn`, `info`, `debug`, and `trace`. Here we give a brief overview of what
//! falls under every level:
//! - **error**: Report unexpected errors or failures in the system.
//! - **warn**: Warn of unexpected errors, unforeseen program states, or
//!   possible issues that are not necessarily fatal, but should be logged so
//!   they may be debugged later.
//! - **info**: For high-level, relevant, events to the execution of the code.
//!   This is our default
//! logging level and should produce useful messages for developers.
//! - **debug**: More verbose, good to have information for debugging purposes.
//! - **trace**: Very verbose information that allows you to trace the execution
//!   of a program at a
//! fine granularity, e.g. program control flow.

mod config;

use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
};

use config::Config;

use clap::Parser;
use lk_session_mongodb::{config::Config as SessionConfig, MongodbSessionCache};
use lock_keeper_key_server::{
    config::Config as ServerConfig, server::start_lock_keeper_server, LockKeeperServerError,
};
use lock_keeper_mongodb::{config::Config as DatabaseConfig, Database};
use tracing::{info, Level};
use tracing_appender::{self, non_blocking::WorkerGuard};

use tracing_subscriber::{filter::Targets, prelude::*};

#[derive(Debug, Parser)]
pub struct Cli {
    /// Path to the server config file
    pub config: PathBuf,
    /// Base64 encoded private key data
    #[clap(long)]
    pub private_key: Option<String>,
    /// Base64 encoded remote storage key data
    #[clap(long)]
    pub remote_storage_key: Option<String>,
}

#[tokio::main]
pub async fn main() {
    let cli = Cli::parse();
    let private_key_bytes = cli
        .private_key
        .map(String::into_bytes)
        .map(base64::decode)
        .transpose()
        .unwrap();

    let remote_storage_key_bytes = cli
        .remote_storage_key
        .map(String::into_bytes)
        .map(base64::decode)
        .transpose()
        .unwrap();

    let config = Config::from_file(&cli.config);

    let server_config =
        ServerConfig::from_file(config.server, private_key_bytes, remote_storage_key_bytes)
            .unwrap();

    // We keep `_logging` around for the lifetime of the server. On drop, this value
    // will ensure that our logs are flushed.
    let _logging = init_logging(
        &server_config.logging.all_logs_file_name,
        &server_config.logging.lock_keeper_logs_file_name,
    )
    .unwrap();

    info!("Sever started!");
    info!("Logging config settings: {:?}", server_config.logging);

    let database_config = DatabaseConfig::from_file(config.database).unwrap();
    let mongo = Database::connect(database_config.clone()).await.unwrap();
    info!("Database config Settings: {:?}", database_config);

    let session_config = SessionConfig::from_file(config.session_cache).unwrap();
    let session_cache = MongodbSessionCache::new(session_config).await.unwrap();
    start_lock_keeper_server(server_config, mongo, session_cache)
        .await
        .unwrap();
}

/// Object representing our logging. Should be kept around as our logging
/// writers return guards that should live for the lifetime of the program. Do
/// not do anything with the guards. Just make sure they are not dropped!
struct Logging {
    _all_layer_guard: WorkerGuard,
    _server_layer_guard: WorkerGuard,
}

/// Initialize our logging with three different logging layers:
/// 1) Log all INFO-level messages (or higher) from our key_server* crates to
/// standard out. 2) Log all messages (TRACE or higher) from our key_server*
/// crates to the path specified by `server_logs`.
/// 3) Log all messages ((TRACE or higher) from any crate to the path specified
/// by `all_logs`.
///
/// Returns an object which should be kept around for the lifetime of the
/// program.
fn init_logging(all_logs: &Path, server_logs: &Path) -> Result<Logging, LockKeeperServerError> {
    let (all_logs_dir, all_logs_file) = get_paths(all_logs)?;
    let (server_logs_dir, server_logs_file) = get_paths(server_logs)?;

    // Initialize logging. Three different files:
    let stdout_layer = tracing_subscriber::fmt::layer()
        .pretty()
        .with_filter(our_targets_filter(Level::INFO));

    let all_appender = tracing_appender::rolling::hourly(all_logs_dir, all_logs_file);
    let (non_blocking, _all_layer_guard) = tracing_appender::non_blocking(all_appender);
    let all_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(non_blocking);

    let server_appender = tracing_appender::rolling::hourly(server_logs_dir, server_logs_file);
    let (non_blocking, _server_layer_guard) = tracing_appender::non_blocking(server_appender);
    let server_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(non_blocking)
        .with_filter(our_targets_filter(Level::TRACE));

    tracing_subscriber::registry()
        .with(stdout_layer)
        .with(server_layer)
        .with(all_layer)
        .init();

    return Ok(Logging {
        _all_layer_guard,
        _server_layer_guard,
    });

    /// Return the path directory and the file name. Needed for passing to
    /// tracing_appender.
    fn get_paths(path: &Path) -> Result<(&Path, &OsStr), LockKeeperServerError> {
        let dir = path
            .parent()
            .ok_or_else(|| LockKeeperServerError::InvalidLogFilePath(path.into()))?;

        let file_name = path
            .file_name()
            .ok_or_else(|| LockKeeperServerError::InvalidLogFilePath(path.into()))?;
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
    }
}
