use std::{
    collections::HashMap,
    fs::{self, File},
    io::{Read, Write},
    process::Command,
    sync::Mutex,
};
use structopt::StructOpt;

use futures::future;
use mongodb::Database;
use thiserror::Error;
use tokio::{task::JoinHandle, time::Duration};
use tracing::info_span;
use tracing_futures::Instrument;

use dams::{timeout::WithTimeout, TestLogs};
use dams_key_server::command::Command as _;

pub const CLIENT_CONFIG: &str = "tests/gen/TestClient.toml";
pub const SERVER_CONFIG: &str = "tests/gen/TestServer.toml";
pub const ERROR_FILENAME: &str = "tests/gen/errors.log";

const SERVER_ADDRESS: &str = "127.0.0.1";

/// Give a name to the slightly annoying type of the joined server futures
type ServerFuture = JoinHandle<Result<(), anyhow::Error>>;

/// Set of processes that run during a test.
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(unused)]
pub enum Party {
    Client,
    Server,
}

impl Party {
    pub const fn to_str(self) -> &'static str {
        match self {
            Party::Client => "party: client",
            Party::Server => "party: server",
        }
    }
}

/// Form a server CLI request. These cannot be constructed directly because the
/// CLI types are non-exhaustive.
macro_rules! server_cli {
    ($cli:ident, $args:expr) => {
        match ::dams_key_server::cli::Server::from_iter(
            ::std::iter::once("key-server-cli").chain($args),
        ) {
            ::dams_key_server::cli::Server::$cli(result) => result,
        }
    };
}
pub(crate) use server_cli;

#[allow(unused)]
pub async fn setup(db: Database) -> ServerFuture {
    let _ = fs::create_dir("tests/gen");

    // Create self-signed SSL certificate in the generated directory
    Command::new("../dev/generate-certificates")
        .arg("tests/gen")
        .spawn()
        .expect("Failed to generate new certificates");
    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

    // write config options for each party
    let _client_config = client_test_config().await;
    let server_config = server_test_config().await;

    // set up tracing for all log messages
    tracing_subscriber::fmt()
        .with_writer(Mutex::new(
            File::create(ERROR_FILENAME).expect("Failed to open log file"),
        ))
        .init();

    // Form the server run request and execute
    #[allow(clippy::infallible_destructuring_match)]
    let run = server_cli!(Run, vec!["run"]);
    let server_handle = tokio::spawn(
        run.run(server_config, db.clone())
            .instrument(info_span!(Party::Server.to_str())),
    );
    // Check the logs of server + client for indication of a successful set-up
    // Note: hard-coded to match the 2-service server with default port.
    let checks = vec![await_log(
        Party::Server,
        TestLogs::ServerSpawned(SERVER_ADDRESS.to_string() + ":1113"),
    )];

    // Wait up to 30sec for the servers to set up or fail
    match future::join_all(checks)
        .with_timeout(Duration::from_secs(30))
        .await
    {
        Err(_) => panic!("Server setup timed out"),
        Ok(results) => {
            match results
                .into_iter()
                .collect::<Result<Vec<()>, anyhow::Error>>()
            {
                Ok(_) => {}
                Err(err) => panic!(
                    "Failed to read logs while waiting for servers to set up: {:?}",
                    err
                ),
            }
        }
    }

    server_handle
}

#[allow(unused)]
pub async fn teardown(server_future: ServerFuture, db: Database) {
    // Ignore the result because we expect it to be an `Expired` error
    let _result = server_future.with_timeout(Duration::from_secs(1)).await;

    // Delete data from this run
    let _ = fs::remove_dir_all("tests/gen/");

    // Drop the test DB
    db.drop(None).await;
}

/// Encode the customizable fields of the keymgmt client Config struct for
/// testing.
async fn client_test_config() -> dams::config::client::Config {
    let m = HashMap::from([("trust_certificate", "\"localhost.crt\"")]);

    let contents = m.into_iter().fold("".to_string(), |acc, (key, value)| {
        format!("{}{} = {}\n", acc, key, value)
    });

    write_config_file(CLIENT_CONFIG, contents);

    dams::config::client::Config::load(CLIENT_CONFIG)
        .await
        .expect("Failed to load client config")
}

/// Encode the customizable fields of the keymgmt server Config struct for
/// testing.
async fn server_test_config() -> dams::config::server::Config {
    // Helper to write out the service for the server service addresses
    let services = HashMap::from([
        ("address", SERVER_ADDRESS),
        ("private_key", "localhost.key"),
        ("certificate", "localhost.crt"),
        ("opaque_path", "tests/gen/opaque"),
        ("opaque_server_key", "tests/gen/opaque/server_setup"),
    ])
    .into_iter()
    .fold("\n[[service]]".to_string(), |acc, (key, value)| {
        format!("{}\n{} = \"{}\"", acc, key, value)
    });

    write_config_file(SERVER_CONFIG, services.to_string());

    dams::config::server::Config::load(SERVER_CONFIG)
        .await
        .expect("failed to load server config")
}

/// Write out the configuration in `contents` to the file at `path`.
fn write_config_file(path: &str, contents: String) {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .unwrap_or_else(|_| panic!("Could not open config file: {}", path))
        .write_all(contents.as_bytes())
        .unwrap_or_else(|_| panic!("Failed to write to config file: {}", path));
}

#[derive(Debug, Error)]
#[allow(unused)]
pub enum LogError {
    #[error("Failed to open log file: {0}")]
    OpenFailed(std::io::Error),
    #[error("Failed to read contents of file: {0}")]
    ReadFailed(std::io::Error),
}

#[allow(unused)]
#[derive(Debug, Clone, Copy)]
pub enum LogType {
    Info,
    Error,
    Warn,
}

#[allow(unused)]
impl LogType {
    pub fn to_str(self) -> &'static str {
        match self {
            LogType::Info => "INFO",
            LogType::Error => "ERROR",
            LogType::Warn => "WARN",
        }
    }
}

/// Get any errors from the log file, filtered by party and log type.
#[allow(unused)]
pub fn get_logs(log_type: LogType, party: Party) -> Result<String, LogError> {
    let mut file = File::open(ERROR_FILENAME).map_err(LogError::OpenFailed)?;
    let mut logs = String::new();
    file.read_to_string(&mut logs)
        .map_err(LogError::ReadFailed)?;

    Ok(logs
        .lines()
        .filter(|s| s.contains("dams_key_server::"))
        .filter(|s| s.contains(log_type.to_str()))
        .filter(|s| s.contains(party.to_str()))
        .fold("".to_string(), |acc, s| format!("{}{}\n", acc, s)))
}

/// Wait for the log file to contain a specific entry.
///
/// This checks the log every 1 second; refactor if greater granularity is
/// needed.
#[allow(unused)]
pub async fn await_log(party: Party, log: TestLogs) -> Result<(), anyhow::Error> {
    loop {
        let result = get_logs(LogType::Info, party);
        if result?.contains(&log.to_string()) {
            return Ok(());
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}
