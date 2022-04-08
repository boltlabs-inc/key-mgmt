use std::io::Read;
use std::{
    collections::HashMap,
    fmt,
    fs::{self, File},
    io::Write,
    process::Command,
    sync::Mutex,
};
use structopt::StructOpt;

use futures::future;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use thiserror::Error;
use tokio::{task::JoinHandle, time::Duration};
use tracing::info_span;
use tracing_futures::Instrument;

use keymgmt::TestLogs;

use keymgmt::{server::keymgmt::Command as _, timeout::WithTimeout};

pub const CLIENT_CONFIG: &str = "tests/gen/TestClient.toml";
pub const SERVER_CONFIG: &str = "tests/gen/TestServer.toml";
pub const ERROR_FILENAME: &str = "tests/gen/errors.log";

/// The default server services we will set up for tests (all run on localhost)
#[derive(Debug, Clone, Copy, EnumIter)]
enum ServerServices {
    IpV4,
    // The server supports IPv6 but it doesn't run on the Github Actions test harness.
    //IpV6,
}

impl ServerServices {
    fn to_str(self) -> &'static str {
        match self {
            Self::IpV4 => "127.0.0.1",
            //Self::IpV6 => "::1",
        }
    }
}

impl fmt::Display for ServerServices {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Note: this hard-codes the default port.
        let ipaddr = match self {
            Self::IpV4 => self.to_str().to_string(),
            //Self::IpV6 => format!("[{}]", self.to_str()),
        };
        write!(f, "{}:1113", ipaddr)
    }
}

/// Give a name to the slightly annoying type of the joined server futures
type ServerFuture = JoinHandle<Result<(), anyhow::Error>>;

/// Set of processes that run during a test.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Party {
    Server,
}

impl Party {
    pub const fn to_str(self) -> &'static str {
        match self {
            Party::Server => "party: server",
        }
    }
}

// Form a client CLI request. These cannot be constructed directly because the CLI types are
// non-exhaustive.
macro_rules! _client_cli {
    ($cli:ident, $args:expr) => {
        match ::keymgmt::client::cli::Client::from_iter(
            ::std::iter::once("key-mgmt-client").chain($args),
        ) {
            ::keymgmt::client::cli::Client::$cli(result) => result,
            _ => panic!("Failed to parse client CLI"),
        }
    };
}

/// Form a server CLI request. These cannot be constructed directly because the CLI types are
/// non-exhaustive.
macro_rules! server_cli {
    ($cli:ident, $args:expr) => {
        match ::keymgmt::server::cli::Server::from_iter(
            ::std::iter::once("key-mgmt-server").chain($args),
        ) {
            ::keymgmt::server::cli::Server::$cli(result) => result,
            _ => panic!("Failed to parse server CLI"),
        }
    };
}
pub(crate) use server_cli;

pub async fn setup() -> ServerFuture {
    let _ = fs::create_dir("tests/gen");

    // Create self-signed SSL certificate in the generated directory
    Command::new("./dev/generate-certificates")
        .arg("tests/gen")
        .spawn()
        .expect("Failed to generate new certificates");
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

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
    let run = server_cli!(Run, vec!["run"]);
    let server_handle = tokio::spawn(
        run.run(server_config)
            .instrument(info_span!(Party::Server.to_str())),
    );

    // Check the logs of server + client for indication of a successful set-up
    // Note: hard-coded to match the 2-service server with default port.
    let checks = vec![await_log(
        Party::Server,
        TestLogs::ServerSpawned(ServerServices::IpV4.to_string()),
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

pub async fn teardown(server_future: ServerFuture) {
    // Ignore the result because we expect it to be an `Expired` error
    let _result = server_future.with_timeout(Duration::from_secs(1)).await;

    // Delete data from this run
    let _ = fs::remove_dir_all("tests/gen/");
}

/// Encode the customizable fields of the keymgmt client Config struct for testing.
async fn client_test_config() -> keymgmt::client::Config {
    let m = HashMap::from([("trust_certificate", "\"localhost.crt\"")]);

    let contents = m.into_iter().fold("".to_string(), |acc, (key, value)| {
        format!("{}{} = {}\n", acc, key, value)
    });

    write_config_file(CLIENT_CONFIG, contents);

    keymgmt::client::Config::load(CLIENT_CONFIG)
        .await
        .expect("Failed to load client config")
}

/// Encode the customizable fields of the keymgmt server Config struct for testing.
async fn server_test_config() -> keymgmt::server::Config {
    // Helper to write out the service for the server service addresses
    let generate_service = |addr: ServerServices| {
        HashMap::from([
            ("address", addr.to_str()),
            ("private_key", "localhost.key"),
            ("certificate", "localhost.crt"),
        ])
        .into_iter()
        .fold("\n[[service]]".to_string(), |acc, (key, value)| {
            format!("{}\n{} = \"{}\"", acc, key, value)
        })
    };

    let services = ServerServices::iter()
        .map(generate_service)
        .fold(String::new(), |acc, next| format!("{}\n{}", acc, next));

    write_config_file(SERVER_CONFIG, services.to_string());

    keymgmt::server::Config::load(SERVER_CONFIG)
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
fn get_logs(log_type: LogType, party: Party) -> Result<String, LogError> {
    let mut file = File::open(ERROR_FILENAME).map_err(LogError::OpenFailed)?;
    let mut logs = String::new();
    file.read_to_string(&mut logs)
        .map_err(LogError::ReadFailed)?;

    Ok(logs
        .lines()
        .filter(|s| s.contains("keymgmt::"))
        .filter(|s| s.contains(log_type.to_str()))
        .filter(|s| s.contains(party.to_str()))
        .fold("".to_string(), |acc, s| format!("{}{}\n", acc, s)))
}

/// Wait for the log file to contain a specific entry.
///
/// This checks the log every 1 second; refactor if greater granularity is needed.
async fn await_log(party: Party, log: TestLogs) -> Result<(), anyhow::Error> {
    loop {
        let result = get_logs(LogType::Info, party);
        if result?.contains(&log.to_string()) {
            return Ok(());
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}
