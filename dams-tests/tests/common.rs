use std::{
    fs::{self, File},
    io::Read,
    path::Path,
    process::Command,
    str::FromStr,
    sync::Mutex,
};

use futures::future;
use mongodb::Database;
use tokio::{task::JoinHandle, time::Duration};
use tracing::info_span;
use tracing_futures::Instrument;

use dams::{
    config::{client::Config as ClientConfig, server::Config as ServerConfig},
    defaults::server::LOCAL_SERVER_URI,
    timeout::WithTimeout,
    TestLogs,
};
use dams_key_server::database;

pub const ERROR_FILENAME: &str = "tests/gen/errors.log";
pub const SERVER_ADDRESS: &str = "127.0.0.1";

/// Give a name to the slightly annoying type of the joined server futures
pub type ServerFuture = JoinHandle<Result<(), dams_key_server::DamsServerError>>;

pub async fn setup() -> TestContext {
    // Read environment variables from .env file
    let server_config = server_test_config().await;
    let database = database::connect_to_mongo(&server_config.database)
        .await
        .expect("Unable to connect to Mongo");

    generate_files(database.clone()).await;

    let server_future = start_server(server_config).await;
    let client_config = client_test_config().await;

    TestContext {
        server_future,
        client_config,
        database,
    }
}

async fn generate_files(db: Database) {
    // Delete data from previous run
    let gen_path = Path::new("tests/gen/");
    // Swallow error if path doesn't exist
    let _ = fs::remove_dir_all(&gen_path);
    fs::create_dir_all(&gen_path).expect("Unable to create directory tests/gen");

    // Ensure that the test DB is fresh
    db.drop(None).await.expect("Failed to drop database");

    // Create self-signed SSL certificate in the generated directory
    Command::new("../dev/generate-certificates")
        .arg("tests/gen")
        .spawn()
        .expect("Failed to generate new certificates");
    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
}

async fn start_server(server_config: ServerConfig) -> ServerFuture {
    // set up tracing for all log messages
    tracing_subscriber::fmt()
        .with_writer(Mutex::new(
            File::create(ERROR_FILENAME).expect("Failed to open log file"),
        ))
        .init();

    // Form the server run request and execute
    #[allow(clippy::infallible_destructuring_match)]
    let server_handle = tokio::spawn(
        dams_key_server::server::start_tonic_server(server_config)
            .instrument(info_span!(Party::Server.to_str())),
    );
    // Check the logs of server + client for indication of a successful set-up
    // Note: hard-coded to match the 2-service server with default port.
    let checks = vec![await_log(
        Party::Server,
        TestLogs::ServerSpawned(format!("{}:1113", SERVER_ADDRESS)),
    )];

    // Wait up to 30sec for the servers to set up or fail
    match future::join_all(checks)
        .with_timeout(Duration::from_secs(30))
        .await
    {
        Err(_) => panic!("Server setup timed out"),
        Ok(results) => match results
            .into_iter()
            .collect::<Result<Vec<()>, anyhow::Error>>()
        {
            Ok(_) => {}
            Err(err) => panic!(
                "Failed to read logs while waiting for servers to set up: {:?}",
                err
            ),
        },
    }

    server_handle
}

/// Encode the customizable fields of the keymgmt client Config struct for
/// testing.
async fn client_test_config() -> ClientConfig {
    let config_str = format!(
        r#"
        server_location = "{}"
        trust_certificate = "tests/gen/localhost.crt"
    "#,
        LOCAL_SERVER_URI
    );

    ClientConfig::from_str(&config_str).expect("Failed to load client config")
}

/// Encode the customizable fields of the keymgmt server Config struct for
/// testing.
async fn server_test_config() -> ServerConfig {
    let config_str = format!(
        r#"
        [[service]]
        address = "{}"
        port = 1113
        private_key = "tests/gen/localhost.key"
        certificate = "tests/gen/localhost.crt"
        opaque_path = "tests/gen/opaque"
        opaque_server_key = "tests/gen/opaque/server_setup"

        [database]
        mongodb_uri = "mongodb://localhost:27017"
        db_name = "dams-test-db"
    "#,
        SERVER_ADDRESS
    );

    ServerConfig::from_str(&config_str).expect("failed to load server config")
}

/// Set of processes that run during a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

pub struct TestContext {
    server_future: ServerFuture,
    pub client_config: ClientConfig,
    pub database: Database,
}

impl TestContext {
    pub async fn teardown(self) {
        // Ignore the result because we expect it to be an `Expired` error
        let _result = self
            .server_future
            .with_timeout(Duration::from_secs(1))
            .await;
    }
}

#[allow(unused)]
#[derive(Debug, Clone, Copy)]
pub enum LogType {
    Info,
    Error,
    Warn,
}

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
pub fn get_logs(log_type: LogType, party: Party) -> Result<String, anyhow::Error> {
    let mut file = File::open(ERROR_FILENAME)?;
    let mut logs = String::new();
    file.read_to_string(&mut logs)?;

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
pub async fn await_log(party: Party, log: TestLogs) -> Result<(), anyhow::Error> {
    loop {
        let result = get_logs(LogType::Info, party);
        if result?.contains(&log.to_string()) {
            return Ok(());
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}
