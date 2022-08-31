use std::{
    fs::{self, File},
    io::Read,
    process::Command,
    str::FromStr,
    sync::Mutex,
};

use futures::future;
use mongodb::Database;
use tokio::{task::JoinHandle, time::Duration};
use tracing::info_span;
use tracing_futures::Instrument;

use dams::{timeout::WithTimeout, TestLogs};

pub const ERROR_FILENAME: &str = "tests/gen/errors.log";

pub const SERVER_ADDRESS: &str = "127.0.0.1";

/// Give a name to the slightly annoying type of the joined server futures
type ServerFuture = JoinHandle<Result<(), dams_key_server::DamsServerError>>;

/// Set of processes that run during a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

pub async fn setup(db: Database, server_config: dams::config::server::Config) -> ServerFuture {
    let gen_path = std::path::Path::new("tests/gen");
    if !gen_path.exists() {
        fs::create_dir(gen_path).expect("Unable to create directory tests/gen");
    }

    // Create self-signed SSL certificate in the generated directory
    Command::new("../dev/generate-certificates")
        .arg("tests/gen")
        .spawn()
        .expect("Failed to generate new certificates");
    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

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

    // Delete any outdated data
    db.drop(None).await.unwrap();

    server_handle
}

pub async fn teardown(server_future: ServerFuture, db: Database) {
    // Ignore the result because we expect it to be an `Expired` error
    let _result = server_future.with_timeout(Duration::from_secs(1)).await;

    // Delete data from this run
    let _ = fs::remove_dir_all("tests/gen/");

    // Drop the test DB
    db.drop(None).await.unwrap();
}

/// Encode the customizable fields of the keymgmt client Config struct for
/// testing.
pub async fn client_test_config() -> dams::config::client::Config {
    let config_str = r#"
        server_location = "https://127.0.0.1:1113"
        trust_certificate = "tests/gen/localhost.crt"
    "#;

    dams::config::client::Config::from_str(config_str).expect("Failed to load client config")
}

/// Encode the customizable fields of the keymgmt server Config struct for
/// testing.
pub async fn server_test_config() -> dams::config::server::Config {
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

    dams::config::server::Config::from_str(&config_str).expect("failed to load server config")
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
