pub(crate) mod common;

use crate::Operation::{Authenticate, Create, Register, Retrieve};
use crate::Party::{Client, Server};
use anyhow::anyhow;
use common::{get_logs, LogType, Party};
use da_mgmt::client::Config;
use da_mgmt::keys::UserId;
use da_mgmt::local_client::{Password, Session, SessionConfig};
use da_mgmt::transport::KeyMgmtAddress;
use da_mgmt::{client, client::key_mgmt::Command};
use std::fs::OpenOptions;
use std::str::FromStr;
use structopt::StructOpt;
use thiserror::Error;

// Form a client CLI request. These cannot be constructed directly because the
// CLI types are non-exhaustive.
macro_rules! client_cli {
    ($cli:ident, $args:expr) => {
        match ::da_mgmt::client::cli::Client::from_iter(
            ::std::iter::once("key-mgmt-client").chain($args),
        ) {
            ::da_mgmt::client::cli::Client::$cli(result) => result,
            _ => panic!("Failed to parse client CLI"),
        }
    };
}

#[tokio::test]
pub async fn integration_tests() {
    let server_future = common::setup().await;
    let client_config = Config::load(common::CLIENT_CONFIG)
        .await
        .expect("Failed to load client config");

    // Run every test, printing out details if it fails
    let tests = tests(&client_config).await;
    println!("Executing {} tests", tests.len());
    let mut results = Vec::with_capacity(tests.len());

    // Clear error log
    OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&common::ERROR_FILENAME)
        .unwrap_or_else(|e| panic!("Failed to clear error file at start: {:?}", e));
    for test in tests {
        eprintln!("\n\ntest integration_tests::{} ... ", test.name);
        let result = test.execute(&client_config).await;
        if let Err(error) = &result {
            eprintln!("failed with error: {:?}", error)
        } else {
            eprintln!("ok")
        }
        results.push(result);

        // Clear error log
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&common::ERROR_FILENAME)
            .unwrap_or_else(|e| panic!("Failed to clear error file after {}: {:?}", test.name, e));
    }

    // Fail if any test failed. This is separate from evaluation to enforce that
    // _every_ test must run without short-circuiting the execution at first
    // failure
    let mut errors = Vec::with_capacity(results.len());
    for result in results.iter() {
        match result {
            Ok(_) => {}
            Err(err) => {
                errors.push(err);
            }
        }
    }
    if !errors.is_empty() {
        panic!("Test failed: {:?}", errors);
    } else {
        common::teardown(server_future).await;
    }
}

/// Get a list of tests to execute.
/// Assumption: none of these will cause a fatal error to the long-running
/// processes (server).
async fn tests(client_config: &Config) -> Vec<Test> {
    vec![
        Test {
            name: "Create a secret on the server".to_string(),
            operations: vec![(
                Create,
                Outcome {
                    error: None,
                    expected_error: None,
                },
            )],
        },
        Test {
            name: "Register the same user twice user".to_string(),
            operations: vec![
                (
                    Register(
                        UserId::from_str("sameUser").unwrap(),
                        Password::from_str("testPassword1").unwrap(),
                        client_config.clone(),
                    ),
                    Outcome {
                        error: None,
                        expected_error: None,
                    },
                ),
                (
                    Register(
                        UserId::from_str("sameUser").unwrap(),
                        Password::from_str("testPassword2").unwrap(),
                        client_config.clone(),
                    ),
                    Outcome {
                        error: Some(Client),
                        expected_error: Some(anyhow!("RegistrationFailed")),
                    },
                ),
            ],
        },
        Test {
            name: "Register and open multiple sessions as a client to the server".to_string(),
            operations: vec![
                (
                    Register(
                        UserId::from_str("testUser").unwrap(),
                        Password::from_str("testPassword").unwrap(),
                        client_config.clone(),
                    ),
                    Outcome {
                        error: None,
                        expected_error: None,
                    },
                ),
                (
                    Authenticate(
                        UserId::from_str("testUser").unwrap(),
                        Password::from_str("testPassword").unwrap(),
                        client_config.clone(),
                    ),
                    Outcome {
                        error: None,
                        expected_error: None,
                    },
                ),
                (
                    Authenticate(
                        UserId::from_str("testUser").unwrap(),
                        Password::from_str("testPassword").unwrap(),
                        client_config.clone(),
                    ),
                    Outcome {
                        error: None,
                        expected_error: None,
                    },
                ),
            ],
        },
        Test {
            name: "Register and authenticate with wrong password fails as a client to the server"
                .to_string(),
            operations: vec![
                (
                    Register(
                        UserId::from_str("testUser2").unwrap(),
                        Password::from_str("testPassword2").unwrap(),
                        client_config.clone(),
                    ),
                    Outcome {
                        error: None,
                        expected_error: None,
                    },
                ),
                (
                    Authenticate(
                        UserId::from_str("testUser2").unwrap(),
                        Password::from_str("wrongPassword").unwrap(),
                        client_config.clone(),
                    ),
                    Outcome {
                        error: Some(Client),
                        expected_error: Some(anyhow!("AuthenticationFailed")),
                    },
                ),
            ],
        },
        Test {
            name: "Authenticate with unregistered user fails".to_string(),
            operations: vec![(
                Authenticate(
                    UserId::from_str("unregisteredUser").unwrap(),
                    Password::from_str("testPassword").unwrap(),
                    client_config.clone(),
                ),
                Outcome {
                    error: Some(Client),
                    expected_error: Some(anyhow!("AuthenticationFailed")),
                },
            )],
        },
        Test {
            name: "Retrieve a secret from the server".to_string(),
            operations: vec![(
                Retrieve,
                Outcome {
                    error: None,
                    expected_error: None,
                },
            )],
        },
    ]
}

#[derive(Debug)]
struct Test {
    pub name: String,
    pub operations: Vec<(Operation, Outcome)>,
}

impl Test {
    async fn execute(&self, client_config: &client::Config) -> Result<(), anyhow::Error> {
        for (op, expected_outcome) in &self.operations {
            let outcome = match op {
                Create => {
                    let create = client_cli!(Create, vec!["create", "keymgmt://localhost"]);
                    create.run(client_config.clone()).await
                }
                Register(user_id, password, client_config) => {
                    let config = SessionConfig::new(
                        client_config.clone(),
                        KeyMgmtAddress::from_str("keymgmt://localhost").unwrap(),
                    );
                    Session::register(user_id, password, &config)
                        .await
                        .map(|_| ())
                        .map_err(|e| e.into())
                }
                Retrieve => {
                    let retrieve = client_cli!(Retrieve, vec!["retrieve", "keymgmt://localhost"]);
                    retrieve.run(client_config.clone()).await.map(|_| ())
                }

                Authenticate(user_id, password, client_config) => {
                    let config = SessionConfig::new(
                        client_config.clone(),
                        KeyMgmtAddress::from_str("keymgmt://localhost").unwrap(),
                    );
                    Session::open(user_id, password, &config)
                        .await
                        .map(|_| ())
                        .map_err(|e| e.into())
                }
            };

            // Get error logs for each party - we make the following assumptions:
            // - logs are deleted after each test, so all errors correspond to this test
            // - any Operation that throws an error is the final Operation in the test
            // These mean that any error found in the logs is caused by the current
            // operation
            let server_errors = get_logs(LogType::Error, Party::Server)?;

            // Check whether the process errors matched the expectation.
            match (&expected_outcome.error, &outcome, server_errors.is_empty()) {
                // No party threw an error
                (None, Ok(_), true) => Ok(()),
                // Only the active operation threw an error
                (Some(Server), Err(_), false) => Ok(()),
                (Some(Client), Err(e), true) => {
                    assert_eq!(
                        expected_outcome
                            .expected_error
                            .as_ref()
                            .unwrap_or(&anyhow!(""))
                            .to_string(),
                        e.to_string()
                    );
                    Ok(())
                }

                // In any other case, something went wrong. Provide lots of details to diagnose
                _ => Err(TestError::InvalidErrorBehavior {
                    server_errors,
                    op_error: outcome,
                }),
            }?;
        }

        Ok(())
    }
}

#[derive(Debug, Error)]
enum TestError {
    // #[error("Operation {0:?} not yet implemented")]
    // NotImplemented(Operation),
    #[error(
        "The error behavior did not satisfy expected behavior. Got
    SERVER OUTPUT:
    {server_errors}
    OPERATION OUTPUT:
    {op_error:?}"
    )]
    InvalidErrorBehavior {
        server_errors: String,
        op_error: Result<(), anyhow::Error>,
    },
}

/// Set of operations that can be executed by the test harness
#[allow(unused)]
#[derive(Debug)]
enum Operation {
    Create,
    Register(UserId, Password, Config),
    Retrieve,
    Authenticate(UserId, Password, Config),
}

#[derive(Debug)]
struct Outcome {
    /// Which process, if any, had an error? Assumes that exactly one party will
    /// error.
    error: Option<Party>,
    expected_error: Option<anyhow::Error>,
}
