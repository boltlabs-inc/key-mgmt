pub(crate) mod common;

use crate::{
    Operation::{Authenticate, Register},
    Party::{Client, Server},
};
use common::{get_logs, LogType, Party};

use dams::{config::client::Config, user::AccountName};
use dams_client::{client::Password, DamsClient, DamsClientError};
use dams_key_server::database;
use std::{fs::OpenOptions, str::FromStr};
use thiserror::Error;

#[tokio::test]
pub async fn integration_tests() {
    // Read environment variables from .env file
    let server_config = common::server_test_config().await;
    let db = database::connect_to_mongo(
        &server_config.database.mongodb_uri,
        &server_config.database.db_name,
    )
    .await
    .expect("Unable to connect to Mongo");
    let server_future = common::setup(db.clone(), server_config).await;
    let client_config = common::client_test_config().await;

    // Run every test, printing out details if it fails
    let tests = tests().await;
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

    common::teardown(server_future, db).await;
    if !errors.is_empty() {
        panic!("Test failed: {:?}", errors);
    }
}

/// Get a list of tests to execute.
/// Assumption: none of these will cause a fatal error to the long-running
/// processes (server).
async fn tests() -> Vec<Test> {
    vec![
        Test {
            name: "Register the same user twice user".to_string(),
            operations: vec![
                (
                    Register(
                        AccountName::from_str("sameUser").unwrap(),
                        Password::from_str("testPassword1").unwrap(),
                    ),
                    Outcome {
                        error: None,
                        expected_error: None,
                    },
                ),
                (
                    Register(
                        AccountName::from_str("sameUser").unwrap(),
                        Password::from_str("testPassword2").unwrap(),
                    ),
                    Outcome {
                        error: Some(Client),
                        expected_error: Some(DamsClientError::RegistrationFailed),
                    },
                ),
            ],
        },
        Test {
            name: "Register and open multiple sessions as a client to the server".to_string(),
            operations: vec![
                (
                    Register(
                        AccountName::from_str("testUser").unwrap(),
                        Password::from_str("testPassword").unwrap(),
                    ),
                    Outcome {
                        error: None,
                        expected_error: None,
                    },
                ),
                (
                    Authenticate(
                        AccountName::from_str("testUser").unwrap(),
                        Password::from_str("testPassword").unwrap(),
                    ),
                    Outcome {
                        error: None,
                        expected_error: None,
                    },
                ),
                (
                    Authenticate(
                        AccountName::from_str("testUser").unwrap(),
                        Password::from_str("testPassword").unwrap(),
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
                        AccountName::from_str("testUser2").unwrap(),
                        Password::from_str("testPassword2").unwrap(),
                    ),
                    Outcome {
                        error: None,
                        expected_error: None,
                    },
                ),
                (
                    Authenticate(
                        AccountName::from_str("testUser2").unwrap(),
                        Password::from_str("wrongPassword").unwrap(),
                    ),
                    Outcome {
                        error: Some(Client),
                        expected_error: Some(DamsClientError::AuthenticationFailed),
                    },
                ),
            ],
        },
        Test {
            name: "Authenticate with unregistered user fails".to_string(),
            operations: vec![(
                Authenticate(
                    AccountName::from_str("unregisteredUser").unwrap(),
                    Password::from_str("testPassword").unwrap(),
                ),
                Outcome {
                    error: Some(Client),
                    expected_error: Some(DamsClientError::AuthenticationFailed),
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
    async fn execute(&self, config: &Config) -> Result<(), anyhow::Error> {
        for (op, expected_outcome) in &self.operations {
            let outcome: Result<(), anyhow::Error> = match op {
                Register(account_name, password) => {
                    DamsClient::register(account_name, password, config)
                        .await
                        .map_err(|e| e.into())
                }
                Authenticate(account_name, password) => {
                    DamsClient::authenticated_client(account_name, password, config)
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
                            .unwrap()
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
    Register(AccountName, Password),
    Authenticate(AccountName, Password),
}

#[derive(Debug)]
struct Outcome {
    /// Which process, if any, had an error? Assumes that exactly one party will
    /// error.
    error: Option<Party>,
    expected_error: Option<DamsClientError>,
}
