mod common;

use common::{get_logs, LogType, Party};
use Operation::{Authenticate, Generate, Register, Retrieve};
use Party::{Client, Server};

use dams::{config::client::Config, crypto::KeyId, user::AccountName, RetrieveContext};
use dams_client::{
    api::arbitrary_secrets::RetrieveResult, client::Password, DamsClient, DamsClientError,
};
use rand::{distributions::Alphanumeric, Rng};
use serde::Serialize;
use serde_json::Value;
use std::{collections::HashMap, fs::OpenOptions, str::FromStr};
use thiserror::Error;

const USER: &str = "user";
const PASSWORD: &str = "password";
const GENERATED_ID: &str = "generated_key_id";
const GENERATED_KEY: &str = "generated_key";

#[tokio::test]
pub async fn end_to_end_tests() {
    let context = common::setup().await;

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
    for mut test in tests {
        eprintln!("\n\ntest integration_tests::{} ... ", test.name);
        let result = test.execute(&context.client_config).await;
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
    for result in results.into_iter() {
        match result {
            Ok(_) => {}
            Err(err) => {
                errors.push(err);
            }
        }
    }

    context.teardown().await;
    if !errors.is_empty() {
        panic!("Test failed: {:?}", errors);
    }
}

/// Get a list of tests to execute.
/// Assumption: none of these will cause a fatal error to the long-running
/// processes (server).
async fn tests() -> Vec<Test> {
    vec![
        Test::new(
            "Register the same user twice user".to_string(),
            vec![
                (
                    Register,
                    Outcome {
                        error: None,
                        expected_error: None,
                    },
                ),
                (
                    Register,
                    Outcome {
                        error: Some(Client),
                        expected_error: Some(DamsClientError::RegistrationFailed),
                    },
                ),
            ],
        ),
        Test::new(
            "Register and open multiple sessions as a client to the server".to_string(),
            vec![
                (
                    Register,
                    Outcome {
                        error: None,
                        expected_error: None,
                    },
                ),
                (
                    Authenticate(None),
                    Outcome {
                        error: None,
                        expected_error: None,
                    },
                ),
                (
                    Authenticate(None),
                    Outcome {
                        error: None,
                        expected_error: None,
                    },
                ),
            ],
        ),
        Test::new(
            "Register and authenticate with wrong password fails as a client to the server"
                .to_string(),
            vec![
                (
                    Register,
                    Outcome {
                        error: None,
                        expected_error: None,
                    },
                ),
                (
                    Authenticate(Some(Password::from_str("wrongPassword").unwrap())),
                    Outcome {
                        error: Some(Client),
                        expected_error: Some(DamsClientError::AuthenticationFailed),
                    },
                ),
            ],
        ),
        Test::new(
            "Authenticate with unregistered user fails".to_string(),
            vec![(
                Authenticate(None),
                Outcome {
                    error: Some(Client),
                    expected_error: Some(DamsClientError::AuthenticationFailed),
                },
            )],
        ),
        Test::new(
            "Generate a secret".to_string(),
            vec![
                (
                    Register,
                    Outcome {
                        error: None,
                        expected_error: None,
                    },
                ),
                (
                    Generate,
                    Outcome {
                        error: None,
                        expected_error: None,
                    },
                ),
            ],
        ),
        Test::new(
            "Retrieve a secret".to_string(),
            vec![
                (
                    Register,
                    Outcome {
                        error: None,
                        expected_error: None,
                    },
                ),
                (
                    Generate,
                    Outcome {
                        error: None,
                        expected_error: None,
                    },
                ),
                (
                    Retrieve,
                    Outcome {
                        error: None,
                        expected_error: None,
                    },
                ),
            ],
        ),
    ]
}

#[derive(Debug)]
struct TestState {
    pub state: HashMap<String, Value>,
}

impl TestState {
    pub fn new() -> Self {
        Self {
            state: HashMap::new(),
        }
    }

    pub fn get(&self, key: &str) -> Result<&Value, anyhow::Error> {
        let val = self
            .state
            .get(key)
            .ok_or_else(|| TestError::TestStateError("Unable to get state".to_string()))?;
        Ok(val)
    }

    pub fn set<T, V>(&mut self, key: T, value: V) -> Result<(), anyhow::Error>
    where
        T: Into<String>,
        V: Serialize,
    {
        let value_json = serde_json::to_value(value)?;
        let prev_state = self.state.insert(key.into(), value_json);
        if prev_state.is_some() {
            return Err(TestError::TestStateError("State was overwritten".to_string()).into());
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Test {
    pub name: String,
    pub account_name: AccountName,
    pub password: Password,
    pub operations: Vec<(Operation, Outcome)>,
    pub state: TestState,
}

impl Test {
    fn generate_tag() -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(7)
            .map(char::from)
            .collect()
    }

    fn new(name: String, operations: Vec<(Operation, Outcome)>) -> Self {
        let tag = Self::generate_tag();
        let account_name = AccountName::from_str(format!("{}-{}", USER, tag).as_str()).unwrap();
        let password = Password::from_str(format!("{}-{}", PASSWORD, tag).as_str()).unwrap();

        Self {
            name,
            account_name,
            password,
            operations,
            state: TestState::new(),
        }
    }

    async fn execute(&mut self, config: &Config) -> Result<(), anyhow::Error> {
        for (op, expected_outcome) in &self.operations {
            let outcome: Result<(), anyhow::Error> = match op {
                Register => DamsClient::register(&self.account_name, &self.password, config)
                    .await
                    .map_err(|e| e.into()),
                Authenticate(pwd) => {
                    let password = match pwd {
                        Some(pwd) => pwd,
                        None => &self.password,
                    };
                    DamsClient::authenticated_client(&self.account_name, password, config)
                        .await
                        .map(|_| ())
                        .map_err(|e| e.into())
                }
                Generate => {
                    // Authenticate and run generate
                    let dams_client = DamsClient::authenticated_client(
                        &self.account_name,
                        &self.password,
                        config,
                    )
                    .await?;
                    let (key_id, local_storage) = dams_client.generate_and_store().await?;
                    // Store generated key ID and local storage object to state
                    self.state.set(GENERATED_ID.to_string(), key_id)?;
                    self.state.set(GENERATED_KEY.to_string(), local_storage)
                }
                Retrieve => {
                    // Authenticate
                    let dams_client = DamsClient::authenticated_client(
                        &self.account_name,
                        &self.password,
                        config,
                    )
                    .await?;
                    // Get KeyId from state and run retrieve
                    let key_id_json = self.state.get(GENERATED_ID)?;
                    let key_id: KeyId = serde_json::from_value(key_id_json.clone())?;
                    let res = dams_client
                        .retrieve(&key_id, RetrieveContext::LocalOnly)
                        .await?;
                    let original_local_storage_json = self.state.get(GENERATED_KEY)?.clone();

                    // Ensure result matches what was stored in generate
                    match res {
                        RetrieveResult::None => Err(TestError::InvalidValueRetrieved(
                            original_local_storage_json,
                            Value::Null,
                        )),
                        RetrieveResult::ExportedKey(exported) => {
                            let exported_json = serde_json::to_value(exported)?;
                            Err(TestError::InvalidValueRetrieved(
                                original_local_storage_json,
                                exported_json,
                            ))
                        }
                        RetrieveResult::ArbitraryKey(local_storage) => {
                            let new_local_storage_json = serde_json::to_value(local_storage)?;
                            if original_local_storage_json != new_local_storage_json {
                                Err(TestError::InvalidValueRetrieved(
                                    original_local_storage_json,
                                    new_local_storage_json,
                                ))
                            } else {
                                Ok(())
                            }
                        }
                    }?;

                    Ok(())
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
    #[error("An error occurred while working with test state: {0:?}")]
    TestStateError(String),
    #[error(
        "The wrong value was retrieved from the key server:
    expected: {0:?}
    got: {1:?}"
    )]
    InvalidValueRetrieved(Value, Value),
}

/// Set of operations that can be executed by the test harness
#[allow(unused)]
#[derive(Debug)]
enum Operation {
    Register,
    Authenticate(Option<Password>),
    Generate,
    Retrieve,
}

#[derive(Debug)]
struct Outcome {
    /// Which process, if any, had an error? Assumes that exactly one party will
    /// error.
    error: Option<Party>,
    expected_error: Option<DamsClientError>,
}
