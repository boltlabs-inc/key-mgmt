use Operation::{Authenticate, Generate, Register, Retrieve};

use lock_keeper::{config::client::Config, crypto::KeyId, user::AccountName, RetrieveContext};
use lock_keeper_client::{
    api::arbitrary_secrets::RetrieveResult, client::Password, LockKeeperClient,
    LockKeeperClientError,
};
use rand::{distributions::Alphanumeric, Rng};
use serde::Serialize;
use serde_json::Value;
use std::{collections::HashMap, str::FromStr};
use thiserror::Error;

const USER: &str = "user";
const PASSWORD: &str = "password";
const GENERATED_ID: &str = "generated_key_id";
const GENERATED_KEY: &str = "generated_key";

pub async fn end_to_end_tests(client_config: &Config) {
    // Run every test, printing out details if it fails
    let tests = tests().await;
    println!("Executing {} tests", tests.len());
    let mut results = Vec::new();

    for mut test in tests {
        println!("\n\ntest integration_tests::{} ... ", test.name);
        let result = test.execute(client_config).await;
        if let Err(error) = &result {
            println!("failed with error: {:?}", error)
        } else {
            println!("ok")
        }

        results.push(TestResult {
            name: test.name,
            error: result.err().map(|e| e.to_string()),
        });
    }

    let failed_tests: Vec<TestResult> = results.into_iter().filter(|r| r.error.is_some()).collect();

    if !failed_tests.is_empty() {
        println!("Tests failed:");
        for test in failed_tests {
            println!(
                "{} => {}",
                test.name,
                test.error.unwrap_or_else(|| "No error message".to_string())
            );
        }

        std::process::exit(1);
    }
}

/// Get a list of tests to execute.
/// Assumption: none of these will cause a fatal error to the long-running
/// processes (server).
async fn tests() -> Vec<Test> {
    vec![
        Test::new(
            "Register the same user twice user",
            vec![
                (
                    Register,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    Register,
                    Outcome {
                        expected_error: Some(LockKeeperClientError::AccountAlreadyRegistered),
                    },
                ),
            ],
        ),
        Test::new(
            "Register and open multiple sessions as a client to the server",
            vec![
                (
                    Register,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    Authenticate(None),
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    Authenticate(None),
                    Outcome {
                        expected_error: None,
                    },
                ),
            ],
        ),
        Test::new(
            "Register and authenticate with wrong password fails as a client to the server",
            vec![
                (
                    Register,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    Authenticate(Some(Password::from_str("wrongPassword").unwrap())),
                    Outcome {
                        expected_error: Some(LockKeeperClientError::InvalidLogin),
                    },
                ),
            ],
        ),
        Test::new(
            "Authenticate with unregistered user fails",
            vec![(
                Authenticate(None),
                Outcome {
                    expected_error: Some(LockKeeperClientError::InvalidAccount),
                },
            )],
        ),
        Test::new(
            "Generate a secret",
            vec![
                (
                    Register,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    Generate,
                    Outcome {
                        expected_error: None,
                    },
                ),
            ],
        ),
        Test::new(
            "Retrieve a secret",
            vec![
                (
                    Register,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    Generate,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    Retrieve,
                    Outcome {
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

    fn new(name: impl Into<String>, operations: Vec<(Operation, Outcome)>) -> Self {
        let tag = Self::generate_tag();
        let account_name = AccountName::from_str(format!("{}-{}", USER, tag).as_str()).unwrap();
        let password = Password::from_str(format!("{}-{}", PASSWORD, tag).as_str()).unwrap();

        Self {
            name: name.into(),
            account_name,
            password,
            operations,
            state: TestState::new(),
        }
    }

    async fn execute(&mut self, config: &Config) -> Result<(), anyhow::Error> {
        for (op, expected_outcome) in &self.operations {
            let outcome: Result<(), anyhow::Error> = match op {
                Register => LockKeeperClient::register(&self.account_name, &self.password, config)
                    .await
                    .map_err(|e| e.into()),
                Authenticate(pwd) => {
                    let password = match pwd {
                        Some(pwd) => pwd,
                        None => &self.password,
                    };
                    LockKeeperClient::authenticated_client(&self.account_name, password, config)
                        .await
                        .map(|_| ())
                        .map_err(|e| e.into())
                }
                Generate => {
                    // Authenticate and run generate
                    let lock_keeper_client = LockKeeperClient::authenticated_client(
                        &self.account_name,
                        &self.password,
                        config,
                    )
                    .await?;
                    let (key_id, local_storage) = lock_keeper_client.generate_and_store().await?;
                    // Store generated key ID and local storage object to state
                    self.state.set(GENERATED_ID.to_string(), key_id)?;
                    self.state.set(GENERATED_KEY.to_string(), local_storage)
                }
                Retrieve => {
                    // Authenticate
                    let lock_keeper_client = LockKeeperClient::authenticated_client(
                        &self.account_name,
                        &self.password,
                        config,
                    )
                    .await?;
                    // Get KeyId from state and run retrieve
                    let key_id_json = self.state.get(GENERATED_ID)?;
                    let key_id: KeyId = serde_json::from_value(key_id_json.clone())?;
                    let res = lock_keeper_client
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

            // Check whether the process errors matched the expectation.
            if let Err(e) = outcome {
                match &expected_outcome.expected_error {
                    Some(expected) => {
                        let expected_string = expected.to_string();
                        let error_string = e.to_string();
                        if expected_string != error_string {
                            return Err(
                                TestError::IncorrectError(expected_string, error_string).into()
                            );
                        }
                    }
                    None => return Err(TestError::UnexpectedError.into()),
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Error)]
enum TestError {
    #[error("An error was returned when none was expected")]
    UnexpectedError,
    #[error("Incorrect error. Expected: {}. Got: {}.", .0, .1)]
    IncorrectError(String, String),

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
    expected_error: Option<LockKeeperClientError>,
}

#[derive(Debug)]
struct TestResult {
    pub name: String,
    pub error: Option<String>,
}
