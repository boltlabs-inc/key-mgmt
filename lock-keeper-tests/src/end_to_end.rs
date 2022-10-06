use lock_keeper::{
    config::client,
    crypto::KeyId,
    types::{
        audit_event::{AuditEventOptions, EventStatus, EventType},
        database::user::AccountName,
        operations::{retrieve::RetrieveContext, ClientAction},
    },
};
use lock_keeper_client::{
    api::{LocalStorage, RetrieveResult},
    client::Password,
    LockKeeperClient, LockKeeperClientError,
};
use rand::{distributions::Alphanumeric, rngs::StdRng, Rng, SeedableRng};
use serde::Serialize;
use serde_json::Value;
use std::{collections::HashMap, str::FromStr};
use thiserror::Error;

use crate::config::Config;

const USER: &str = "user";
const PASSWORD: &str = "password";
const GENERATED_ID: &str = "generated_key_id";
const GENERATED_KEY: &str = "generated_key";

pub async fn end_to_end_tests(config: &Config) {
    // Run every test, printing out details if it fails
    let tests = tests().await;
    println!("Executing {} tests", tests.len());
    let mut results = Vec::new();

    for mut test in tests {
        println!("\n\ntest integration_tests::{} ... ", test.name);
        if !config.filters.matches(&test.name) {
            println!("skipped");
            continue;
        }

        let result = test.execute(&config.client_config).await;
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
    use Operation::*;

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
        Test::new(
            "Retrieving a non-existent secret fails",
            vec![
                (
                    Register,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    SetFakeKeyId,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    Retrieve,
                    Outcome {
                        expected_error: Some(LockKeeperClientError::InvalidAccount),
                    },
                ),
            ],
        ),
        Test::new(
            "Export a secret",
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
                    Export,
                    Outcome {
                        expected_error: None,
                    },
                ),
            ],
        ),
        Test::new(
            "Exporting a non-existent secret fails",
            vec![
                (
                    Register,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    SetFakeKeyId,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    Export,
                    Outcome {
                        expected_error: Some(LockKeeperClientError::InvalidAccount),
                    },
                ),
            ],
        ),
        Test::new(
            "Remote generate a secret",
            vec![
                (
                    Register,
                    Outcome {
                        expected_error: None,
                    },
                ),
                (
                    RemoteGenerate,
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

    async fn execute(&mut self, config: &client::Config) -> Result<(), anyhow::Error> {
        use Operation::*;

        for (op, expected_outcome) in &self.operations {
            let outcome: Result<(), anyhow::Error> = match op {
                SetFakeKeyId => {
                    // Authenticate
                    let lock_keeper_client = LockKeeperClient::authenticated_client(
                        &self.account_name,
                        &self.password,
                        config,
                    )
                    .await?;
                    // Create fake KeyId and set to GENERATED_ID
                    let mut rng = StdRng::from_entropy();
                    let key_id = KeyId::generate(&mut rng, lock_keeper_client.user_id())?;
                    self.state.set(GENERATED_ID, key_id)?;
                    Ok(())
                }
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
                Export => {
                    // Authenticate
                    let lock_keeper_client = LockKeeperClient::authenticated_client(
                        &self.account_name,
                        &self.password,
                        config,
                    )
                    .await?;

                    // Get KeyId from state and run export
                    let key_id_json = self.state.get(GENERATED_ID)?;
                    let key_id: KeyId = serde_json::from_value(key_id_json.clone())?;
                    match lock_keeper_client.export_key(&key_id).await {
                        Ok(res) => {
                            // Compare generated key and exported key material
                            let original_local_storage_json =
                                self.state.get(GENERATED_KEY)?.clone();
                            let original_local_storage_bytes: Vec<u8> =
                                serde_json::from_value::<LocalStorage>(
                                    original_local_storage_json.clone(),
                                )?
                                .secret
                                .into();
                            let res_json = serde_json::to_value(res.clone())?;
                            if original_local_storage_bytes != res {
                                Err(TestError::InvalidValueRetrieved(
                                    original_local_storage_json,
                                    res_json,
                                )
                                .into())
                            } else {
                                Ok(())
                            }
                        }
                        Err(e) => Err(anyhow::Error::from(e)),
                    }
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
                    self.state.set(GENERATED_ID, key_id)?;
                    self.state.set(GENERATED_KEY, local_storage)
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

                    // Ensure result matches what was stored in generate
                    match lock_keeper_client
                        .retrieve(&key_id, RetrieveContext::LocalOnly)
                        .await
                    {
                        Ok(res) => {
                            let original_local_storage_json =
                                self.state.get(GENERATED_KEY)?.clone();
                            match res {
                                RetrieveResult::None => Err(TestError::InvalidValueRetrieved(
                                    original_local_storage_json,
                                    Value::Null,
                                )
                                .into()),
                                RetrieveResult::ArbitraryKey(local_storage) => {
                                    let new_local_storage_json =
                                        serde_json::to_value(local_storage)?;
                                    if original_local_storage_json != new_local_storage_json {
                                        Err(TestError::InvalidValueRetrieved(
                                            original_local_storage_json,
                                            new_local_storage_json,
                                        )
                                        .into())
                                    } else {
                                        Ok(())
                                    }
                                }
                            }
                        }
                        Err(e) => Err(anyhow::Error::from(e)),
                    }
                }
                RemoteGenerate => {
                    // Authenticate and run remote generate
                    let lock_keeper_client = LockKeeperClient::authenticated_client(
                        &self.account_name,
                        &self.password,
                        config,
                    )
                    .await?;
                    let key_id = lock_keeper_client.remote_generate().await?;
                    // Store generated key ID
                    self.state.set(GENERATED_ID, key_id)?;

                    Ok(())
                }
            };

            // Check whether the process errors matched the expectation.
            match outcome {
                Ok(_) => {
                    self.check_audit_events(config, EventStatus::Successful, op)
                        .await?
                }
                Err(e) => {
                    self.check_audit_events(config, EventStatus::Failed, op)
                        .await?;
                    match &expected_outcome.expected_error {
                        Some(expected) => {
                            let expected_string = expected.to_string();
                            let error_string = e.to_string();
                            if expected_string != error_string {
                                return Err(TestError::IncorrectError(
                                    expected_string,
                                    error_string,
                                )
                                .into());
                            }
                        }
                        None => return Err(TestError::UnexpectedError.into()),
                    }
                }
            }
        }

        Ok(())
    }

    async fn check_audit_events(
        &self,
        config: &client::Config,
        expected_status: EventStatus,
        operation: &Operation,
    ) -> Result<(), anyhow::Error> {
        // Map operation to ClientAction (None case is for expected Auth failures)
        let expected_action = match operation.to_final_client_action(&expected_status) {
            Some(action) => action,
            None => return Ok(()),
        };
        // Authenticate to LockKeeperClient
        let lock_keeper_client =
            LockKeeperClient::authenticated_client(&self.account_name, &self.password, config)
                .await?;

        // Get audit event log
        let audit_event_log = lock_keeper_client
            .retrieve_audit_event_log(EventType::All, AuditEventOptions::default())
            .await?;

        // Get the fourth last event, the last 3 are for retrieving audit logs and
        // authenticating
        let fourth_last = audit_event_log
            .len()
            .checked_sub(4)
            .map(|i| &audit_event_log[i])
            .ok_or_else(|| {
                TestError::InvalidAuditEventLog(
                    "No last element found in audit event log".to_string(),
                )
            })?;
        // Check that expected status and action match
        assert_eq!(expected_status, fourth_last.status());
        assert_eq!(expected_action, fourth_last.action());
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
    #[error("An error occurred while reading the audit log: {0:?}")]
    InvalidAuditEventLog(String),
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
    Authenticate(Option<Password>),
    Export,
    Generate,
    Register,
    RemoteGenerate,
    Retrieve,
    SetFakeKeyId,
}

impl Operation {
    fn to_final_client_action(&self, status: &EventStatus) -> Option<ClientAction> {
        match self {
            Self::Authenticate(_) => {
                if status == &EventStatus::Failed {
                    None
                } else {
                    Some(ClientAction::Authenticate)
                }
            }
            Self::Export => Some(ClientAction::Export),
            Self::Generate => Some(ClientAction::Generate),
            Self::Register => {
                if status == &EventStatus::Successful {
                    Some(ClientAction::CreateStorageKey)
                } else {
                    Some(ClientAction::Register)
                }
            }
            Self::RemoteGenerate => Some(ClientAction::RemoteGenerate),
            Self::Retrieve => Some(ClientAction::Retrieve),
            Self::SetFakeKeyId => None,
        }
    }
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
