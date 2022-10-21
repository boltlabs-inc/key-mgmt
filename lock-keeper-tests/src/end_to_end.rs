//! End-to-end testing framework and test definitions

pub mod operations;
pub mod test_cases;

use anyhow::anyhow;
use colored::Colorize;
use lock_keeper::{
    config::client,
    crypto::KeyId,
    types::{
        audit_event::{AuditEventOptions, EventStatus, EventType},
        database::user::AccountName,
    },
};
use lock_keeper_client::{client::Password, LockKeeperClient, LockKeeperClientError};
use rand::{rngs::StdRng, SeedableRng};
use serde::Serialize;
use serde_json::Value;
use std::{collections::HashMap, str::FromStr};

use crate::{config::Config, utils::tagged};

use self::operations::Operation;

const USER: &str = "user";
const PASSWORD: &str = "password";
const KEY_ID: &str = "generated_key_id";
const KEY_MATERIAL: &str = "generated_key";
const REMOTE_GENERATED_PUBLIC_KEY: &str = "remote_generated_public_key";

pub async fn run_tests(config: &Config) {
    // Run every test, printing out details if it fails
    let tests = test_cases::tests(config).await;
    println!("Executing {} tests", tests.len());
    let mut results = Vec::new();

    for test in tests {
        let name = test.name.clone();
        println!("\n\ntest {} ... ", name);
        if !config.filters.matches(&name) {
            println!("{}", "skipped".bright_blue());
            continue;
        }

        let result = test.execute().await;
        if let Err(error) = &result {
            println!("{}: {:?}", "failed with error".red(), error)
        } else {
            println!("{}", "ok".green())
        }

        results.push(TestResult {
            name,
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

#[derive(Debug)]
pub struct Test {
    pub name: String,
    pub account_name: AccountName,
    pub password: Password,
    pub operations: Vec<(Operation, Outcome)>,
    pub state: TestState,
    pub config: client::Config,
}

impl Test {
    fn new(
        name: impl Into<String>,
        operations: Vec<(Operation, Outcome)>,
        config: client::Config,
    ) -> Self {
        let account_name = AccountName::from_str(&tagged(USER)).unwrap();
        let password = Password::from_str(&tagged(PASSWORD)).unwrap();

        Self {
            name: name.into(),
            account_name,
            password,
            operations,
            state: TestState::new(),
            config,
        }
    }

    async fn execute(mut self) -> Result<(), anyhow::Error> {
        use Operation::*;

        // We need a mutable reference to `self` in the upcoming loop but we also need
        // to loop over these operations. We'll remove them from the vec
        // entirely to avoid borrow checker errors.
        let operations = std::mem::take(&mut self.operations);

        for (op, expected_outcome) in operations {
            let outcome: Result<(), anyhow::Error> = match op {
                SetFakeKeyId => {
                    // Authenticate
                    let lock_keeper_client = LockKeeperClient::authenticated_client(
                        &self.account_name,
                        &self.password,
                        &self.config,
                    )
                    .await?;
                    // Create fake KeyId and set to GENERATED_ID
                    let mut rng = StdRng::from_entropy();
                    let key_id = KeyId::generate(&mut rng, lock_keeper_client.user_id())?;
                    self.state.set(KEY_ID, key_id)?;

                    Ok(())
                }
                Register => self.register().await,
                Authenticate(ref pwd) => self.authenticate(pwd).await,
                Export => self.export().await,
                ExportSigningKey => self.export_signing_key().await,
                Generate => self.generate().await,
                ImportSigningKey => self.import_signing_key().await,
                Retrieve => self.retrieve().await,
                RemoteGenerate => self.remote_generate().await,
                RemoteSignBytes => self.remote_sign().await,
            };

            // Check whether the process errors matched the expectation.
            match outcome {
                Ok(_) => match &expected_outcome.expected_error {
                    Some(_) => {
                        anyhow::bail!("Unexpected success")
                    }
                    None => {
                        self.check_audit_events(&self.config, EventStatus::Successful, &op)
                            .await
                    }
                }?,
                Err(e) => {
                    self.check_audit_events(&self.config, EventStatus::Failed, &op)
                        .await?;
                    match &expected_outcome.expected_error {
                        Some(expected) => {
                            let expected_string = expected.to_string();
                            let error_string = e.to_string();
                            if expected_string != error_string {
                                anyhow::bail!("Incorrect error. expected {expected_string}; got {error_string}")
                            }
                        }
                        None => anyhow::bail!("Unexpected error"),
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
            .ok_or_else(|| anyhow!("No last element found in audit event log".to_string(),))?;
        // Check that expected status and action match
        let actual_status = fourth_last.status();
        let actual_action = fourth_last.action();
        let result = if expected_status != actual_status {
            Err(anyhow!("Incorrect audit event status. expected: {expected_status:?}, got: {actual_status:?}"))
        } else if expected_action != actual_action {
            Err(anyhow!("Incorrect audit event action. expected: {expected_action:?}, got: {actual_action:?}"))
        } else {
            Ok(())
        };

        // Print full audit log on failure
        // TODO #317: Remove when issue is resolved
        if let Err(e) = result {
            let lock_keeper_client = LockKeeperClient::authenticated_client(
                &self.account_name,
                &self.password,
                &self.config,
            )
            .await?;

            let audit_event_log = lock_keeper_client
                .retrieve_audit_event_log(EventType::All, AuditEventOptions::default())
                .await?;

            dbg!(audit_event_log);
            anyhow::bail!(e);
        }

        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct TestState {
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
            .ok_or_else(|| anyhow!("Unable to get test state"))?;
        Ok(val)
    }

    /// Get value from state and attempt to deserialize as `T`.
    pub fn get_as<T>(&self, key: &str) -> Result<T, anyhow::Error>
    where
        T: serde::de::DeserializeOwned,
    {
        let json = self.get(key)?.clone();
        let result = serde_json::from_value(json)?;
        Ok(result)
    }

    pub fn set<T, V>(&mut self, key: T, value: V) -> Result<(), anyhow::Error>
    where
        T: Into<String>,
        V: Serialize,
    {
        let value_json = serde_json::to_value(value)?;
        let prev_state = self.state.insert(key.into(), value_json);
        if prev_state.is_some() {
            anyhow::bail!("Test state was overwritten");
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Outcome {
    expected_error: Option<LockKeeperClientError>,
}

#[derive(Debug)]
pub struct TestResult {
    pub name: String,
    pub error: Option<String>,
}
