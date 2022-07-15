pub(crate) mod common;

use common::{get_logs, LogType, Party};
use dams_local_client::command::Command;
use std::fs::OpenOptions;
use structopt::StructOpt;
use thiserror::Error;

/// Form a client CLI request. These cannot be constructed directly because the
/// CLI types are non-exhaustive.
macro_rules! client_cli {
    ($cli:ident, $args:expr) => {
        match ::dams_local_client::cli::Client::from_iter(
            ::std::iter::once("local-client-cli").chain($args),
        ) {
            ::dams_local_client::cli::Client::$cli(result) => result,
            _ => panic!("Failed to parse client CLI"),
        }
    };
}

#[tokio::test]
pub async fn integration_tests() {
    let server_future = common::setup().await;
    let client_config = dams::config::client::Config::load(common::CLIENT_CONFIG)
        .await
        .expect("Failed to load client config");

    // Run every test, printing out details if it fails
    let tests = tests();
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
fn tests() -> Vec<Test> {
    vec![
        Test {
            name: "Create a secret on the server".to_string(),
            operations: vec![(Operation::Create, Outcome { error: None })],
        },
        Test {
            name: "Retrieve a secret from the server".to_string(),
            operations: vec![(Operation::Retrieve, Outcome { error: None })],
        },
    ]
}

#[derive(Debug)]
struct Test {
    pub name: String,
    pub operations: Vec<(Operation, Outcome)>,
}

impl Test {
    async fn execute(
        &self,
        client_config: &dams::config::client::Config,
    ) -> Result<(), anyhow::Error> {
        for (op, expected_outcome) in &self.operations {
            let outcome = match op {
                Operation::Create => {
                    let est = client_cli!(Create, vec!["create", "keymgmt://localhost"]);
                    est.run(client_config.clone()).await.map(|_| ())
                }
                Operation::Retrieve => {
                    let est = client_cli!(Retrieve, vec!["retrieve", "keymgmt://localhost"]);
                    est.run(client_config.clone()).await.map(|_| ())
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
                (Some(Party::Server), Err(_), false) => Ok(()),

                // In any other case, something went wrong. Provide lots of details to diagnose
                _ => Err(TestError::InvalidErrorBehavior {
                    op: *op,
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
    "The error behavior did not satisfy expected behavior {op:?}. Got
    SERVER OUTPUT:
    {server_errors}
    OPERATION OUTPUT:
    {op_error:?}"
    )]
    InvalidErrorBehavior {
        op: Operation,
        server_errors: String,
        op_error: Result<(), anyhow::Error>,
    },
}

/// Set of operations that can be executed by the test harness
#[allow(unused)]
#[derive(Debug, Clone, Copy)]
enum Operation {
    Create,
    Retrieve,
}

#[derive(Debug)]
struct Outcome {
    /// Which process, if any, had an error? Assumes that exactly one party will
    /// error.
    error: Option<Party>,
}
