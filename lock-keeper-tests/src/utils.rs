//! Various testing utilities

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::{
    error::{LockKeeperTestError, Result},
    Config,
};
use colored::Colorize;
use futures::Future;
use lock_keeper::config::opaque::OpaqueCipherSuite;
use lock_keeper_client::{Config as ClientConfig, LockKeeperClient};
use opaque_ke::{
    ClientRegistration, ClientRegistrationFinishParameters, ServerRegistration, ServerSetup,
};
use rand::{distributions::Alphanumeric, Rng};

pub const RNG_SEED: &[u8; 32] = b"we love deterministic testing!!!";

/// Add random text to the end of a string
/// # Example
/// ```
/// let user = tagged("user");
/// println!("{user}");
/// // Prints something like "user-1h65k35"
/// ```
pub fn tagged(text: impl AsRef<str>) -> String {
    let text = text.as_ref();
    let tag: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(7)
        .map(char::from)
        .collect();

    format!("{text}-{tag}")
}

/// Locally simulates OPAQUE registration to get a valid
/// `ServerRegistration` for remaining tests.
pub fn server_registration() -> ServerRegistration<OpaqueCipherSuite> {
    let mut rng = rand::thread_rng();

    let server_setup = ServerSetup::<OpaqueCipherSuite>::new(&mut rng);
    let client_reg_start_result =
        ClientRegistration::<OpaqueCipherSuite>::start(&mut rng, b"password").unwrap();
    let server_reg_start_result = ServerRegistration::<OpaqueCipherSuite>::start(
        &server_setup,
        client_reg_start_result.message,
        b"email@email.com",
    )
    .unwrap();
    let client_reg_finish_result = client_reg_start_result
        .state
        .finish(
            &mut rng,
            b"password",
            server_reg_start_result.message,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    ServerRegistration::<OpaqueCipherSuite>::finish(client_reg_finish_result.message)
}

/// Generate a sequence of random bytes with the given length.
pub fn random_bytes(mut rng: impl Rng, len: usize) -> Vec<u8> {
    std::iter::repeat_with(|| rng.gen()).take(len).collect()
}

/// Pass a list of async test functions with parameters included.
/// All test functions must return [`Result<()>`].
/// Tests will run in parallel and report the names of any failing test.
/// # Example
/// ```no_run
/// run_parallel(test_1(), test_2(&db))
/// ```
#[macro_export]
macro_rules! run_parallel {
    ($config:expr, $($task:expr),+,) => {
        run_parallel!($config, $($task),+)
    };
    ($config:expr, $($task:expr),+) => {
        // Stick this in a scope so it can return a result
        {
            use std::sync::{Arc, Mutex};
            use $crate::{error::LockKeeperTestError, utils::TestResult};

            let results = Arc::new(Mutex::new(Vec::new()));
            tokio::try_join!($($crate::utils::run_test_case($config, stringify!($task), $task, results.clone())),+)?;

            let results = results.lock().unwrap().clone();

            Ok::<Vec<TestResult>, LockKeeperTestError>(results)
        }
    };
}

/// Runs a test case and manually handles any panics triggered by `assert`
/// macros.
pub async fn run_test_case(
    config: Config,
    name: &str,
    task: impl Future<Output = Result<()>> + Send + 'static,
    results: Arc<Mutex<Vec<TestResult>>>,
) -> Result<()> {
    use futures::FutureExt;
    use TestResult::*;

    // Create string for result so that we can print the whole thing at once
    let mut test_result = String::new();

    // Get name of test from function name
    let name = name
        .split('(')
        .next()
        .expect("Function has at least one character");
    test_result.push_str(&format!("\n{name}:\n"));

    if !config.filters.matches(name) {
        let mut results = results.lock().unwrap();
        results.push(Skipped);
        test_result.push_str(&format!("{}", "skipped\n".bright_blue()));
        println!("{test_result}");
        return Ok(());
    }

    let handle = tokio::spawn(task);

    // Store normal panic hook so we can set it back later
    let panic_hook = std::panic::take_hook();

    // Create an new panic hook to catch assert! checks
    std::panic::set_hook(Box::new(|_| {
        // Don't print panic details
    }));

    // Catch any panic and print test result
    match handle.catch_unwind().await {
        // task returned at all
        Ok(Ok(res)) => {
            match res {
                // task returned and it was Ok
                Ok(_) => {
                    {
                        let mut results = results.lock().unwrap();
                        results.push(Passed);
                    }
                    test_result.push_str(&format!("{}", "ok\n".green()));
                }
                // task returned but it was Err
                Err(e) => {
                    {
                        let mut results = results.lock().unwrap();
                        results.push(Failed);
                    }
                    test_result.push_str(&format!("{}: {}\n", "failed".red(), e));
                }
            }
        }
        Ok(Err(err)) => {
            // Get panic message from error
            match err.try_into_panic() {
                Ok(panic) => {
                    {
                        let mut results = results.lock().unwrap();
                        results.push(Failed);
                    }
                    test_result.push_str(&format!("{}", "Test panicked\n".red()));

                    // Try to convert message to `&str` or `String` and print
                    if let Some(message) = panic.downcast_ref::<&str>() {
                        test_result.push_str(&format!("{message}\n"));
                    }
                    if let Some(message) = panic.downcast_ref::<String>() {
                        test_result.push_str(&format!("{message}\n"));
                    }
                }
                Err(e) => {
                    test_result.push_str(&format!("{}: {}\n", "failed".red(), e));
                }
            }
        }
        Err(err) => {
            {
                let mut results = results.lock().unwrap();
                results.push(Failed);
            }
            test_result.push_str(&format!("failed: {:?}\n", err));
        }
    }

    println!("{test_result}");

    // Replace original panic hook
    std::panic::set_hook(panic_hook);

    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestResult {
    Passed,
    Failed,
    Skipped,
}

pub fn report_test_results(results: &[TestResult]) -> String {
    use TestResult::*;

    let any_failed = results.iter().any(|r| *r == Failed);
    if any_failed {
        return format!("{}", "FAILED".red());
    }

    let num_results = results.len();
    let num_skipped = results.iter().filter(|r| **r == Skipped).count();

    if num_skipped == num_results {
        format!("{}", "SKIPPED".bright_blue())
    } else if num_skipped > 0 {
        format!(
            "{} ({} {})",
            "PASSED".green(),
            num_skipped,
            "SKIPPED".bright_blue()
        )
    } else {
        format!("{}", "PASSED".green())
    }
}

pub async fn wait_for_server(config: &ClientConfig) -> Result<()> {
    const NUM_RETRIES: u32 = 10;
    const RETRY_DELAY: Duration = Duration::from_secs(10);

    for i in 0..NUM_RETRIES {
        println!("Attempting to connect to server...");
        match LockKeeperClient::health(config).await {
            Ok(_) => return Ok(()),
            Err(_) => {
                println!("Server connection failed. Retrying in {:?}", RETRY_DELAY);
                if i == 0 {
                    println!("Did you remember to run `cargo make start`?");
                }
                std::thread::sleep(RETRY_DELAY);
            }
        }
    }

    Err(LockKeeperTestError::WaitForServerTimedOut)
}
