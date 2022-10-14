//! Various testing utilities

use std::sync::{Arc, Mutex};

use colored::Colorize;
use lock_keeper::config::opaque::OpaqueCipherSuite;
use opaque_ke::{
    ClientRegistration, ClientRegistrationFinishParameters, ServerRegistration, ServerSetup,
};
use rand::{distributions::Alphanumeric, Rng};

/// Add random text to the end of a string
/// # Exmaple
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

/// Pass a list of async test functions with parameters included.
/// All test functions must return `anyhow::Result<()>`.
/// Tests will run in parallel and report the names of any failing test.
/// # Example
/// ```no_run
/// run_parallel(test_1(), test_2(&db))
/// ```
#[macro_export]
macro_rules! run_parallel {
    ($($task:expr),+,) => {
        run_parallel!($($task),+)
    };
    ($($task:expr),+) => {
        // Stick this in a scope so it can return a result
        {
            use std::sync::{Arc, Mutex};
            use $crate::utils::TestResult::{self, *};

            let result = Arc::new(Mutex::new(Passed));
            tokio::try_join!($($crate::utils::run_test_case(stringify!($task), tokio::spawn($task), result.clone())),+)?;

            let result = result.lock().unwrap().clone();
            Ok::<TestResult, anyhow::Error>(result)
        }
    };
}

/// Runs a test case and manually handles any panics triggered by `assert`
/// macros.
pub async fn run_test_case(
    name: &str,
    handle: tokio::task::JoinHandle<anyhow::Result<()>>,
    result: Arc<Mutex<TestResult>>,
) -> anyhow::Result<()> {
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

    // Store normal panic hook so we can set it back later
    let panic_hook = std::panic::take_hook();

    // Create an new panic hook to catch assert! checks
    std::panic::set_hook(Box::new(|_| {
        // Don't print panic details
    }));

    // Catch any panic and print test result
    match handle.catch_unwind().await {
        Ok(Ok(_)) => {
            test_result.push_str(&format!("{}", "ok\n".green()));
        }
        Ok(Err(err)) => {
            // Get panic message from error
            match err.try_into_panic() {
                Ok(panic) => {
                    {
                        let mut result = result.lock().unwrap();
                        *result = Failed;
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
                let mut result = result.lock().unwrap();
                *result = Failed;
            }
            test_result.push_str(&format!("failed: {:?}\n", err));
        }
    }

    println!("{test_result}");

    // Replace original panic hook
    std::panic::set_hook(panic_hook);

    Ok(())
}

#[derive(Clone, Debug)]
pub enum TestResult {
    Passed,
    Failed,
}

impl TestResult {
    pub fn report(&self, test_name: impl AsRef<str>) {
        let test_name = test_name.as_ref();
        match self {
            TestResult::Passed => println!("{test_name} {}", "PASSED".green()),
            TestResult::Failed => println!("{test_name} {}", "FAILED".red()),
        }
    }
}
