//! End-to-end tests

pub mod operations;
pub mod test_cases;
use crate::{
    config::{Environments, TestFilters},
    error::Result,
    utils::{report_test_results, TestResult},
};
use colored::Colorize;
use lock_keeper_client::Config;
use test_cases::{
    authenticate, check_session, delete_key, export, generate, import, metrics, register,
    remote_generate, remote_sign, retrieve,
};

pub async fn run_tests(environments: &Environments) -> Result<Vec<TestResult>> {
    let mut results = Vec::new();

    for (name, config) in &environments.configs {
        let env_results = run_tests_with_config(name, config, &environments.filters).await?;
        results.extend(env_results);
    }

    Ok(results)
}

pub async fn run_tests_with_config(
    environment_name: &str,
    config: &Config,
    filters: &TestFilters,
) -> Result<Vec<TestResult>> {
    println!(
        "Running end-to-end tests with environment: {}",
        environment_name.magenta()
    );

    let register_results = register::run_tests(config, filters).await?;
    let authenticate_results = authenticate::run_tests(config, filters).await?;
    let check_session_results = check_session::run_tests(config, filters).await?;
    let delete_key_tests = delete_key::run_tests(config, filters).await?;
    let generate_results = generate::run_tests(config, filters).await?;
    let retrieve_results = retrieve::run_tests(config, filters).await?;
    let export_results = export::run_tests(config, filters).await?;
    let import_results = import::run_tests(config, filters).await?;
    let remote_generate_results = remote_generate::run_tests(config, filters).await?;
    let remote_sign_results = remote_sign::run_tests(config, filters).await?;
    let metrics_results = metrics::run_tests(config, filters).await?;

    println!("Results for environment: {}", environment_name.magenta());
    // Report results after all tests finish so results show up together
    println!("register tests: {}", report_test_results(&register_results));
    println!(
        "authenticate tests {}",
        report_test_results(&authenticate_results)
    );
    println!(
        "check session tests: {}",
        report_test_results(&check_session_results)
    );
    println!(
        "delete key tests: {}",
        report_test_results(&delete_key_tests)
    );
    println!("generate tests: {}", report_test_results(&generate_results));
    println!("retrieve tests: {}", report_test_results(&retrieve_results));
    println!("export tests: {}", report_test_results(&export_results));
    println!("import tests: {}", report_test_results(&import_results));
    println!(
        "remote generate tests: {}",
        report_test_results(&remote_generate_results)
    );
    println!(
        "remote sign tests: {}",
        report_test_results(&remote_sign_results)
    );
    println!("metrics tests: {}", report_test_results(&metrics_results));

    println!();

    let results = register_results
        .into_iter()
        .chain(authenticate_results)
        .chain(check_session_results)
        .chain(delete_key_tests)
        .chain(generate_results)
        .chain(retrieve_results)
        .chain(export_results)
        .chain(import_results)
        .chain(remote_generate_results)
        .chain(remote_sign_results)
        .chain(metrics_results)
        .collect();

    Ok(results)
}
