use crate::{
    config::Config,
    error::Result,
    utils::{report_test_results, TestResult},
};

pub mod client_auth;
pub mod config_files;
pub mod database;
pub mod end_to_end;

pub async fn run_all(config: &Config) -> Result<Vec<TestResult>> {
    let config_file_results = config_files::run_tests(config).await?;
    let database_results = database::run_tests(config).await?;
    let end_to_end_results = end_to_end::run_tests(config).await?;
    let client_auth_results = client_auth::run_tests(config).await?;

    println!(
        "config file tests: {}",
        report_test_results(&config_file_results)
    );
    println!("database tests: {}", report_test_results(&database_results));
    println!(
        "end to end tests: {}",
        report_test_results(&end_to_end_results)
    );
    println!(
        "client auth tests: {}",
        report_test_results(&client_auth_results)
    );

    Ok([
        config_file_results,
        database_results,
        end_to_end_results,
        client_auth_results,
    ]
    .concat())
}
