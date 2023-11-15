use colored::Colorize;
use lock_keeper_client::Config;

use crate::{
    config::TestFilters, error::Result, run_parallel,
    test_suites::end_to_end::operations::authenticate, utils::TestResult,
};

use super::init_test_state;

pub async fn run_tests(config: &Config, filters: &TestFilters) -> Result<Vec<TestResult>> {
    println!("{}", "Running metrics tests".cyan());

    let result = run_parallel!(filters, metrics_works(config.clone()),)?;

    Ok(result)
}

async fn metrics_works(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    let result = client.metrics().await;
    assert!(result.is_ok());

    Ok(())
}
