//! End-to-end testing framework and test definitions

pub mod operations;
pub mod test_cases;
use crate::{config::Config, error::Result, utils::report_test_results};
use test_cases::{
    authenticate, export, generate, import, register, remote_generate, remote_sign, retrieve,
};

pub async fn run_tests(config: &Config) -> Result<()> {
    println!("Running end-to-end tests");

    let register_results = register::run_tests(config.clone()).await?;
    let authenticate_results = authenticate::run_tests(config.clone()).await?;
    let generate_results = generate::run_tests(config.clone()).await?;
    let retrieve_results = retrieve::run_tests(config.clone()).await?;
    let export_results = export::run_tests(config.clone()).await?;
    let import_results = import::run_tests(config.clone()).await?;
    let remote_generate_results = remote_generate::run_tests(config.clone()).await?;
    let remote_sign_results = remote_sign::run_tests(config.clone()).await?;

    // Report results after all tests finish so results show up together
    println!("register tests: {}", report_test_results(&register_results));
    println!(
        "authenticate tests {}",
        report_test_results(&authenticate_results)
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

    println!();

    Ok(())
}
