use colored::Colorize;
use lock_keeper::{
    config::client::Config,
    types::{audit_event::EventStatus, operations::ClientAction},
};
use lock_keeper_client::LockKeeperClientError;

use crate::{
    end_to_end::{
        operations::{
            check_audit_events, compare_errors, export, export_signing_key, generate,
            generate_fake_key_id, import_signing_key,
        },
        test_cases::init_test_state,
    },
    run_parallel,
    utils::TestResult,
    Config as TestConfig,
};

pub async fn run_tests(config: TestConfig) -> anyhow::Result<Vec<TestResult>> {
    println!("{}", "Running export tests".cyan());

    let result = run_parallel!(
        config.clone(),
        export_works(config.client_config.clone()),
        cannot_export_fake_key(config.client_config.clone()),
        cannot_export_signing_key_as_secret(config.client_config.clone()),
        export_signing_key_works(config.client_config.clone()),
        cannot_export_fake_signing_key(config.client_config.clone()),
        cannot_export_secret_as_signing_key(config.client_config.clone())
    )?;

    Ok(result)
}

async fn export_works(config: Config) -> anyhow::Result<()> {
    let state = init_test_state(config).await?;

    let (key_id, local_storage) = generate(&state).await?;
    let bytes_res = export(&state, &key_id).await;
    assert!(bytes_res.is_ok());

    let bytes_new = bytes_res?;
    let bytes_original: Vec<u8> = local_storage.material.into();
    assert_eq!(bytes_new, bytes_original);
    check_audit_events(&state, EventStatus::Successful, ClientAction::Export).await?;

    Ok(())
}

async fn cannot_export_fake_key(config: Config) -> anyhow::Result<()> {
    let state = init_test_state(config).await?;

    let fake_key_id = generate_fake_key_id(&state).await?;
    let bytes_res = export(&state, &fake_key_id).await;
    compare_errors(bytes_res, LockKeeperClientError::InvalidAccount);
    check_audit_events(&state, EventStatus::Failed, ClientAction::Export).await?;

    Ok(())
}

async fn cannot_export_signing_key_as_secret(config: Config) -> anyhow::Result<()> {
    let state = init_test_state(config).await?;

    let (key_id, _) = import_signing_key(&state).await?;
    let export_res = export(&state, &key_id).await;
    compare_errors(export_res, LockKeeperClientError::InvalidAccount);
    check_audit_events(&state, EventStatus::Failed, ClientAction::Export).await?;

    Ok(())
}

async fn export_signing_key_works(config: Config) -> anyhow::Result<()> {
    let state = init_test_state(config).await?;

    let (key_id, bytes_original) = import_signing_key(&state).await?;
    let export_res = export_signing_key(&state, &key_id).await;
    assert!(export_res.is_ok());

    let export = export_res?;
    assert_eq!(export.key_material, bytes_original);
    check_audit_events(
        &state,
        EventStatus::Successful,
        ClientAction::ExportSigningKey,
    )
    .await?;

    Ok(())
}

async fn cannot_export_fake_signing_key(config: Config) -> anyhow::Result<()> {
    let state = init_test_state(config).await?;

    let fake_key_id = generate_fake_key_id(&state).await?;
    let export_res = export_signing_key(&state, &fake_key_id).await;
    compare_errors(export_res, LockKeeperClientError::InvalidAccount);
    check_audit_events(&state, EventStatus::Failed, ClientAction::ExportSigningKey).await?;

    Ok(())
}

async fn cannot_export_secret_as_signing_key(config: Config) -> anyhow::Result<()> {
    let state = init_test_state(config).await?;

    let (key_id, _) = generate(&state).await?;
    let export_res = export_signing_key(&state, &key_id).await;
    compare_errors(export_res, LockKeeperClientError::InvalidAccount);
    check_audit_events(&state, EventStatus::Failed, ClientAction::ExportSigningKey).await?;

    Ok(())
}
