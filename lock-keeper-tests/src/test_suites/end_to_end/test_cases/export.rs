use colored::Colorize;
use lock_keeper::{
    crypto::Secret,
    types::{audit_event::EventStatus, operations::ClientAction},
};
use lock_keeper_client::{api::GenerateResult, Config};
use tonic::Status;

use crate::{
    error::Result,
    run_parallel,
    test_suites::end_to_end::{
        operations::{
            authenticate, check_audit_events, compare_errors, compare_status_errors,
            generate_fake_key_id, import_signing_key,
        },
        test_cases::init_test_state,
    },
    utils::TestResult,
    Config as TestConfig,
};

pub async fn run_tests(config: TestConfig) -> Result<Vec<TestResult>> {
    println!("{}", "Running export tests".cyan());

    let result = run_parallel!(
        config.clone(),
        export_works(config.client_config.clone()),
        cannot_export_fake_key(config.client_config.clone()),
        cannot_export_signing_key_as_secret(config.client_config.clone()),
        cannot_export_after_logout(config.client_config.clone()),
        export_signing_key_works(config.client_config.clone()),
        cannot_export_fake_signing_key(config.client_config.clone()),
        cannot_export_secret_as_signing_key(config.client_config.clone()),
        cannot_export_signing_key_after_logout(config.client_config.clone()),
    )?;

    Ok(result)
}

async fn export_works(config: Config) -> Result<()> {
    let state = init_test_state(config).await?;
    let client = authenticate(&state).await?;

    let GenerateResult {
        key_id,
        local_storage,
    } = client.generate_and_store().await?.into_inner();
    let bytes_res = client.export_key(&key_id).await;
    assert!(bytes_res.is_ok());

    // Turn the export back into a Secret and compare directly
    let exported_secret: Secret = bytes_res?.into_inner().try_into()?;
    assert_eq!(exported_secret, local_storage.material);
    check_audit_events(&state, EventStatus::Successful, ClientAction::Export).await?;

    Ok(())
}

async fn cannot_export_fake_key(config: Config) -> Result<()> {
    let state = init_test_state(config).await?;
    let client = authenticate(&state).await?;

    let fake_key_id = generate_fake_key_id(&client).await?;
    let bytes_res = client.export_key(&fake_key_id).await;
    compare_errors(bytes_res, Status::internal("Internal server error"));
    check_audit_events(&state, EventStatus::Failed, ClientAction::Export).await?;

    Ok(())
}

async fn cannot_export_signing_key_as_secret(config: Config) -> Result<()> {
    let state = init_test_state(config).await?;
    let client = authenticate(&state).await?;

    let (key_id, _) = import_signing_key(&client).await?.into_inner();
    let export_res = client.export_key(&key_id).await;
    compare_errors(export_res, Status::internal("Internal server error"));
    check_audit_events(&state, EventStatus::Failed, ClientAction::Export).await?;

    Ok(())
}

async fn cannot_export_after_logout(config: Config) -> Result<()> {
    let state = init_test_state(config).await?;
    let client = authenticate(&state).await?;

    let GenerateResult {
        key_id,
        local_storage: _,
    } = client.generate_and_store().await?.into_inner();
    client.logout().await?;

    let res = client.export_key(&key_id).await;
    compare_status_errors(res, Status::unauthenticated("No session key for this user"))?;

    Ok(())
}

async fn export_signing_key_works(config: Config) -> Result<()> {
    let state = init_test_state(config).await?;
    let client = authenticate(&state).await?;

    let (key_id, bytes_original) = import_signing_key(&client).await?.into_inner();
    let export_res = client.export_signing_key(&key_id).await;
    assert!(export_res.is_ok());

    let export = export_res?.into_inner();
    assert_eq!(export.key_material, bytes_original);
    check_audit_events(
        &state,
        EventStatus::Successful,
        ClientAction::ExportSigningKey,
    )
    .await?;

    Ok(())
}

async fn cannot_export_fake_signing_key(config: Config) -> Result<()> {
    let state = init_test_state(config).await?;
    let client = authenticate(&state).await?;

    let fake_key_id = generate_fake_key_id(&client).await?;
    let export_res = client.export_signing_key(&fake_key_id).await;
    compare_errors(export_res, Status::internal("Internal server error"));
    check_audit_events(&state, EventStatus::Failed, ClientAction::ExportSigningKey).await?;

    Ok(())
}

async fn cannot_export_secret_as_signing_key(config: Config) -> Result<()> {
    let state = init_test_state(config).await?;
    let client = authenticate(&state).await?;

    let GenerateResult {
        key_id,
        local_storage: _,
    } = client.generate_and_store().await?.into_inner();
    let export_res = client.export_signing_key(&key_id).await;
    compare_errors(export_res, Status::internal("Internal server error"));
    check_audit_events(&state, EventStatus::Failed, ClientAction::ExportSigningKey).await?;

    Ok(())
}

async fn cannot_export_signing_key_after_logout(config: Config) -> Result<()> {
    let state = init_test_state(config).await?;
    let client = authenticate(&state).await?;

    let (key_id, _) = import_signing_key(&client).await?.into_inner();
    client.logout().await?;

    let res = client.export_signing_key(&key_id).await;
    compare_status_errors(res, Status::unauthenticated("No session key for this user"))?;

    Ok(())
}
