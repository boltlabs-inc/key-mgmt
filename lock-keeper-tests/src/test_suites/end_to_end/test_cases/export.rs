use colored::Colorize;
use lock_keeper::{
    crypto::Secret,
    types::{audit_event::EventStatus, operations::ClientAction},
};
use lock_keeper_client::{api::GenerateResult, Config};
use tonic::Status;

use crate::{
    config::TestFilters,
    error::Result,
    run_parallel,
    test_suites::end_to_end::{
        operations::{
            authenticate, check_audit_events, compare_errors, compare_status_errors,
            generate_fake_key_id, import_signing_key,
        },
        test_cases::{init_test_state, NO_ENTRY_FOUND, NO_SESSION, WRONG_KEY_DATA},
    },
    utils::TestResult,
};

pub async fn run_tests(config: &Config, filters: &TestFilters) -> Result<Vec<TestResult>> {
    println!("{}", "Running export tests".cyan());

    let result = run_parallel!(
        filters,
        export_works(config.clone()),
        cannot_export_fake_key(config.clone()),
        cannot_export_signing_key_as_secret(config.clone()),
        cannot_export_after_logout(config.clone()),
        export_signing_key_works(config.clone()),
        cannot_export_fake_signing_key(config.clone()),
        cannot_export_secret_as_signing_key(config.clone()),
        cannot_export_signing_key_after_logout(config.clone()),
    )?;

    Ok(result)
}

async fn export_works(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    let GenerateResult {
        key_id,
        local_storage,
    } = client.generate_secret().await.result?;
    let bytes_res = client.export_secret(&key_id).await;

    // Turn the export back into a Secret and compare directly
    let exported_secret: Secret = bytes_res.result?.try_into()?;
    assert_eq!(exported_secret, local_storage.material);
    let request_id = bytes_res.metadata.unwrap().request_id;
    check_audit_events(
        &state,
        EventStatus::Successful,
        ClientAction::ExportSecret,
        request_id,
        Some(key_id),
    )
    .await?;

    Ok(())
}

async fn cannot_export_fake_key(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    let fake_key_id = generate_fake_key_id(&client).await?;
    let bytes_res = client.export_secret(&fake_key_id).await;
    let request_id = bytes_res.metadata.clone().unwrap().request_id;
    compare_errors(bytes_res, Status::internal(NO_ENTRY_FOUND));
    check_audit_events(
        &state,
        EventStatus::Failed,
        ClientAction::ExportSecret,
        request_id,
        Some(fake_key_id),
    )
    .await?;

    Ok(())
}

async fn cannot_export_signing_key_as_secret(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    let (key_id, _) = import_signing_key(&client).await.result?;
    let export_res = client.export_secret(&key_id).await;
    let request_id = export_res.metadata.clone().unwrap().request_id;
    compare_errors(export_res, Status::internal(WRONG_KEY_DATA));
    check_audit_events(
        &state,
        EventStatus::Failed,
        ClientAction::ExportSecret,
        request_id,
        Some(key_id),
    )
    .await?;

    Ok(())
}

async fn cannot_export_after_logout(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    let GenerateResult {
        key_id,
        local_storage: _,
    } = client.generate_secret().await.result?;
    client.logout().await.result?;

    let res = client.export_secret(&key_id).await;
    compare_status_errors(res, Status::unauthenticated(NO_SESSION))?;

    Ok(())
}

async fn export_signing_key_works(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    let (key_id, bytes_original) = import_signing_key(&client).await.result?;
    let export_res = client.export_signing_key(&key_id).await;
    assert!(
        export_res.result.is_ok(),
        "Export failed: {}",
        export_res.result.unwrap_err()
    );

    let export = export_res.result?;
    let request_id = export_res.metadata.unwrap().request_id;
    assert_eq!(export.key_material, bytes_original);
    check_audit_events(
        &state,
        EventStatus::Successful,
        ClientAction::ExportSigningKey,
        request_id,
        Some(key_id),
    )
    .await?;

    Ok(())
}

async fn cannot_export_fake_signing_key(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    let fake_key_id = generate_fake_key_id(&client).await?;
    let export_res = client.export_signing_key(&fake_key_id).await;
    let request_id = export_res.metadata.clone().unwrap().request_id;
    compare_errors(export_res, Status::internal(NO_ENTRY_FOUND));
    check_audit_events(
        &state,
        EventStatus::Failed,
        ClientAction::ExportSigningKey,
        request_id,
        Some(fake_key_id),
    )
    .await?;

    Ok(())
}

async fn cannot_export_secret_as_signing_key(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    let GenerateResult {
        key_id,
        local_storage: _,
    } = client.generate_secret().await.result?;
    let export_res = client.export_signing_key(&key_id).await;
    let request_id = export_res.metadata.clone().unwrap().request_id;
    compare_errors(export_res, Status::internal(WRONG_KEY_DATA));
    check_audit_events(
        &state,
        EventStatus::Failed,
        ClientAction::ExportSigningKey,
        request_id,
        Some(key_id),
    )
    .await?;

    Ok(())
}

async fn cannot_export_signing_key_after_logout(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    let (key_id, _) = import_signing_key(&client).await.result?;
    client.logout().await.result?;

    let res = client.export_signing_key(&key_id).await;
    compare_status_errors(res, Status::unauthenticated(NO_SESSION))?;

    Ok(())
}
