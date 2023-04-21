use colored::Colorize;
use lock_keeper::{
    crypto::{Signable, SignableBytes},
    types::{audit_event::EventStatus, operations::ClientAction},
};
use lock_keeper_client::{api::RemoteGenerateResult, Config, LockKeeperClientError};
use rand::{rngs::StdRng, SeedableRng};
use uuid::Uuid;

use crate::{
    config::TestFilters,
    error::Result,
    run_parallel,
    test_suites::end_to_end::{
        operations::{authenticate, check_audit_events},
        test_cases::init_test_state,
    },
    utils::{self, TestResult, RNG_SEED},
};

pub async fn run_tests(config: &Config, filters: &TestFilters) -> Result<Vec<TestResult>> {
    println!("{}", "Running remote sign tests".cyan());

    let result = run_parallel!(
        filters,
        remote_sign_works(config.clone()),
        cannot_remote_sign_after_logout(config.clone()),
    )?;

    Ok(result)
}

async fn remote_sign_works(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    let RemoteGenerateResult { key_id, public_key } = client.remote_generate().await.result?;

    let mut rng = StdRng::from_seed(*RNG_SEED);
    let mut request_id = Uuid::nil();

    for _ in 0..10 {
        let data = SignableBytes(utils::random_bytes(&mut rng, 100));
        let signature_response = client.remote_sign_bytes(key_id.clone(), data.clone()).await;
        // Verify that the data was signed with the generated key
        let signature = signature_response.result?;
        request_id = signature_response.metadata.unwrap().request_id;
        assert!(
            data.verify(&public_key, &signature).is_ok(),
            "original bytes: {data:?}"
        );
    }

    check_audit_events(
        &state,
        EventStatus::Successful,
        ClientAction::RemoteSignBytes,
        request_id,
        Some(key_id),
    )
    .await?;

    Ok(())
}

async fn cannot_remote_sign_after_logout(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    // Remote generate before waiting out the timeout
    let res = client.remote_generate().await.result?;
    client.logout().await.result?;

    let mut rng = StdRng::from_seed(*RNG_SEED);
    let data = SignableBytes(utils::random_bytes(&mut rng, 100));
    let res = client.remote_sign_bytes(res.key_id, data).await;
    assert!(matches!(
        res.result,
        Err(LockKeeperClientError::InvalidSession)
    ));

    Ok(())
}
