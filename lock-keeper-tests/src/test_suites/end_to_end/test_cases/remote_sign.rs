use colored::Colorize;
use lock_keeper::{
    crypto::{Signable, SignableBytes},
    types::{audit_event::EventStatus, operations::ClientAction},
};
use lock_keeper_client::{api::RemoteGenerateResult, Config};
use rand::{rngs::StdRng, SeedableRng};
use tonic::Status;

use crate::{
    config::TestFilters,
    error::Result,
    run_parallel,
    test_suites::end_to_end::{
        operations::{authenticate, check_audit_events, compare_status_errors},
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
    let client = authenticate(&state).await?;

    let RemoteGenerateResult { key_id, public_key } = client.remote_generate().await?.into_inner();

    let mut rng = StdRng::from_seed(*RNG_SEED);

    for _ in 0..10 {
        let data = SignableBytes(utils::random_bytes(&mut rng, 100));
        let signature = client
            .remote_sign_bytes(key_id.clone(), data.clone())
            .await?;
        // Verify that the data was signed with the generated key
        assert!(
            data.verify(&public_key, &signature.into_inner()).is_ok(),
            "original bytes: {data:?}"
        );
    }

    check_audit_events(
        &state,
        EventStatus::Successful,
        ClientAction::RemoteSignBytes,
    )
    .await?;

    Ok(())
}

async fn cannot_remote_sign_after_logout(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await?;

    // Remote generate before waiting out the timeout
    let res = client.remote_generate().await?.into_inner();
    client.logout().await?;

    let mut rng = StdRng::from_seed(*RNG_SEED);
    let data = SignableBytes(utils::random_bytes(&mut rng, 100));
    let res = client.remote_sign_bytes(res.key_id, data).await;
    compare_status_errors(res, Status::unauthenticated("No session key for this user"))?;

    Ok(())
}
