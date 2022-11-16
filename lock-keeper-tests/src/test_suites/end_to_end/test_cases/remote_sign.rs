use colored::Colorize;
use lock_keeper::{
    crypto::{Signable, SignableBytes},
    types::{audit_event::EventStatus, operations::ClientAction},
};
use lock_keeper_client::{api::RemoteGenerateResult, Config};
use rand::{rngs::StdRng, SeedableRng};

use crate::{
    error::Result,
    run_parallel,
    test_suites::end_to_end::{
        operations::{check_audit_events, remote_generate, remote_sign_bytes},
        test_cases::init_test_state,
    },
    utils::{self, TestResult, RNG_SEED},
    Config as TestConfig,
};

pub async fn run_tests(config: TestConfig) -> Result<Vec<TestResult>> {
    println!("{}", "Running remote sign tests".cyan());

    let result = run_parallel!(
        config.clone(),
        remote_sign_works(config.client_config.clone()),
    )?;

    Ok(result)
}

async fn remote_sign_works(config: Config) -> Result<()> {
    let state = init_test_state(config).await?;

    let RemoteGenerateResult { key_id, public_key } = remote_generate(&state).await?;

    let mut rng = StdRng::from_seed(*RNG_SEED);

    for _ in 0..10 {
        let data = SignableBytes(utils::random_bytes(&mut rng, 100));
        let signature = remote_sign_bytes(&state, &key_id, data.clone()).await?;
        // Verify that the data was signed with the generated key
        assert!(
            data.verify(&public_key, &signature).is_ok(),
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
