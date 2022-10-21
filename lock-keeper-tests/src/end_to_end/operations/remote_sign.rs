use lock_keeper::crypto::{KeyId, Signable, SignableBytes, SigningPublicKey};
use lock_keeper_client::LockKeeperClient;
use rand::{rngs::StdRng, SeedableRng};

use crate::{
    end_to_end::{Test, KEY_ID, REMOTE_GENERATED_PUBLIC_KEY},
    utils::{self, RNG_SEED},
};

impl Test {
    pub async fn remote_sign(&mut self) -> anyhow::Result<()> {
        let key_id = self.state.get_as::<KeyId>(KEY_ID)?;
        let public_key = self
            .state
            .get_as::<SigningPublicKey>(REMOTE_GENERATED_PUBLIC_KEY)?;

        let mut rng = StdRng::from_seed(*RNG_SEED);

        for _ in 0..10 {
            // Authenticate each time to make the audit event checks happy
            let lock_keeper_client = LockKeeperClient::authenticated_client(
                &self.account_name,
                &self.password,
                &self.config,
            )
            .await?;

            let data = utils::random_bytes(&mut rng, 100);
            remote_sign_single_test(
                &lock_keeper_client,
                &key_id,
                &public_key,
                SignableBytes(data),
            )
            .await?;
        }

        Ok(())
    }
}

async fn remote_sign_single_test(
    client: &LockKeeperClient,
    key_id: &KeyId,
    public_key: &SigningPublicKey,
    data: SignableBytes,
) -> anyhow::Result<()> {
    // Sign the data
    let signature = client
        .remote_sign_bytes(key_id.clone(), data.clone())
        .await?;

    // Verify that the data was signed with the generated key
    assert!(
        data.verify(public_key, &signature).is_ok(),
        "original bytes: {data:?}"
    );

    Ok(())
}
