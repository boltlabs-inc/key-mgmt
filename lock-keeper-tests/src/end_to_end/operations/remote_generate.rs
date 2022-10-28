use lock_keeper_client::LockKeeperClient;

use crate::end_to_end::{Test, KEY_ID, REMOTE_GENERATED_PUBLIC_KEY};

impl Test {
    pub async fn remote_generate(&mut self) -> anyhow::Result<()> {
        // Authenticate and run remote generate
        let lock_keeper_client = LockKeeperClient::authenticated_client(
            &self.account_name,
            &self.password,
            &self.config,
        )
        .await?;
        let key_info = lock_keeper_client.remote_generate().await?;

        // Store generated key ID
        self.state.set(KEY_ID, key_info.key_id)?;
        self.state
            .set(REMOTE_GENERATED_PUBLIC_KEY, key_info.public_key)?;

        Ok(())
    }
}
