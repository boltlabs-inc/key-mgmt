use lock_keeper_client::LockKeeperClient;

use crate::end_to_end::{Test, KEY_ID};

impl Test {
    pub async fn remote_generate(&mut self) -> anyhow::Result<()> {
        // Authenticate and run remote generate
        let lock_keeper_client = LockKeeperClient::authenticated_client(
            &self.account_name,
            &self.password,
            &self.config,
        )
        .await?;
        let key_id = lock_keeper_client.remote_generate().await?;
        // Store generated key ID
        self.state.set(KEY_ID, key_id)?;

        Ok(())
    }
}
