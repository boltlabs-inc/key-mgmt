use lock_keeper_client::LockKeeperClient;

use crate::end_to_end::{Test, KEY_ID, KEY_MATERIAL};

impl Test {
    pub async fn generate(&mut self) -> anyhow::Result<()> {
        // Authenticate and run generate
        let lock_keeper_client = LockKeeperClient::authenticated_client(
            &self.account_name,
            &self.password,
            &self.config,
        )
        .await?;
        let (key_id, local_storage) = lock_keeper_client.generate_and_store().await?;
        // Store generated key ID and local storage object to state
        self.state.set(KEY_ID, key_id)?;
        self.state.set(KEY_MATERIAL, local_storage)?;

        Ok(())
    }
}
