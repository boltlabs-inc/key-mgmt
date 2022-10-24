use lock_keeper_client::LockKeeperClient;
use rand::Rng;

use crate::end_to_end::{Test, KEY_ID, KEY_MATERIAL};

impl Test {
    pub async fn import_signing_key(&mut self) -> anyhow::Result<()> {
        // Authenticate and run generate
        let lock_keeper_client = LockKeeperClient::authenticated_client(
            &self.account_name,
            &self.password,
            &self.config,
        )
        .await?;
        let random_bytes = rand::thread_rng().gen::<[u8; 32]>().to_vec();
        let key_id = lock_keeper_client
            .import_signing_key(random_bytes.clone())
            .await?;
        // Store generated key ID to state
        self.state.set(KEY_ID, key_id)?;
        self.state.set(KEY_MATERIAL, random_bytes)?;

        Ok(())
    }
}
