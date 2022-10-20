use lock_keeper_client::LockKeeperClient;

use crate::end_to_end::Test;

impl Test {
    pub async fn register(&self) -> anyhow::Result<()> {
        LockKeeperClient::register(&self.account_name, &self.password, &self.config).await?;

        Ok(())
    }
}
