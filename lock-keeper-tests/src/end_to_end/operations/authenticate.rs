use lock_keeper_client::{client::Password, LockKeeperClient};

use crate::end_to_end::Test;

impl Test {
    pub async fn authenticate(&self, password: &Option<Password>) -> anyhow::Result<()> {
        let password = match password {
            Some(pwd) => pwd,
            None => &self.password,
        };
        let _ = LockKeeperClient::authenticated_client(&self.account_name, password, &self.config)
            .await?;

        Ok(())
    }
}
