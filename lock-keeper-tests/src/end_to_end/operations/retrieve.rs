use lock_keeper::{crypto::KeyId, types::operations::retrieve::RetrieveContext};
use lock_keeper_client::LockKeeperClient;

use crate::end_to_end::{Test, KEY_ID, KEY_MATERIAL};

impl Test {
    pub async fn retrieve(&self) -> anyhow::Result<()> {
        // Authenticate
        let lock_keeper_client = LockKeeperClient::authenticated_client(
            &self.account_name,
            &self.password,
            &self.config,
        )
        .await?;
        // Get KeyId from state and run retrieve
        let key_id_json = self.state.get(KEY_ID)?;
        let key_id: KeyId = serde_json::from_value(key_id_json.clone())?;

        // Ensure result matches what was stored in generate
        match lock_keeper_client
            .retrieve(&key_id, RetrieveContext::LocalOnly)
            .await
        {
            Ok(res) => {
                let original_local_storage_json = self.state.get(KEY_MATERIAL)?.clone();
                match res {
                    None => anyhow::bail!("No key with key_id {:?}", key_id),
                    Some(local_storage) => {
                        let new_local_storage_json = serde_json::to_value(local_storage)?;
                        if original_local_storage_json != new_local_storage_json {
                            anyhow::bail!(
                                "Wrong key\nexpected: {};\n got: {}",
                                original_local_storage_json,
                                new_local_storage_json
                            );
                        }
                    }
                }
            }
            Err(e) => anyhow::bail!(e),
        }

        Ok(())
    }
}
