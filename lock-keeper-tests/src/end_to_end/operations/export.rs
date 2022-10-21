use lock_keeper::crypto::KeyId;
use lock_keeper_client::{api::LocalStorage, LockKeeperClient};

use crate::end_to_end::{Test, KEY_ID, KEY_MATERIAL};

impl Test {
    pub async fn export(&self) -> anyhow::Result<()> {
        // Authenticate
        let lock_keeper_client = LockKeeperClient::authenticated_client(
            &self.account_name,
            &self.password,
            &self.config,
        )
        .await?;

        // Get KeyId from state and run export
        let key_id_json = self.state.get(KEY_ID)?;
        let key_id: KeyId = serde_json::from_value(key_id_json.clone())?;
        match lock_keeper_client.export_key(&key_id).await {
            Ok(res) => {
                // Compare generated key and exported key material
                let original_local_storage_json = self.state.get(KEY_MATERIAL)?.clone();
                let original_local_storage_bytes: Vec<u8> =
                    serde_json::from_value::<LocalStorage>(original_local_storage_json.clone())?
                        .secret
                        .into();
                let res_json = serde_json::to_value(res.clone())?;
                if original_local_storage_bytes != res {
                    anyhow::bail!(
                        "expected: {}; got: {}",
                        original_local_storage_json,
                        res_json
                    );
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(anyhow::Error::from(e)),
        }
    }

    pub async fn export_signing_key(&self) -> anyhow::Result<()> {
        // Authenticate
        let lock_keeper_client = LockKeeperClient::authenticated_client(
            &self.account_name,
            &self.password,
            &self.config,
        )
        .await?;

        // Get KeyId from state and run export
        let key_id_json = self.state.get(KEY_ID)?;
        let key_id: KeyId = serde_json::from_value(key_id_json.clone())?;
        match lock_keeper_client.export_signing_key(&key_id).await {
            Ok(res) => {
                // Compare generated key and exported key material
                let original_bytes_json = self.state.get(KEY_MATERIAL)?.clone();
                let original_bytes: Vec<u8> = serde_json::from_value(original_bytes_json)?;
                if original_bytes != res.key_material {
                    anyhow::bail!(
                        "expected: {:?}; got: {:?}",
                        original_bytes,
                        res.key_material
                    );
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(anyhow::Error::from(e)),
        }
    }
}
