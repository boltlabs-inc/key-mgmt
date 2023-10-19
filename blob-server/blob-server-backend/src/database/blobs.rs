pub mod types;

use crate::{BlobServerDatabase, BlobServerError};
use self::types::{BlobAccountDb, BlobSessionDb, BlobDb};

impl BlobServerDatabase {
    pub async fn create_blob_account(&self, username: &str, hashed_secret: &str) -> Result<(), BlobServerError> {
        sqlx::query!(
            r#"INSERT INTO blob_account (name, api_secret)
               VALUES ($1, $2)"#,
            username,
            hashed_secret,
        )
        .execute(&self.connection_pool)
        .await?;

        Ok(())
    }

    pub async fn read_blob_account(&self, username: &str) -> Result<BlobAccountDb, BlobServerError> {
        let account_db = sqlx::query_as!(
            BlobAccountDb,
            r#"SELECT * FROM blob_account
               WHERE name=$1"#,
            username,
        )
        .fetch_one(&self.connection_pool)
        .await?;

        Ok(account_db)
    }

    pub async fn update_blob_account(&self, username: &str, new_hashed_secret: &str) -> Result<(), BlobServerError> {
        sqlx::query!(
            r#"UPDATE blob_account
               SET api_secret=$1
               WHERE name=$2"#,
               new_hashed_secret,
               username,
        )
        .execute(&self.connection_pool)
        .await?;

        Ok(())
    }    

    pub async fn delete_blob_account(&self, username: &str) -> Result<(), BlobServerError> {
        sqlx::query!(
            r#"DELETE FROM blob_account
               WHERE name=$1"#,
               username,
        )
        .execute(&self.connection_pool)
        .await?;

        Ok(())
    }

    pub async fn create_session(&self, username: &str) -> Result<BlobSessionDb, BlobServerError> {
        todo!()
    }

    pub async fn validate_session(&self, username: &str, token: &str) -> Result<(), BlobServerError> {
        todo!()
    }

    pub async fn store_blob(&self, username: &str, data: &[u8]) -> Result<i64, BlobServerError> {
        let blob_id = sqlx::query!(
            r#"INSERT INTO blob (blob_account_id, data)
               VALUES ($1, $2)
               RETURNING blob_id"#,
            0,
            data,
        )
        .fetch_one(&self.connection_pool)
        .await?
        .blob_id;

        Ok(blob_id)
    }

    pub async fn retrieve_blob(&self, blob_id: i64) -> Result<Vec<u8>, BlobServerError> {
        let blob = sqlx::query_as!(
            BlobDb,
            r#"SELECT * FROM blob
               WHERE blob_id=$1"#,
            blob_id,
        )
        .fetch_one(&self.connection_pool)
        .await?
        .data;

        Ok(blob)
    }
}
