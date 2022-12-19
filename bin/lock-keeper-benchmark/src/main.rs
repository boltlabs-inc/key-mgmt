use std::str::FromStr;

use lock_keeper::types::database::user::AccountName;
use lock_keeper_client::{LockKeeperClient, client::Password, Config};

#[tokio::main]
async fn main() {
    let account_name = AccountName::from_str("test_account").unwrap();
    let password = Password::from_str("password").unwrap();
    let config = Config::from_file("dev/config/local/Client.toml", None).unwrap();

    let _ = LockKeeperClient::register(&account_name, &password, &config).await;
    let client = LockKeeperClient::authenticated_client(&account_name, &password, &config).await.unwrap().data;

    let key_id = client.generate_secret().await.unwrap().data.key_id;
    let _exported = client.export_secret(&key_id).await.unwrap();

}
