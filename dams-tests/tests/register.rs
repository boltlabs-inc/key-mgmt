mod common;

use dams::user::AccountName;
use dams_client::{client::Password, DamsClient};
use std::str::FromStr;

#[tokio::test]
pub async fn end_to_end_tests() {
    let (server_future, client_config, db) = common::setup().await;

    let account_name = AccountName::from_str("testUser").unwrap();
    let password = Password::from_str("testPassword").unwrap();

    DamsClient::register(&account_name, &password, &client_config)
        .await
        .unwrap();

    // let collection = db.collection::<User>(constants::USERS);
    // let query = doc! {"user_id": user_id.to_string()};
    // let user = collection.find_one(query, None).await?;

    common::teardown(server_future).await;
}
