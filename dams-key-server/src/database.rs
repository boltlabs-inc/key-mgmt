//! Database for key-servers.
//!
//! This database will hold information on users and the secret material
//! they have stored in the key server.

use dams::user::User;
use mongodb::{
    bson::doc,
    options::{ClientOptions, IndexOptions},
    Client, Database, IndexModel,
};

use crate::{constants, error::DamsServerError};

pub(crate) mod user;

/// Connect to the MongoDB instance and database specified by your environment
/// variables
pub async fn connect_to_mongo(
    mongodb_uri: &str,
    db_name: &str,
) -> Result<Database, DamsServerError> {
    // Parse a connection string into an options struct
    let client_options = ClientOptions::parse(mongodb_uri).await?;
    // Get a handle to the deployment
    let client = Client::with_options(client_options)?;
    // Get a handle to the database
    let db = client.database(db_name);

    // Enforce that the user ID is unique
    let enforce_uniqueness = IndexOptions::builder().unique(true).build();
    let user_id_index = IndexModel::builder()
        .keys(doc! {"user_id": 1})
        .options(enforce_uniqueness)
        .build();

    // Enforce that the account name is unique
    let enforce_uniqueness = IndexOptions::builder().unique(true).build();
    let account_name_index = IndexModel::builder()
        .keys(doc! {"account_name": 1})
        .options(enforce_uniqueness)
        .build();

    // Apply uniquness to the database
    let _created_indices = db
        .collection::<User>(constants::USERS)
        .create_indexes([user_id_index, account_name_index], None)
        .await?;

    Ok(db)
}
