//! Database for key-servers.
//!
//! This database will hold information on users and the secret material
//! they have stored in the key server.

use mongodb::{options::ClientOptions, Client, Database};

pub(crate) mod user;

/// Connect to the MongoDB instance and database specified by your environment
/// variables
pub async fn connect_to_mongo(
    mongodb_uri: &String,
    db_name: &String,
) -> Result<Database, anyhow::Error> {
    // Parse a connection string into an options struct
    let client_options = ClientOptions::parse(mongodb_uri).await?;
    // Get a handle to the deployment
    let client = Client::with_options(client_options)?;
    // Get a handle to the database
    let db = client.database(&db_name);
    Ok(db)
}
