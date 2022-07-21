use mongodb::{options::ClientOptions, Client, Database};
use std::env;

pub async fn connect_to_mongo() -> Result<Database, anyhow::Error> {
    let mongodb_url = env::var("MONGODB_URI")?;
    let db_name = env::var("DB_NAME")?;
    // Parse a connection string into an options struct
    let client_options = ClientOptions::parse(mongodb_url).await?;
    // Get a handle to the deployment
    let client = Client::with_options(client_options)?;
    // Get a handle to the database
    let db = client.database(&db_name);
    Ok(db)
}
