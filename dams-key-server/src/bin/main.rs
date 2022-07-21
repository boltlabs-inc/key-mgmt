extern crate dotenv;

use dams_key_server::database;
use structopt::StructOpt;
use tracing::error;
use tracing_subscriber::EnvFilter;

use Cli::Server;

mod server;

#[derive(Debug, StructOpt)]
pub enum Cli {
    Server(dams_key_server::cli::Cli),
}

#[tokio::main]
pub async fn main() {
    dotenv::dotenv().ok();
    let filter = EnvFilter::try_new("info,sqlx::query=warn").unwrap();
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let db = database::connect_to_mongo().await;

    if db.is_ok() {
        let result = match Cli::from_args() {
            Server(cli) => server::main_with_cli(cli, db.unwrap().clone()).await,
        };
        if let Err(e) = result {
            error!("{}, caused by: {}", e, e.root_cause());
        }
    } else {
        error!("Unable to connect to mongo");
    }
}
