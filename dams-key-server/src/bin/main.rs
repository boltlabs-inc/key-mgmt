use dams_key_server::server;
use structopt::StructOpt;
use tracing::error;
use tracing_subscriber::EnvFilter;

use Cli::Server;

#[derive(Debug, StructOpt)]
pub enum Cli {
    Server(dams_key_server::cli::Cli),
}

#[tokio::main]
pub async fn main() {
    let filter = EnvFilter::try_new("info,sqlx::query=warn").unwrap();
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let result = match Cli::from_args() {
        Server(cli) => server::main_with_cli(cli).await,
    };
    if let Err(e) = result {
        error!("{}", e);
    }
}
