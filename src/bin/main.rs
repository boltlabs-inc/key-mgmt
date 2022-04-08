use structopt::StructOpt;
use tracing::error;
use tracing_subscriber::EnvFilter;

pub(crate) mod client;

mod server;

#[derive(Debug, StructOpt)]
pub enum Cli {
    Client(keymgmt::client::Cli),
    Server(keymgmt::server::Cli),
}

#[tokio::main]
pub async fn main() {
    let filter = EnvFilter::try_new("info,sqlx::query=warn").unwrap();
    tracing_subscriber::fmt().with_env_filter(filter).init();

    use Cli::{Client, Server};
    let result = match Cli::from_args() {
        Server(cli) => server::main_with_cli(cli).await,
        Client(cli) => client::main_with_cli(cli).await,
    };
    if let Err(e) = result {
        error!("{}, caused by: {}", e, e.root_cause());
    }
}
