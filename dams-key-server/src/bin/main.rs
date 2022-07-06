use structopt::StructOpt;
use tracing::error;
use tracing_subscriber::EnvFilter;

mod server;

#[derive(Debug, StructOpt)]
pub enum Cli {
    Server(key_server::cli::Cli),
}

#[tokio::main]
pub async fn main() {
    let filter = EnvFilter::try_new("info,sqlx::query=warn").unwrap();
    tracing_subscriber::fmt().with_env_filter(filter).init();

    use Cli::Server;
    let result = match Cli::from_args() {
        Server(cli) => server::main_with_cli(cli).await,
    };
    if let Err(e) = result {
        error!("{}, caused by: {}", e, e.root_cause());
    }
}
