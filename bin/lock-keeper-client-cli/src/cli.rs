//! Command-line arguments

use anyhow::anyhow;
use clap::Parser;
use lock_keeper_client::{
    config::{ClientAuth, ConfigFile},
    Config,
};
use std::path::PathBuf;

#[derive(Debug, Parser)]
pub struct Cli {
    /// Location of client config file.
    /// If this arg is not provided, the `uri` and `ca-chain` args must be
    /// provided.
    #[clap(long)]
    pub config: Option<PathBuf>,

    /// Server URI.
    #[clap(long = "uri", conflicts_with = "config", requires = "ca-chain")]
    pub server_uri: Option<String>,
    /// Location of the file containing the signing CA chain for the server.
    #[clap(long, conflicts_with = "config", requires = "server-uri")]
    pub ca_chain: Option<PathBuf>,

    /// Client's signing CA chain.
    /// Only needed when client auth is enabled on the server.
    #[clap(long, conflicts_with = "config", requires = "private-key")]
    pub client_chain: Option<PathBuf>,
    /// Client's private key.
    /// Only needed when client auth is enabled on the server.
    #[clap(long, conflicts_with = "config", requires = "client-chain")]
    pub private_key: Option<PathBuf>,

    /// Directory where persistent storage files will be saved.
    #[clap(long, default_value = "dev/lk_client_cli_data")]
    pub storage_path: PathBuf,
    /// Path to a script file containing a sequence of CLI commands
    #[clap(long = "script-file", conflicts_with = "script")]
    pub script_file: Option<PathBuf>,
    /// Sequence of CLI commands separated by a semicolon or newline
    #[clap(long, conflicts_with = "script-file")]
    pub script: Option<String>,
}

impl Cli {
    pub fn client_config(&self) -> anyhow::Result<Config> {
        if let Some(config) = &self.config {
            return Ok(Config::from_file(config, None)?);
        }

        let server_uri = self.server_uri.as_ref().ok_or(anyhow!(
            "If `config` argument is not provided, `uri` must be provided"
        ))?;
        let ca_chain = self.ca_chain.as_ref().ok_or(anyhow!(
            "If `config` argument is not provided, `ca_chain` must be provided"
        ))?;

        let client_auth = if let (Some(certificate_chain), Some(private_key)) =
            (&self.client_chain, &self.private_key)
        {
            Some(ClientAuth {
                certificate_chain: certificate_chain.clone(),
                private_key: Some(private_key.clone()),
            })
        } else {
            None
        };

        let config_file = ConfigFile {
            server_uri: server_uri.clone(),
            ca_chain: ca_chain.clone(),
            client_auth,
        };
        Ok(Config::from_config_file(config_file, None)?)
    }
}
