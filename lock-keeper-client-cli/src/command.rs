//! Types for parsing and handling commands received as user input.

use rand::Rng;
use std::str::FromStr;
use tracing::info;

use lock_keeper::{crypto::SignableBytes, types::operations::retrieve::RetrieveContext};
use lock_keeper_client::LockKeeperClient;

use crate::{
    state::{Credentials, State},
    storage::{DataType, Entry},
};

const REGISTER_FORMAT: &str = "register [account_name] [password]";
const AUTHENTICATE_FORMAT: &str = "authenticate [account_name] [password]";
const RETRIEVE_FORMAT: &str = "retrieve [key_name]";
const REMOTE_SIGN_FORMAT: &str = "remote-sign [key_name] [string_to_sign]";
const PRINT_FORMAT: &str = "print [key_name]";
const EXPORT_FORMAT: &str = "export [key_name]";

/// Fully parsed command that's ready for processing.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Register {
        account_name: String,
        password: String,
    },
    Authenticate {
        account_name: String,
        password: String,
    },
    Generate {
        name: Option<String>,
    },
    Retrieve {
        name: String,
    },
    RemoteGenerate {
        name: Option<String>,
    },
    Export {
        name: String,
    },
    Import {
        name: Option<String>,
    },
    RemoteSign {
        name: String,
        data: String,
    },
    Print {
        name: String,
    },
    List,
    GetAuditEvents,
    Logout,
    Help,
    Exit,
}

impl Command {
    /// Execute this command
    pub async fn execute(self, state: &mut State) -> anyhow::Result<()> {
        match self {
            Command::Register {
                account_name,
                password,
            } => {
                let account_name = account_name.parse()?;
                let password = password.parse()?;

                LockKeeperClient::register(&account_name, &password, &state.config).await?;

                println!("Logged in to {account_name}");
                state.credentials = Some(Credentials {
                    account_name,
                    password,
                })
            }
            Command::Authenticate {
                account_name,
                password,
            } => {
                let account_name = account_name.parse()?;
                let password = password.parse()?;

                LockKeeperClient::authenticated_client(&account_name, &password, &state.config)
                    .await?;

                println!("Logged in to {account_name}");
                state.credentials = Some(Credentials {
                    account_name,
                    password,
                })
            }
            Command::Generate { name } => {
                let credentials = state
                    .credentials
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;

                // Authenticate user to the key server
                let lock_keeper_client = LockKeeperClient::authenticated_client(
                    &credentials.account_name,
                    &credentials.password,
                    &state.config,
                )
                .await?;

                // If successful, proceed to generate a secret with the established session
                let generate_result = lock_keeper_client.generate_and_store().await?;

                // Store Key
                match name {
                    Some(name) => {
                        state.storage.store_named(
                            credentials.account_name.clone(),
                            &name,
                            generate_result,
                        )?;
                        println!("Stored: {name}");
                    }
                    None => {
                        let name = state
                            .storage
                            .store(credentials.account_name.clone(), generate_result)?;
                        println!("Stored: {name}");
                    }
                }
            }
            Command::Retrieve { name } => {
                let credentials = state
                    .credentials
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;

                // Authenticate user to the key server
                let lock_keeper_client = LockKeeperClient::authenticated_client(
                    &credentials.account_name,
                    &credentials.password,
                    &state.config,
                )
                .await?;

                // Get key_id from storage
                let entry = state
                    .storage
                    .get(&credentials.account_name, &name)?
                    .ok_or_else(|| anyhow::anyhow!("No key found with name {name}"))?;

                let retrieve_result = lock_keeper_client
                    .retrieve(&entry.key_id, RetrieveContext::LocalOnly)
                    .await?;

                let retrieve_entry: Entry = (entry.key_id.clone(), retrieve_result).into();
                println!("Retrieved: {name}");
                println!("{retrieve_entry}");

                state.storage.store_named(
                    credentials.account_name.clone(),
                    &name,
                    retrieve_entry,
                )?;
                println!("Updated: {name}");
            }
            Command::RemoteGenerate { name } => {
                let credentials = state
                    .credentials
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;

                // Authenticate user to the key server
                let lock_keeper_client = LockKeeperClient::authenticated_client(
                    &credentials.account_name,
                    &credentials.password,
                    &state.config,
                )
                .await?;

                // If successful, proceed to generate a secret with the established session
                let generate_result = lock_keeper_client.remote_generate().await?;

                // Store Key Id
                match name {
                    Some(name) => {
                        state.storage.store_named(
                            credentials.account_name.clone(),
                            &name,
                            generate_result.key_id,
                        )?;
                        println!("Stored: {name}");
                    }
                    None => {
                        let name = state
                            .storage
                            .store(credentials.account_name.clone(), generate_result.key_id)?;
                        println!("Stored: {name}");
                    }
                }
            }
            Command::RemoteSign { name, data } => {
                let credentials = state
                    .credentials
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;

                // Get key_id from storage
                let entry = state
                    .storage
                    .get(credentials.account_name.clone(), &name)?
                    .ok_or_else(|| anyhow::anyhow!("No key found with name {name}"))?;

                // Authenticate user to the key server
                let lock_keeper_client = LockKeeperClient::authenticated_client(
                    &credentials.account_name,
                    &credentials.password,
                    &state.config,
                )
                .await?;

                let bytes = SignableBytes(data.into_bytes());

                // If successful, proceed to generate a secret with the established session
                let signature = lock_keeper_client
                    .remote_sign_bytes(entry.key_id.clone(), bytes)
                    .await?;
                let sig_hex = hex::encode(signature.as_ref());

                println!("Signature: {sig_hex}");
            }
            Command::Export { name } => {
                info!("Exporting {}", name);

                let credentials = state
                    .credentials
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;

                // Authenticate user to the key server.
                let lock_keeper_client = LockKeeperClient::authenticated_client(
                    &credentials.account_name,
                    &credentials.password,
                    &state.config,
                )
                .await?;

                // Get key_id from storage
                let entry = state
                    .storage
                    .get(&credentials.account_name, &name)?
                    .ok_or_else(|| anyhow::anyhow!("No key found with name {name}"))?;

                let export = lock_keeper_client
                    .export_signing_key(&entry.key_id)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to export signing key. Error: {:?}", e))?;

                println!("Retrieved: {name}");
                println!("{:?}", export);

                state.storage.store_named(
                    credentials.account_name.clone(),
                    &name,
                    Entry::new(entry.key_id.clone(), DataType::Export(export)),
                )?;
                println!("Updated Key: {name}");
            }
            Command::Print { name } => {
                let credentials = state
                    .credentials
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;

                // Get key_id from storage
                let entry = state
                    .storage
                    .get(&credentials.account_name, &name)?
                    .ok_or_else(|| anyhow::anyhow!("No key found with name {name}"))?;

                println!("name: {name}");
                println!("{entry}");
            }
            Command::Import { name } => {
                let credentials = state
                    .credentials
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;

                // Authenticate user to the key server
                let lock_keeper_client = LockKeeperClient::authenticated_client(
                    &credentials.account_name,
                    &credentials.password,
                    &state.config,
                )
                .await?;

                let random_bytes = rand::thread_rng().gen::<[u8; 32]>().to_vec();
                let key_id = lock_keeper_client
                    .import_signing_key(random_bytes)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to import signing key. Error: {:?}", e))?;

                match name {
                    Some(name) => {
                        state.storage.store_named(
                            credentials.account_name.clone(),
                            &name,
                            key_id,
                        )?;
                        println!("Stored: {name}");
                    }
                    None => {
                        let name = state
                            .storage
                            .store(credentials.account_name.clone(), key_id)?;
                        println!("Stored: {name}");
                    }
                }
            }
            Command::List => {
                let credentials = state
                    .credentials
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;

                state.storage.list(&credentials.account_name)?;
            }
            Command::GetAuditEvents => {
                println!("Not implemented");
            }
            Command::Logout => {
                state.credentials = None;
            }
            Command::Help => println!("{HELP_TEXT}"),
            Command::Exit => std::process::exit(0),
        }

        Ok(())
    }
}

impl FromStr for Command {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.trim().split(' ');

        let command = match split.next() {
            Some(command_str) => match command_str {
                "register" | "reg" => {
                    let account_name = split
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("Expected: {REGISTER_FORMAT}"))?
                        .to_string();
                    let password = split
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("Expected: {REGISTER_FORMAT}"))?
                        .to_string();
                    Self::Register {
                        account_name,
                        password,
                    }
                }
                "authenticate" | "auth" | "a" | "login" => {
                    let account_name = split
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("Expected: {AUTHENTICATE_FORMAT}"))?
                        .to_string();
                    let password = split
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("Expected: {AUTHENTICATE_FORMAT}"))?
                        .to_string();
                    Self::Authenticate {
                        account_name,
                        password,
                    }
                }
                "generate" | "gen" | "g" => {
                    let name = split.next().map(ToString::to_string);
                    Self::Generate { name }
                }
                "retrieve" | "ret" | "r" => {
                    let name = split
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("Expected: {RETRIEVE_FORMAT}"))?
                        .to_string();
                    Self::Retrieve { name }
                }
                "remote-generate" | "rgen" | "rg" => {
                    let name = split.next().map(ToString::to_string);
                    Self::RemoteGenerate { name }
                }
                "export" | "e" => {
                    let name = split
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("Expected: {EXPORT_FORMAT}"))?
                        .to_string();
                    Self::Export { name }
                }
                "import" | "i" => {
                    let name = split.next().map(String::from);
                    Self::Import { name }
                }
                "remote-sign" | "rsig" | "rs" => {
                    let name = split
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("Expected: {REMOTE_SIGN_FORMAT}"))?
                        .to_string();
                    let data = split
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("Expected: {REMOTE_SIGN_FORMAT}"))?
                        .to_string();

                    Self::RemoteSign { name, data }
                }
                "print" | "p" => {
                    let name = split
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("Expected: {PRINT_FORMAT}"))?
                        .to_string();
                    Self::Print { name }
                }
                "list" | "ls" => Self::List,
                "audit" => Self::GetAuditEvents,
                "logout" => Self::Logout,
                "help" | "h" => Self::Help,
                "exit" | "quit" | "q" => Self::Exit,
                _ => anyhow::bail!("Invalid command"),
            },
            None => anyhow::bail!("Invalid command"),
        };

        info!("Parsed command: {:?}", command);
        Ok(command)
    }
}

const HELP_TEXT: &str = "
Enter a command at the prompt. The prompt will display \"|\" if you are logged out and \">\" if you are logged in.

command: register [account_name] [password]
aliases: reg
description: Registers a new account with the given account_name and password

command: authenticate [account_name] [password]
aliases: auth, a, login
description: Authenticates to a previously registered account. Authentication is required for most commands.

command: generate [key_name (optional)]
aliases: gen, g
description: Generate an arbitrary key. If you provide a name, the key can be referenced by that name. 
             If you don't provide a name, the key can be referenced by the number printed to the screen after generation.

command: retrieve [key_name]
aliases: ret, r
description: Retrieve a previously generated arbitrary key from the server and update local storage.
             This command will fail if the key is a signing key.
             

command: remote-generate [key_name (optional)]
aliases: rgen, rg
description: Generate a new signing key remotely. This key will be generated entirely in the server.
             If you provide a name, the key can be referenced by that name. 
             If you don't provide a name, the key can be referenced by the number printed to the screen after generation.

command: export [key_name]
aliases: e
description: Export a previously generated signing key from the key server and update local storage.
             By default the signing key is not removed from the server after exporting.
             This operation will fail if called on an arbitrary key.

command: import [key_name (optional)]
aliases: i
description: Import a randomly generated signing key to the server.
             If you provide a name, the key can be referenced by that name. 
             If you don't provide a name, the key can be referenced by the number printed to the screen after generation.


command: print [key_name]
aliases: p
description: Prints all stored information about the given key.

command: list
aliases: ls
description: Prints stored information about every key associated with the current account.

command: logout
description: Log out of currently authenticated account.

command: help
aliases: h
description: Prints help text.

command: quit
aliases: q, exit
description: Quits the application
";
