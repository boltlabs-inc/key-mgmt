//! Types for parsing and handling commands received as user input.

use std::str::FromStr;

use lock_keeper::types::operations::retrieve::RetrieveContext;
use lock_keeper_client::LockKeeperClient;

use crate::{
    state::{Credentials, State},
    storage::Entry,
};

const REGISTER_FORMAT: &str = "register [account_name] [password]";
const AUTHENTICATE_FORMAT: &str = "authenticate [account_name] [password]";
const RETRIEVE_FORMAT: &str = "retrieve [key_name]";
const PRINT_FORMAT: &str = "print [key_name]";

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
                    .get(credentials.account_name.clone(), &name)?
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
            Command::Print { name } => {
                let credentials = state
                    .credentials
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;

                // Get key_id from storage
                let entry = state
                    .storage
                    .get(credentials.account_name.clone(), &name)?
                    .ok_or_else(|| anyhow::anyhow!("No key found with name {name}"))?;

                println!("name: {name}");
                println!("{entry}");
            }
            Command::List => {
                let credentials = state
                    .credentials
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;

                state.storage.list(credentials.account_name.clone())?;
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

        match split.next() {
            Some(command) => match command {
                "register" | "reg" => {
                    let account_name = split
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("Expected: {REGISTER_FORMAT}"))?
                        .to_string();
                    let password = split
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("Expected: {REGISTER_FORMAT}"))?
                        .to_string();
                    Ok(Self::Register {
                        account_name,
                        password,
                    })
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
                    Ok(Self::Authenticate {
                        account_name,
                        password,
                    })
                }
                "generate" | "gen" | "g" => {
                    let name = split.next().map(ToString::to_string);

                    Ok(Self::Generate { name })
                }
                "retrieve" | "ret" | "r" => {
                    let name = split
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("Expected: {RETRIEVE_FORMAT}"))?
                        .to_string();
                    Ok(Self::Retrieve { name })
                }
                "print" | "p" => {
                    let name = split
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("Expected: {PRINT_FORMAT}"))?
                        .to_string();

                    Ok(Self::Print { name })
                }
                "list" | "ls" => Ok(Self::List),
                "audit" => Ok(Self::GetAuditEvents),
                "logout" => Ok(Self::Logout),
                "help" | "h" => Ok(Self::Help),
                "exit" | "quit" | "q" => Ok(Self::Exit),
                _ => anyhow::bail!("Invalid command"),
            },
            None => anyhow::bail!("Invalid command"),
        }
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
description: Generate a new key. If you provide a name, the key can be referenced by that name. 
             If you don't provide a name, the key can be referenced by the number printed to the screen after generation.

command: retrieve [key_name]
aliases: ret, r
description: Retrieve a previously generated key from the key server and update local storage.

command: print [key_name]
aliases: p
description: Prints all stored information about the given key.

command: list
aliases: ls
description: Prints stored information about every key associated with the current account.

command: help
aliases: h
description: Prints help text.

command: quit
aliases: q, exit
description: Quits the application
";
