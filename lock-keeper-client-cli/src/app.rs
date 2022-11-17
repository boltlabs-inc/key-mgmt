use anyhow::anyhow;
use lock_keeper_client::Config;

use std::{
    io::{self, Write},
    path::PathBuf,
};
use tracing::info;

use crate::{
    cli_command::{get_cmd_functions, CliCommand, DynCommand, GetCmdFunction},
    state::State,
};

/// Runs the interactive client
pub async fn run(config: Config, storage_path: PathBuf) -> anyhow::Result<()> {
    let mut state = State::new(config, storage_path)?;
    println!("Type \"help\" to view list of commands.");

    loop {
        match parse_input(&state) {
            Ok(command) => {
                if let Err(e) = command.execute(&mut state).await {
                    println!("Error: {e}");
                }
            }
            Err(e) => {
                println!("Unable to parse command: {e}");
            }
        };
    }
}

/// Reads next command from standard input.
///
/// Returns a dynamic trait representing the parsed command or an error if no
/// such command exist.
fn parse_input(state: &State) -> anyhow::Result<Box<dyn CliCommand>> {
    if state.credentials.is_some() {
        print!("> ");
    } else {
        print!("| ");
    }
    // Flush stdout so the prompt actually get printed
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let command = parse_cli_command(&input)?;

    Ok(command)
}

// Iterate through our registered commands and see if any of them can parse this
// command.
fn parse_cli_command(input: &str) -> Result<DynCommand, anyhow::Error> {
    info!("Attempting to parse user input string: {}", input);

    let parsers = get_cmd_functions::<Parse>();
    for cmd_parse in parsers {
        if let Ok(c) = cmd_parse(input) {
            return Ok(c);
        }
    }

    Err(anyhow!("No matching command."))
}

/// Helper type to implement [GetCmdFunction]. This returns the parsing
/// function for all commands and allows the [parse_cli_command] to iterate
/// through these functions.
struct Parse;

impl GetCmdFunction for Parse {
    type FunctionSignature = fn(&str) -> Result<DynCommand, anyhow::Error>;

    fn get_function<T: CliCommand + 'static>() -> Self::FunctionSignature {
        |s| T::from_str(s).map(|c| c.to_dyn())
    }
}
