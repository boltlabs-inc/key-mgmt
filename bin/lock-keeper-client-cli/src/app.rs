use lock_keeper_client::Config;

use std::{
    io::{self, Write},
    path::PathBuf,
    time::SystemTime,
};

use crate::{
    cli_command::{parse_cli_command, CliCommand},
    scripting::Script,
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

/// Runs the interactive client
pub async fn run_script(
    config: Config,
    storage_path: PathBuf,
    script: Script,
) -> anyhow::Result<()> {
    let mut state = State::new(config, storage_path)?;

    let now = SystemTime::now();
    let elapsed = script.execute(&mut state).await?;
    let total_script_time = now.elapsed()?;

    println!();
    println!("Script completed successfully");
    println!("Client operations completed in {} ms", elapsed.as_millis());
    println!(
        "Total script execution completed in {} ms",
        total_script_time.as_millis()
    );

    Ok(())
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
