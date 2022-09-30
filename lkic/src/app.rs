use std::{
    io::{self, Write},
    path::PathBuf,
    str::FromStr,
};

use lock_keeper::config::client::Config;

use crate::{command::Command, state::State};

/// Runs the interactive client
pub async fn run(config: Config, storage_path: PathBuf) -> anyhow::Result<()> {
    let mut state = State::new(config, storage_path)?;

    loop {
        let command = match input(&state) {
            Ok(cmd) => cmd,
            Err(e) => {
                println!("{e}");
                continue;
            }
        };
        if let Err(e) = command.execute(&mut state).await {
            println!("{e}");
            continue;
        }
    }
}

/// Prints the appropriate prompt and inputs the next command
fn input(state: &State) -> anyhow::Result<Command> {
    if state.credentials.is_some() {
        print!("> ");
    } else {
        print!("| ");
    }
    // Flush stdout so the prompt actually get printed
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let command = Command::from_str(&input)?;

    Ok(command)
}
