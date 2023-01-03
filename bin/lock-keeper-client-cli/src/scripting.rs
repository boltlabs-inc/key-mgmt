use anyhow::Result;
use std::{path::Path, str::FromStr, time::Duration};

use crate::{
    cli_command::{parse_cli_command, DynCommand},
    state::State,
};

/// A sequence of commands that can be executed without user input.
#[derive(Debug)]
pub struct Script(Vec<DynCommand>);

impl Script {
    /// Execute all of the commands in the script in sequence.
    pub async fn execute(self, state: &mut State) -> Result<Duration> {
        let mut total_duration = Duration::ZERO;
        for command in self.0 {
            let duration = command.execute(state).await?;
            total_duration += duration;
        }

        Ok(total_duration)
    }

    /// Parse a script from a file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let script_string = std::fs::read_to_string(path)?;
        script_string.parse()
    }
}

impl FromStr for Script {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Replace semicolon with line breaks. Add line breaks after brackets.
        let s = s.replace(';', "\n").replace('{', "{\n").replace('}', "}\n");

        // Trim whitespace and remove empty lines
        let mut lines = s.lines().map(str::trim).filter(|line| !line.is_empty());

        let mut commands = Vec::new();
        while let Some(line) = lines.next() {
            if line.starts_with("repeat") {
                // Find the number of repeats
                let split: Vec<&str> = line.split(' ').collect();
                let num_repeats: usize = split
                    .get(1)
                    .ok_or_else(|| anyhow::anyhow!("Invalid repeat command"))?
                    .parse()?;

                commands.extend(parse_repeats(num_repeats, &mut lines)?);
            } else {
                commands.push(parse_cli_command(line)?)
            }
        }

        Ok(Self(commands))
    }
}

fn parse_repeats<'a>(
    num_repeats: usize,
    input: &mut impl Iterator<Item = &'a str>,
) -> anyhow::Result<Vec<DynCommand>> {
    let mut commands = Vec::new();

    // Parse commands until a close bracket is detected.
    let mut lines_to_repeat = Vec::new();
    for line in input.by_ref() {
        // Repeat block ends
        if line.starts_with('}') {
            break;
        } else {
            lines_to_repeat.push(line);
        }
    }

    // Now repeat those commands `num_repeats` times.
    for _ in 0..num_repeats {
        for line in &lines_to_repeat {
            commands.push(parse_cli_command(line)?)
        }
    }

    Ok(commands)
}
