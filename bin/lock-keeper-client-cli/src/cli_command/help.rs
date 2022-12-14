use crate::{cli_command::CliCommand, state::State};
use anyhow::Error;
use async_trait::async_trait;
use tracing::info;

use crate::cli_command::{get_cmd_functions, GetCmdFunction};

#[derive(Debug)]
pub struct Help {
    help_string: String,
}

impl Help {
    /// Generate help string from all registered commands.
    fn all_commands() -> String {
        let mut help_string = String::new();

        for gen_help_str in get_cmd_functions::<HelpString>() {
            help_string.push_str(&gen_help_str());
            help_string.push('\n');
        }
        help_string
    }

    /// Generate a help string from the other trait methods in this struct.
    fn help_string(cmd_format: &str, aliases: &[&str], description: &str) -> String {
        use colored::Colorize;
        format!(
            "Command: {}\nAliases: {:?}\nDescription: {}\n",
            cmd_format.bold(),
            aliases,
            description
        )
    }
}

/// This represents calling help with no args, i.e. print all commands.
#[async_trait]
impl CliCommand for Help {
    async fn execute(self: Box<Self>, _state: &mut State) -> Result<(), Error> {
        println!("{}", self.help_string);
        Ok(())
    }

    fn parse_command_args(args: &[&str]) -> Option<Self> {
        info!("Trying to parse help with args {:?}", args);
        match args {
            // User does not specify help command. Return string for all commands.
            [] => Some(Help {
                help_string: Help::all_commands(),
            }),
            // User specifies command. Look for matching command and return relevant help
            // string.
            [command] => {
                for parse_command in get_cmd_functions::<FindCommand>() {
                    if let Some(help_string) = parse_command(command) {
                        return Some(Help { help_string });
                    }
                }
                None
            }
            _ => None,
        }
    }
    fn format() -> &'static str {
        "help [command (Optional)]"
    }

    fn aliases() -> Vec<&'static str> {
        vec!["help", "h"]
    }

    fn description() -> &'static str {
        "Prints the help string of the specified command. Or print the help strings for all commands
             if no command is specified."
    }
}

/// Helper type to generate help strings based on the methods provided by the
/// [CliCommand] trait.
struct HelpString;

impl GetCmdFunction for HelpString {
    type FunctionSignature = fn() -> String;

    fn get_function<T: CliCommand>() -> Self::FunctionSignature {
        || Help::help_string(T::format(), &T::aliases(), T::description())
    }
}

/// Helper type to generate functions for all our CliCommand implementors. This
/// function generates the proper help string from a command string or alias.
struct FindCommand;

impl GetCmdFunction for FindCommand {
    type FunctionSignature = fn(&str) -> Option<String>;

    fn get_function<T: CliCommand>() -> Self::FunctionSignature {
        |alias| {
            if T::aliases().contains(&alias) {
                Some(Help::help_string(
                    T::format(),
                    &T::aliases(),
                    T::description(),
                ))
            } else {
                None
            }
        }
    }
}
