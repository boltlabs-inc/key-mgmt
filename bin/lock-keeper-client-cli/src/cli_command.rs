pub mod authenticate;
pub mod export;
pub mod generate;
pub mod get_audit_events;
pub mod health;
pub mod help;
pub mod import;
pub mod list;
pub mod logout;
pub mod print;
pub mod quit;
pub mod register;
pub mod remote_generate;
pub mod remote_sign;
pub mod retrieve;
pub mod retrieve_blob;
pub mod store_blob;
pub mod wait;

pub use authenticate::Authenticate;
pub use export::Export;
pub use generate::Generate;
pub use get_audit_events::GetAuditEvents;
pub use health::Health;
pub use help::Help;
pub use import::Import;
pub use list::List;
pub use logout::Logout;
pub use print::Print;
pub use quit::Quit;
pub use register::Register;
pub use remote_generate::RemoteGenerate;
pub use remote_sign::RemoteSign;
pub use retrieve::Retrieve;
pub use retrieve_blob::RetrieveBlob;
pub use store_blob::StoreBlob;
pub use wait::Wait;

use crate::state::State;
use anyhow::{anyhow, bail};
use async_trait::async_trait;
use std::{fmt::Debug, time::Duration};
use tracing::{debug, info};

pub type DynCommand = Box<dyn CliCommand>;

#[async_trait]
pub trait CliCommand: Debug {
    /// Execute the command. Returns the total elapsed time of the client
    /// operation not including authentication or extra work done by this
    /// application.
    async fn execute(self: Box<Self>, state: &mut State) -> Result<Duration, anyhow::Error>;

    /// Given the proper string arguments to a command, return an instance of
    /// this command.
    fn parse_command_args(args: &[&str]) -> Option<Self>
    where
        Self: Sized;

    /// Expected format for this command such as "register \[account_name\]
    /// \[password\]". Used for generating help string dynamically.
    fn format() -> &'static str
    where
        Self: Sized;

    fn aliases() -> Vec<&'static str>
    where
        Self: Sized;

    fn description() -> &'static str
    where
        Self: Sized;

    /// Convert a string into a `Box<dyn Command>` suitable for dynamically
    /// dispatching the execute function.
    fn to_dyn(self) -> DynCommand
    where
        Self: Sized + 'static,
    {
        Box::new(self)
    }

    fn from_str(s: &str) -> Result<Self, anyhow::Error>
    where
        Self: Sized,
    {
        let mut split = s.trim().split(' ');

        let command = split
            .next()
            .ok_or_else(|| anyhow!("Missing \"command\" part of argument."))?;
        debug!("Looking for match for \"{}\"", command);

        // Check if this command matches any of our aliases. Otherwise return.
        // We do this check here to avoid doing it inside every
        // `CliCommand::parse_command_args` function.
        if !Self::aliases().contains(&command) {
            info!("Valid aliases for this command are: {:?}", Self::aliases());
            bail!("Command does not match any know name or alias.");
        }
        info!("Found valid command: {}", command);

        match Self::parse_command_args(&split.collect::<Vec<_>>()) {
            Some(t) => Ok(t),
            None => bail!("Expected Format: {}", Self::format()),
        }
    }
}

// Iterate through our registered commands and see if any of them can parse this
// command.
pub fn parse_cli_command(input: &str) -> Result<DynCommand, anyhow::Error> {
    let input = input.trim();

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

/// This code supports numerous commands which have similar functionality. This
/// common functionality is expressed by the [CliCommand] trait. A common
/// pattern in this code is to get the analogous function for all our commands.
/// For example, the parsing function for each implementor of CliCommand.
///
/// This function allows us to return a vector of functions which implement some
/// functionality.
///
/// The correct function to fetch can be specified via the type parameter by
/// implementing the [GetCmdFunction] trait for your type.
///
/// If you want to add a new command to this CLI please specify your command
/// here! The rest of the code will know how to use it.
pub fn get_cmd_functions<F: GetCmdFunction>() -> Vec<F::FunctionSignature> {
    vec![
        F::get_function::<Authenticate>(),
        F::get_function::<Export>(),
        F::get_function::<Generate>(),
        F::get_function::<GetAuditEvents>(),
        F::get_function::<Health>(),
        F::get_function::<Help>(),
        F::get_function::<Import>(),
        F::get_function::<List>(),
        F::get_function::<Logout>(),
        F::get_function::<Print>(),
        F::get_function::<Quit>(),
        F::get_function::<Register>(),
        F::get_function::<RemoteGenerate>(),
        F::get_function::<RemoteSign>(),
        F::get_function::<Retrieve>(),
        F::get_function::<RetrieveBlob>(),
        F::get_function::<StoreBlob>(),
        F::get_function::<Wait>(),
    ]
}

/// This trait allows us to specify two things:
/// The implementor of this trait, Self.
/// And the T: CliCommand, which is a generic parameter to the
/// [GetCmdFunction::get_function].
///
/// This allows us to map Self -> get_function<T: CliCommand>.
///
/// With this, we can generate a set of functions generic over this T. Then
/// specify this T with all the different types that implement CliCommand.
///
/// This is used to generate a vector of functions that implement some
/// functionality for each type that implements CliCommand. See
/// [get_cmd_functions] for how this is used.
pub trait GetCmdFunction {
    /// The signature of the function this implementor will be returning.
    type FunctionSignature;
    /// Given a specific implementor of CliCommand, T, return the correct
    /// function implementation for that type.
    fn get_function<T: CliCommand + 'static>() -> Self::FunctionSignature;
}
