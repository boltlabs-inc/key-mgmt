//! Constants that are shared between other crates in this workspace.
//! Crate-specific constants should go in their respective crates.

pub const LOCAL_SERVER_URI: &str = "https://localhost:1113";

pub mod headers {
    pub const ACCOUNT_NAME: &str = "account_name";
    pub const ACTION: &str = "action";
    pub const USER_ID: &str = "user_id";
}
