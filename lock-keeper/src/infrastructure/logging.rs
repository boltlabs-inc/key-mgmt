//! Utilities for our logging (tracing) infrastructure.

use std::fmt::Debug;
use tracing::{warn, Span};

/// For the current active span, record `field_value` for the field
/// `field_name`. This fields must already be defined in the current span.
///
/// All events that happen inside this span will have these fields attached as
/// additional data.
///
/// For example:
/// ```text
///   2022-12-05T19:47:03.090605Z  INFO lock_keeper_key_server::operations::authenticate: Starting authentication protocol.
///     at lock-keeper-key-server/src/operations/authenticate.rs:38
///     in lock_keeper_key_server::operations::authenticate::operation
///     in lock_keeper_key_server::server::operation::handle_request with request_id: "9cb5e6fe-aa86-43e9-b7c9-413c005cbb50", action: "Authenticate"
/// ```
/// We can see here the `handle_request` span has fields "request_id" and
/// "action".
///
/// If running on development mode, this function will check if the field has
/// NOT been defined and log a warning.
///
///  Note: We use dynamic dispatch for the `field_value` argument as we expect
/// lots of types to call this function.
pub fn record_field(field_name: &str, field_value: &dyn Debug) {
    if cfg!(debug_assertions) && !Span::current().has_field(field_name) {
        warn!("Field {} not defined in current span!", field_name);
    }

    // Ignore the resulting span.
    let _ = Span::current().record(field_name, &format!("{field_value:?}"));
}
