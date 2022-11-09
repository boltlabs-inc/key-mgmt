//! Constants used throughout the database API.

/* TABLE NAMES */
pub(crate) const AUDIT_EVENTS: &str = "audit_events";
pub(crate) const USERS: &str = "users";

/* FIELD NAMES */
pub(crate) const ACTION: &str = "action";
pub(crate) const ACTOR: &str = "actor";
pub(crate) const DATE: &str = "date";
pub(crate) const SECRET_ID: &str = "secret_id";
pub(crate) const STORAGE_KEY: &str = "storage_key";

/* DB CONFIG */
pub(crate) const MAX_AUDIT_ENTRIES: i64 = 100;
