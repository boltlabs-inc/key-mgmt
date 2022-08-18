//! Constants used throughout the dams-key-server.

/// Buffer size for mpsc channels used for gRPC calls.
pub(crate) const BUFFER: usize = 2;

/* DB TABLE NAMES */
/// Name of MongoDB users table.
pub(crate) const USERS: &str = "users";
