pub mod client;
pub mod server;

pub use client::ClientChannel;
pub use server::ServerChannel;

use rand::{CryptoRng, RngCore};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::crypto::OpaqueSessionKey;

const BUFFER_SIZE: usize = 2;

/// Passed to channel types as the `AUTH` generic parameter.
/// It is used for channels that handle authenticated operations.
/// This type ensures that messages moving across a channel are encrypted.
pub struct Authenticated<RNG: CryptoRng + RngCore> {
    pub session_key: OpaqueSessionKey,
    pub rng: Arc<Mutex<RNG>>,
}

/// Passed to channel types as the `AUTH` generic parameter.
/// It is used for channels that handle unauthenticated operations.
/// This type does nothing to modify messages passed across a channel.
pub struct Unauthenticated;
