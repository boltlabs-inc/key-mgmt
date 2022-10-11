//! Type definitions that are shared between crates but have little to no logic.

pub mod audit_event;
pub mod operations;
pub mod user;

pub use crate::rpc::Message;

use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;

pub type MessageStream = ReceiverStream<Result<Message, Status>>;
