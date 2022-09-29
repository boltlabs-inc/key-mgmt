pub mod authenticate;
pub mod create_storage_key;
pub mod generate;
pub mod register;
pub mod retrieve;
pub mod retrieve_audit_events;
pub mod retrieve_storage_key;

use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;

pub use crate::rpc::Message;

pub type MessageStream = ReceiverStream<Result<Message, Status>>;
