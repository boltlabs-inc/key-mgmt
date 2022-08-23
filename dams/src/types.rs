use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;

pub mod authenticate;
pub mod register;

pub use crate::dams_rpc::Message;

pub type MessageStream = ReceiverStream<Result<Message, Status>>;
