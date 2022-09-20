use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_stream::StreamExt;
use tonic::{Status, Streaming};

use crate::{dams_rpc::Message, DamsError};

const BUFFER_SIZE: usize = 2;

pub type ServerChannel = Channel<Result<Message, Status>>;
pub type ClientChannel = Channel<Message>;

/// A two-way channel between a client and server used to communicate with
/// `Message` objects. `Channel` uses `tonic` types to receive messages. It can
/// only be used with streaming messages generated by `tonic`.
///
/// The implementations are slightly different between the client and server due
/// to the types required by the code auto-generated by `tonic`. Type aliases
/// are provided and each comes with its own `create` implementation.
#[derive(Debug)]
pub struct Channel<T> {
    sender: Sender<T>,
    receiver: Streaming<Message>,
}

impl<T> Channel<T> {
    /// Receive the next message on the channel and convert it to the type `R`.
    /// If the message cannot be converted to `R`, it is assumed to be an
    /// invalid message and an error is returned.
    pub async fn receive<R: TryFrom<Message>>(&mut self) -> Result<R, DamsError> {
        match self.receiver.next().await {
            Some(message) => {
                let message = message?;
                let result = R::try_from(message).map_err(|_| DamsError::InvalidMessage)?;
                Ok(result)
            }
            None => Err(DamsError::NoMessageReceived),
        }
    }

    /// Generic `send` function used by the client and server versions of
    /// `Channel`.
    async fn handle_send(&mut self, message: T) -> Result<(), DamsError> {
        Ok(self.sender.send(message).await?)
    }
}

impl ServerChannel {
    /// Create a server-side `Channel` that sends error codes in addition to
    /// `Message` objects.
    pub fn create(receiver: Streaming<Message>) -> (Self, Receiver<Result<Message, Status>>) {
        let (sender, remote_receiver) = mpsc::channel(BUFFER_SIZE);

        (Self { sender, receiver }, remote_receiver)
    }

    /// Send a message across the channel. This function accepts any type that
    /// can be converted to a `Message.
    pub async fn send(&mut self, message: impl TryInto<Message>) -> Result<(), DamsError> {
        let message = message
            .try_into()
            .map_err(|_| Status::internal("Invalid message"))?;

        self.handle_send(Ok(message)).await
    }

    pub async fn send_error(&mut self, status: impl Into<Status>) -> Result<(), DamsError> {
        self.handle_send(Err(status.into())).await
    }
}

impl ClientChannel {
    /// Create a client-side `Channel` that sends raw `Message` objects.
    pub fn create(sender: Sender<Message>, receiver: Streaming<Message>) -> Self {
        Self { sender, receiver }
    }

    /// Send a message across the channel. This function accepts any type that
    /// can be converted to a `Message.
    pub async fn send(&mut self, message: impl TryInto<Message>) -> Result<(), DamsError> {
        let message = message
            .try_into()
            .map_err(|_| Status::internal("Invalid message"))?;

        self.handle_send(message).await
    }
}
