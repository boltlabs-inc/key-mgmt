use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};

use crate::{
    constants::METADATA,
    rpc::Message,
    types::operations::{RequestMetadata, ResponseMetadata},
    LockKeeperError,
};

const BUFFER_SIZE: usize = 2;

pub type ServerChannel = Channel<Result<Message, Status>, RequestMetadata>;
pub type ClientChannel = Channel<Message, ResponseMetadata>;

/// A two-way channel between a client and server used to communicate with
/// `Message` objects. `Channel` uses `tonic` types to receive messages. It can
/// only be used with streaming messages generated by `tonic`.
///
/// The implementations are slightly different between the client and server due
/// to the types required by the code auto-generated by `tonic`. Type aliases
/// are provided and each comes with its own `create` implementation.
#[derive(Debug)]
pub struct Channel<T, M> {
    sender: Sender<T>,
    receiver: Streaming<Message>,
    metadata: M,
}

impl<T, M> Channel<T, M> {
    /// Receive the next message on the channel and convert it to the type `R`.
    /// If the message cannot be converted to `R`, it is assumed to be an
    /// invalid message and an error is returned.
    pub async fn receive<R: TryFrom<Message>>(&mut self) -> Result<R, LockKeeperError> {
        match self.receiver.next().await {
            Some(message) => {
                let message = message?;
                let result = R::try_from(message).map_err(|_| LockKeeperError::InvalidMessage)?;
                Ok(result)
            }
            None => Err(LockKeeperError::NoMessageReceived),
        }
    }

    /// Generic `send` function used by the client and server versions of
    /// `Channel`.
    async fn handle_send(&mut self, message: T) -> Result<(), LockKeeperError> {
        Ok(self.sender.send(message).await?)
    }

    /// Returns the metadata associated with this channel.
    pub fn metadata(&self) -> &M {
        &self.metadata
    }

    /// Consumes the channel and returns the metadata.
    /// Use this when you're finished with the channel but need to return the
    /// metadata.
    pub fn into_metadata(self) -> M {
        self.metadata
    }
}

impl ServerChannel {
    /// Create a server-side `Channel` that sends error codes in addition to
    /// `Message` objects.
    pub fn create(
        request: Request<Streaming<Message>>,
    ) -> Result<(Self, Receiver<Result<Message, Status>>), LockKeeperError> {
        let (sender, remote_receiver) = mpsc::channel(BUFFER_SIZE);

        let metadata = request
            .metadata()
            .get(METADATA)
            .ok_or(LockKeeperError::MetadataNotFound)?
            .try_into()?;

        Ok((
            Self {
                sender,
                receiver: request.into_inner(),
                metadata,
            },
            remote_receiver,
        ))
    }

    /// Send a message across the channel. This function accepts any type that
    /// can be converted to a `Message.
    pub async fn send(&mut self, message: impl TryInto<Message>) -> Result<(), LockKeeperError> {
        let message = message
            .try_into()
            .map_err(|_| Status::internal("Invalid message"))?;

        self.handle_send(Ok(message)).await
    }

    pub async fn send_error(&mut self, status: impl Into<Status>) -> Result<(), LockKeeperError> {
        self.handle_send(Err(status.into())).await
    }
}

impl ClientChannel {
    /// Create a client-side `Channel` that sends raw `Message` objects.
    pub fn create(
        sender: Sender<Message>,
        response: Response<Streaming<Message>>,
    ) -> Result<Self, LockKeeperError> {
        let metadata = response
            .metadata()
            .get(METADATA)
            .ok_or(LockKeeperError::MetadataNotFound)?
            .try_into()?;

        Ok(Self {
            sender,
            receiver: response.into_inner(),
            metadata,
        })
    }

    /// Send a message across the channel. This function accepts any type that
    /// can be converted to a `Message.
    pub async fn send(&mut self, message: impl TryInto<Message>) -> Result<(), LockKeeperError> {
        let message = message
            .try_into()
            .map_err(|_| Status::internal("Invalid message"))?;

        self.handle_send(message).await
    }
}
