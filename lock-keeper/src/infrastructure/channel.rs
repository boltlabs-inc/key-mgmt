use rand::rngs::StdRng;
use std::sync::Arc;
use tokio::sync::{
    mpsc::{self, Receiver, Sender},
    Mutex,
};
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};

use crate::{
    constants::METADATA,
    crypto::{Encrypted, OpaqueSessionKey},
    rpc::Message,
    types::operations::{RequestMetadata, ResponseMetadata},
    LockKeeperError,
    LockKeeperError::AlreadyAuthenticated,
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
    session_key: Option<OpaqueSessionKey>,
    rng: Arc<Mutex<StdRng>>,
}

pub trait ShouldBeAuthenticated {
    fn should_be_authenticated(&self) -> bool;
}

impl<T, M> Channel<T, M> {
    /// Receive the next message on the channel and convert it to the type `R`.
    /// If this is an authenticated channel the message gets decrypted first.
    /// If the message cannot be converted to `R`, it is assumed to be an
    /// invalid message and an error is returned.
    pub async fn receive<R: TryFrom<Message>>(&mut self) -> Result<R, LockKeeperError> {
        match self.receiver.next().await {
            Some(message) => {
                let message = message?;
                let result = match self.session_key.clone() {
                    None => R::try_from(message).map_err(|_| LockKeeperError::InvalidMessage)?,
                    Some(session_key) => {
                        let encrypted_message: Encrypted<Message> =
                            Encrypted::<Message>::try_from(message)?;
                        let message = encrypted_message.decrypt_message(session_key)?;
                        R::try_from(message).map_err(|_| LockKeeperError::InvalidMessage)?
                    }
                };
                Ok(result)
            }
            None => Err(LockKeeperError::NoMessageReceived),
        }
    }

    /// This function encrypts the message using the session_key if this is an
    /// authenticated channel. The object that is send needs to implement
    /// the ShouldBeAuthenticated trait as an extra verification that the object
    /// needs to be sent over an (un)authenticated channel.
    async fn optional_encryption_with_session_key(
        &mut self,
        message: impl TryInto<Message> + ShouldBeAuthenticated,
    ) -> Result<Message, LockKeeperError> {
        match self.session_key.clone() {
            None => {
                if message.should_be_authenticated() {
                    return Err(LockKeeperError::ShouldBeAuthenticated);
                }
                Ok(message
                    .try_into()
                    .map_err(|_| Status::internal("Invalid message"))?)
            }
            Some(session_key) => {
                let message = message
                    .try_into()
                    .map_err(|_| Status::internal("Invalid message"))?;
                let message = {
                    let mut rng = self.rng.lock().await;
                    session_key
                        .encrypt(&mut *rng, message)
                        .map_err(LockKeeperError::Crypto)?
                };

                Ok(message
                    .try_into()
                    .map_err(|_| Status::internal("Invalid message"))?)
            }
        }
    }

    /// Generic `send` function used by the client and server versions of
    /// `Channel`.
    async fn handle_send(&mut self, message: T) -> Result<(), LockKeeperError> {
        Ok(self.sender.send(message).await?)
    }

    /// During authentication a channel can be upgraded to become an
    /// authenticated channel. Such that future messages are sent while
    /// being encrypted by the session_key.
    pub fn try_upgrade_to_authenticated(
        &mut self,
        session_key: OpaqueSessionKey,
    ) -> Result<(), LockKeeperError> {
        if self.session_key.is_some() {
            return Err(AlreadyAuthenticated);
        }
        self.session_key = Some(session_key);
        Ok(())
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
    ///
    /// # Arguments
    ///
    /// * rng - a reference to a secure random number generated.
    /// * receiver - a receiver of the messages sent over the channel.
    /// * session_key - an optional session key in case this should be an
    /// authenticated channel.
    pub fn create(
        rng: Arc<Mutex<StdRng>>,
        request: Request<Streaming<Message>>,
        session_key: Option<OpaqueSessionKey>,
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
                session_key,
                rng,
            },
            remote_receiver,
        ))
    }

    /// Send a message across the channel. This function accepts any type that
    /// can be converted to a `Message. In case a session_key is provided to the
    /// channel, the message will be encrypted using the session_key.
    pub async fn send(
        &mut self,
        message: impl TryInto<Message> + ShouldBeAuthenticated,
    ) -> Result<(), LockKeeperError> {
        let message_to_send = self.optional_encryption_with_session_key(message).await?;
        self.handle_send(Ok(message_to_send)).await
    }

    pub async fn send_error(&mut self, status: impl Into<Status>) -> Result<(), LockKeeperError> {
        self.handle_send(Err(status.into())).await
    }
}

impl ClientChannel {
    /// Create a client-side `Channel` that sends raw `Message` objects.
    ///
    /// # Arguments
    ///
    /// * rng - a reference to a secure random number generated.
    /// * sender - a sender for the messages that need to be sent over the
    /// channel.
    /// * receiver - a receiver of the messages sent over the channel.
    /// * session_key - an optional session key in case this should be an
    /// authenticated channel.
    pub fn create(
        rng: Arc<Mutex<StdRng>>,
        sender: Sender<Message>,
        response: Response<Streaming<Message>>,
        session_key: Option<OpaqueSessionKey>,
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
            session_key,
            rng,
        })
    }

    /// Send a message across the channel. This function accepts any type that
    /// can be converted to a `Message. In case a session_key is provided to the
    /// channel, the message will be encrypted using the session_key.
    pub async fn send(
        &mut self,
        message: impl TryInto<Message> + ShouldBeAuthenticated,
    ) -> Result<(), LockKeeperError> {
        let message_to_send = self.optional_encryption_with_session_key(message).await?;
        self.handle_send(message_to_send).await
    }
}
