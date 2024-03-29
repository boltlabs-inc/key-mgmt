use rand::{CryptoRng, RngCore};
use std::{fmt::Debug, sync::Arc};
use tokio::sync::{
    mpsc::{self, Receiver, Sender},
    Mutex,
};
use tokio_stream::StreamExt;
use tonic::{Request, Status, Streaming};

use lock_keeper::{
    constants::METADATA,
    crypto::{Encrypted, OpaqueSessionKey, StorageKey},
    rpc::Message,
    types::{
        database::account::{Account, AccountId, UserId},
        operations::{ConvertMessage, RequestMetadata},
    },
    LockKeeperError,
};

/// Number of buffer in our MPSC Channel. Determines how many messages
/// may be queued in channel.
const BUFFER_SIZE: usize = 2;

/// Server-side implementation of a two-way channel between a client and the
/// server used to communicate `Message` objects.
///
/// This bidirectional `Channel` is implemented under the hood as two
/// unidirectional channels. It can only be used with streaming messages
/// generated by `tonic`.
///
/// These are tokio MPSC channels, but `tonic` is able to use them to send
/// messages via the network between the server and client.
///
/// The `AUTH` generic parameter allows our channel to be generic over
/// either _authenticated_ or _unauthenticated_ operations.
#[derive(Debug)]
pub struct Channel<AUTH> {
    /// `Sender` end of an unidirectional channel. Allows us to send messages
    /// to the client. The server spawns the `sender` and `receiver` ends as a pair.
    /// The `receiver` is sent to the client as part of gRPC call so the server
    /// can send the client messages using this channel.
    sender: Sender<Result<Message, Status>>,
    /// A receiver end of an unidirectional channel. Allows us to receive
    /// messages from the client. When the client made a gRPC call, it sent
    /// this receiving end. The client can send messages to it and we will
    /// receive them.
    receiver: Streaming<Message>,
    metadata: RequestMetadata,
    auth: AUTH,
}

impl<AUTH> Channel<AUTH> {
    /// Returns the metadata associated with this channel.
    pub fn metadata(&self) -> &RequestMetadata {
        &self.metadata
    }

    /// Send an error message across the channel.
    pub async fn send_error(&mut self, status: impl Into<Status>) -> Result<(), LockKeeperError> {
        let payload = Err(status.into());
        Ok(self.sender.send(payload).await?)
    }

    pub async fn closed(&mut self) {
        self.sender.closed().await;
    }
}

/// Passed to channel type as the `AUTH` generic parameter.
///
/// It is used for channels that handle authenticated operations.
/// This type ensures that messages moving across a channel are encrypted.
pub struct Authenticated<RNG: CryptoRng + RngCore> {
    pub session_key: OpaqueSessionKey,
    pub account: Account,
    pub rng: Arc<Mutex<RNG>>,
}

impl<RNG: CryptoRng + RngCore> Channel<Authenticated<RNG>> {
    /// Returns the account ID for the authenticated user.
    pub fn account_id(&self) -> AccountId {
        self.auth.account.account_id
    }

    pub fn user_id(&self) -> &UserId {
        &self.auth.account.user_id
    }

    /// Returns the full account info for the authenticated user.
    pub fn account(&self) -> &Account {
        &self.auth.account
    }

    pub fn set_storage_key(&mut self, storage_key: Encrypted<StorageKey>) {
        self.auth.account.storage_key = Some(storage_key);
    }

    /// Receive the next message on the channel and convert it to the type `R`.
    pub async fn receive<R: ConvertMessage>(&mut self) -> Result<R, LockKeeperError> {
        match self.receiver.next().await {
            Some(message) => {
                let message = message?;
                let encrypted_message: Encrypted<Message> =
                    Encrypted::<Message>::try_from_message(message)?;
                let message = encrypted_message.decrypt_message(&self.auth.session_key)?;
                let result =
                    R::from_message(message).map_err(|_| LockKeeperError::InvalidMessage)?;
                Ok(result)
            }
            None => Err(LockKeeperError::NoMessageReceived),
        }
    }

    /// Send a message across the channel. This function accepts any type that
    /// can be converted to a `message` via the [`ConvertMessage`] trait.
    pub async fn send(&mut self, message: impl ConvertMessage) -> Result<(), LockKeeperError> {
        let message = message.to_message()?;

        let encrypted_message = {
            let mut rng = self.auth.rng.lock().await;
            self.auth
                .session_key
                .encrypt(&mut *rng, message)
                .map_err(LockKeeperError::Crypto)?
        }
        .try_into_message()?;

        let payload = Ok(encrypted_message);

        Ok(self.sender.send(payload).await?)
    }
}

/// Passed to channel type as the `AUTH` generic parameter.
/// It is used for channels that handle unauthenticated operations.
/// This type does nothing to modify messages passed across a channel.
pub struct Unauthenticated;

impl Channel<Unauthenticated> {
    pub fn new(
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
                auth: Unauthenticated,
            },
            remote_receiver,
        ))
    }

    pub fn into_authenticated<RNG: CryptoRng + RngCore>(
        self,
        account: Account,
        session_key: OpaqueSessionKey,
        rng: Arc<Mutex<RNG>>,
    ) -> Channel<Authenticated<RNG>> {
        Channel {
            sender: self.sender,
            receiver: self.receiver,
            metadata: self.metadata,
            auth: Authenticated {
                account,
                session_key,
                rng,
            },
        }
    }

    /// Receive the next message on the channel and convert it to the type `R`.
    pub async fn receive<R: ConvertMessage>(&mut self) -> Result<R, LockKeeperError> {
        match self.receiver.next().await {
            Some(message) => {
                let message = message?;
                let result =
                    R::from_message(message).map_err(|_| LockKeeperError::InvalidMessage)?;
                Ok(result)
            }
            None => Err(LockKeeperError::NoMessageReceived),
        }
    }

    /// Send a message across the channel. This function accepts any type that
    /// can be converted to a `Message`.
    pub async fn send(&mut self, message: impl ConvertMessage) -> Result<(), LockKeeperError> {
        let payload = Ok(message.to_message()?);
        Ok(self.sender.send(payload).await?)
    }
}
