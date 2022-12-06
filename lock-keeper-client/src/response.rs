use lock_keeper::{infrastructure::channel::ClientChannel, types::operations::ResponseMetadata};

#[derive(Clone, Debug)]
pub struct LockKeeperResponse<T> {
    pub data: T,
    pub metadata: ResponseMetadata,
}

impl<T> LockKeeperResponse<T> {
    /// Consumes a [`ClientChannel`] and returns a response.
    pub fn from_channel<AUTH>(channel: ClientChannel<AUTH>, data: T) -> Self {
        Self {
            data,
            metadata: channel.into_metadata(),
        }
    }

    /// Consumes the response and returns the inner data.
    pub fn into_inner(self) -> T {
        self.data
    }
}
