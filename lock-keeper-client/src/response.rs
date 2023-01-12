use crate::LockKeeperClientError;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Metadata {
    pub request_id: Uuid,
}

#[derive(Debug)]
pub struct LockKeeperResponse<T> {
    pub result: Result<T, LockKeeperClientError>,
    pub metadata: Option<Metadata>,
}
