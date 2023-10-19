use time::OffsetDateTime;

#[derive(Clone)]
pub struct BlobAccountDb {
    pub blob_account_id: i64,
    pub name: String,
    pub api_secret: String,
    pub time_created: OffsetDateTime,
    pub time_modified: OffsetDateTime,
}

#[derive(Clone)]
pub struct BlobDb {
    pub blob_id: i64,
    pub blob_account_id: i64,
    pub data: Vec<u8>,
    pub time_created: OffsetDateTime,
    pub time_modified: OffsetDateTime,
}

#[derive(Clone)]
pub struct BlobSessionDb {
    pub blob_session_id: i64,
    pub blob_account_id: i64,
    pub device_id: i64,
    pub token: String,
    pub expiration: OffsetDateTime,
}
