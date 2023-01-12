use lock_keeper_key_server::server::session_cache::Session;
use sqlx::types::time::OffsetDateTime;
use uuid::Uuid;

use crate::Error;

pub(crate) struct SessionDB {
    pub(crate) session_id: Uuid,
    pub(crate) account_id: i64,
    pub(crate) timestamp: OffsetDateTime,
    pub(crate) session_key: Vec<u8>,
}

impl TryFrom<SessionDB> for Session {
    type Error = Error;

    fn try_from(session: SessionDB) -> Result<Self, Self::Error> {
        let account_id = session.account_id.into();
        let session_key = bincode::deserialize(&session.session_key)?;

        Ok(Session {
            session_id: session.session_id,
            account_id,
            timestamp: session.timestamp,
            session_key,
        })
    }
}
