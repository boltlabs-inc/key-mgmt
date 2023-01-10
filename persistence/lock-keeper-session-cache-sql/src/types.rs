use lock_keeper_key_server::server::session_cache::Session;
use sqlx::types::time::OffsetDateTime;
use uuid::Uuid;

use crate::Error;

pub(crate) struct SessionDB {
    pub(crate) session_id: Uuid,
    pub(crate) user_id: Vec<u8>,
    pub(crate) timestamp: OffsetDateTime,
    pub(crate) session_key: Vec<u8>,
}

impl TryFrom<SessionDB> for Session {
    type Error = Error;

    fn try_from(session: SessionDB) -> Result<Self, Self::Error> {
        let user_id = session.user_id.as_slice().try_into()?;
        let session_key = bincode::deserialize(&session.session_key)?;

        Ok(Session {
            session_id: session.session_id,
            user_id,
            timestamp: session.timestamp,
            session_key,
        })
    }
}
