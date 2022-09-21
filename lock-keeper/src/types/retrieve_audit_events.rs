pub mod client {
    use crate::{audit_event::EventType, crypto::KeyId, impl_message_conversion, user::UserId};
    use mongodb::bson::DateTime;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// Query specific set of audit event logs
    pub struct Request {
        pub user_id: UserId,
        pub event_type: EventType,
        pub key_ids: Option<Vec<KeyId>>,
        pub after_date: Option<DateTime>,
        pub before_date: Option<DateTime>,
    }

    impl_message_conversion!(Request);
}

pub mod server {
    use crate::{audit_event::AuditEvent, impl_message_conversion};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// Return vector of audit events
    pub struct Response {
        pub summary_record: Vec<AuditEvent>,
    }

    impl_message_conversion!(Response);
}
