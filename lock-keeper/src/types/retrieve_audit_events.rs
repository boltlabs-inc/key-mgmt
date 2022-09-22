pub mod client {
    use crate::{
        audit_event::{AuditEventOptions, EventType},
        impl_message_conversion,
    };
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// Query specific set of audit event logs
    pub struct Request {
        // TODO spec#132: decide whether user ID needs to be added back in to request
        pub event_type: EventType,
        pub options: Option<AuditEventOptions>,
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
