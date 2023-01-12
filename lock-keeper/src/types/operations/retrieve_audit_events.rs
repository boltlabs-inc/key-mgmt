pub mod client {
    use crate::types::audit_event::{AuditEventOptions, EventType};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// Query specific set of audit event logs
    pub struct Request {
        // TODO spec#132: decide whether user ID needs to be added back in to request
        pub event_type: EventType,
        pub options: AuditEventOptions,
    }
}

pub mod server {
    use crate::types::audit_event::AuditEvent;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// Return vector of audit events
    pub struct Response {
        pub summary_record: Vec<AuditEvent>,
    }
}
