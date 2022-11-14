use crate::{LockKeeperClient, LockKeeperClientError, LockKeeperResponse};
use lock_keeper::{
    infrastructure::channel::ClientChannel,
    types::{
        audit_event::{AuditEvent, AuditEventOptions, EventType},
        operations::retrieve_audit_events::{client, server},
    },
};

impl LockKeeperClient {
    pub(crate) async fn handle_retrieve_audit_events(
        &self,
        mut channel: ClientChannel,
        event_type: EventType,
        options: AuditEventOptions,
    ) -> Result<LockKeeperResponse<Vec<AuditEvent>>, LockKeeperClientError> {
        // Send audit event request and filters
        let client_request = client::Request {
            event_type,
            options,
        };
        channel.send(client_request).await?;

        // Receive audit event log and return
        let server_response: server::Response = channel.receive().await?;

        Ok(LockKeeperResponse::from_channel(
            channel,
            server_response.summary_record,
        ))
    }
}
