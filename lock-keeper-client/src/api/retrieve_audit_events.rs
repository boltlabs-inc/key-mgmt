use crate::{api::AuditEventOptions, LockKeeperClient, LockKeeperClientError};
use lock_keeper::{
    audit_event::{AuditEvent, EventType},
    channel::ClientChannel,
    types::retrieve_audit_events::{client, server},
};

impl LockKeeperClient {
    pub(crate) async fn handle_retrieve_audit_events(
        &self,
        channel: &mut ClientChannel,
        event_type: EventType,
        options: Option<AuditEventOptions>,
    ) -> Result<Vec<AuditEvent>, LockKeeperClientError> {
        // Generate step: get new KeyId from server
        // Send UserId to server
        let generate_message = client::Request {
            event_type,
            options,
        };
        channel.send(generate_message).await?;

        let server_response: server::Response = channel.receive().await?;

        Ok(server_response.summary_record)
    }
}
