use crate::{
    server::{Context, Operation},
    LockKeeperServerError,
};
use async_trait::async_trait;
use lock_keeper::{
    infrastructure::channel::ServerChannel,
    types::operations::retrieve_audit_events::{client, server},
};

#[derive(Debug)]
pub struct RetrieveAuditEvents;

#[async_trait]
impl Operation for RetrieveAuditEvents {
    async fn operation(
        self,
        channel: &mut ServerChannel,
        context: &mut Context,
    ) -> Result<(), LockKeeperServerError> {
        // Receive event type and options for audit events to return
        let request: client::Request = channel.receive().await?;

        let audit_events = context
            .db
            .find_audit_events(
                context.metadata.account_name(),
                request.event_type,
                request.options,
            )
            .await?;

        let reply = server::Response {
            summary_record: audit_events,
        };

        channel.send(reply).await?;

        Ok(())
    }
}
