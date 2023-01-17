//! This operation allows client to retrieve the stored audit event logs.
use crate::{
    database::DataStore,
    server::{Context, Operation},
    LockKeeperServerError,
};
use async_trait::async_trait;
use lock_keeper::{
    infrastructure::channel::{Authenticated, ServerChannel},
    types::operations::retrieve_audit_events::{client, server},
};
use rand::rngs::StdRng;
use tracing::{info, instrument};

#[derive(Debug)]
pub struct RetrieveAuditEvents;

#[async_trait]
impl<DB: DataStore> Operation<Authenticated<StdRng>, DB> for RetrieveAuditEvents {
    #[instrument(skip_all, err(Debug))]
    async fn operation(
        self,
        channel: &mut ServerChannel<Authenticated<StdRng>>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        info!("Starting retrieve audit events protocol");
        // Receive event type and options for audit events to return
        let request: client::Request = channel.receive().await?;

        let account_name = channel.metadata().account_name();
        let audit_events = context
            .db
            .find_audit_events(account_name, request.event_type, request.options)
            .await?;

        let reply = server::Response {
            summary_record: audit_events,
        };

        channel.send(reply).await?;
        info!("Successfully completed retrieve audit events protocol");
        Ok(())
    }
}
