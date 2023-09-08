use std::sync::Arc;

use lock_keeper::{
    crypto::KeyId,
    types::{audit_event::EventStatus, database::account::AccountId, operations::ClientAction},
};
use rand::rngs::StdRng;
use tokio::sync::Mutex;
use tracing::instrument;
use uuid::Uuid;

use crate::{Config, LockKeeperServerError};

use super::{database::DataStore, metrics::OperationMetrics, session_cache::SessionCache};

pub(crate) struct Context<DB: DataStore> {
    pub db: Arc<DB>,
    pub config: Arc<Config>,
    pub rng: Arc<Mutex<StdRng>>,
    pub key_id: Option<KeyId>,
    /// Our user session keys are held in this cache after authentication.
    pub session_cache: Arc<Mutex<dyn SessionCache>>,
    pub operation_metrics: Arc<OperationMetrics>,
}

impl<DB: DataStore> Context<DB> {
    #[instrument(skip(self))]
    pub(crate) async fn create_audit_event(
        &self,
        account_id: AccountId,
        request_id: Uuid,
        client_action: ClientAction,
        status: EventStatus,
    ) -> Result<(), LockKeeperServerError> {
        Ok(self
            .db
            .create_audit_event(request_id, account_id, &self.key_id, client_action, status)
            .await?)
    }
}
