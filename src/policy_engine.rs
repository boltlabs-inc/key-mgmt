//! Black-box policy engine API and supporting types.
//!
//! The key server will interact with a [`PolicyEngine`] instantiation.

use crate::transaction::TransactionApprovalRequest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Configuration for an asset fiduciary.
///
/// This must include public key information that can be used to verify approvals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetFiduciaryConfig;

/// Configuration for a policy engine.
///
/// Assumption: The access control structure for asset fiduciaries requires approval
/// from all fiduciaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEngineConfig {
    /// Indicates whether unilateral control keys are allowed in the system.
    #[serde(default)]
    unilateral_control_allowed: bool,
    /// The number of [`SelfCustodial`](crate::keys::SelfCustodial) keys each user can create.
    #[serde(default)]
    max_self_custodial: u16,
    /// The number of [`Delegated`](crate::keys::Delegated) keys each user can create.
    #[serde(default)]
    max_delegated: u16,
    /// The set of asset fiduciaries.
    asset_fiduciaries: Vec<AssetFiduciaryConfig>,
}

#[allow(unused)]
impl PolicyEngineConfig {
    pub fn unilateral_control_allowed(&self) -> bool {
        self.unilateral_control_allowed
    }
    pub fn max_self_custodial(&self) -> u16 {
        self.max_self_custodial
    }
    pub fn max_delegated(&self) -> u16 {
        self.max_delegated
    }
    pub fn asset_fiduciaries(&self) -> &Vec<AssetFiduciaryConfig> {
        &self.asset_fiduciaries
    }
}

/// A `PolicyEngine` is the entity responsible for coordination and management
/// of operations requested on digital asset keys with
/// [`SharedControl`](crate::keys::SharedControl).
///
/// This trait describes the interactions between a key server and the policy
/// engine, but doesn't encompass the entire behavior of a policy engine -- the
/// policy engine is responsible for all interactions with service providers and asset
/// fiduciaries.
///
/// Assumption: any policy engine implementation will have one or more API
/// endpoints that correspond to the trait methods. Instantiation of this trait
/// will call out to the appropriate endpoints, and will handle any retries and
/// waiting behavior dictated by the external implementation.
pub trait PolicyEngine {
    /// Initialize the policy engine interface according to the specified configuration.
    fn initialize(config: PolicyEngineConfig) -> Result<Self, PolicyEngineError>
    where
        Self: Sized;

    fn request_transaction_approval(
        &self,
        request: TransactionApprovalRequest,
    ) -> Result<TransactionApprovalDecision, PolicyEngineError>;
}

/// The set of valid outcomes from a [`PolicyEngine`] decision.
#[derive(Debug)]
#[allow(unused)]
pub enum TransactionApprovalDecision {
    /// All asset fiduciaries approved the request; there must be exactly one
    /// signature per asset fiduciary.
    Approve(Vec<ApprovalSignature>),
    /// At least one asset fiduciary rejected the request; the vector cannot be
    /// empty.
    Reject(Vec<RejectionContext>),
}

/// Signature from an asset fiduciary over a [`TransactionApprovalRequest`].
///
/// The set of asset fiduciaries is fixed and defined in the [`PolicyEngineConfig`].
/// This type can only be instantiated if the underlying signature corresponds
/// to one of the specified fiduciaries.
#[derive(Debug)]
pub struct ApprovalSignature;

/// Context for why an asset fiduciary rejected a [`TransactionApprovalRequest`].
#[derive(Debug)]
pub struct RejectionContext;

/// Errors that can arise during a transaction approval request to a policy
/// engine.
///
/// This does not include rejection of a request! That is covered by a
/// [`TransactionApprovalDecision`].
#[derive(Debug, Error)]
pub enum PolicyEngineError {}
