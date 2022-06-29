//! Black-box policy engine API and supporting types.
//!
//! The key server will interact with a [`PolicyEngine`] instantiation.

use crate::transaction::TransactionApprovalRequest;
use thiserror::Error;

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
    fn request_transaction_approval(
        &self,
        request: TransactionApprovalRequest,
    ) -> Result<TransactionApprovalDecision, PolicyEngineError>;
}

/// The set of valid outcomes from a [`PolicyEngine`] decision.
///
/// TODO : Expand these variants with the appropriate context - approval
/// signatures or a note to describe the rejection.
#[derive(Debug)]
#[allow(unused)]
pub enum TransactionApprovalDecision {
    Approve(Vec<ApprovalSignature>),
    Reject(RejectionContext),
}

/// Signature from an asset fiduciary over a [`TransactionApprovalRequest`].
///
/// Assumption: The signature is from an asset fiduciary. The set of asset
/// fiduciaries is fixed and defined in the system configuration. This type
/// must not be instantiated if the underlying signature does not correspond
/// to one of the specified fiduciaries.
#[derive(Debug)]
pub struct ApprovalSignature;

/// Context for why a the [`PolicyEngine`] rejected a
/// [`TransactionApprovalRequest`].
#[derive(Debug)]
pub struct RejectionContext;

/// Errors that can arise during a transaction approval request to a policy
/// engine.
///
/// This does not include rejection of a request! That is covered by a
/// [`TransactionApprovalDecision`].
#[derive(Debug, Error)]
pub enum PolicyEngineError {}
