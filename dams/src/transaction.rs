//! Library for blockchains, transactions, and requests for signatures on
//! transactions.

use serde::{Deserialize, Serialize};

use crate::{keys::KeyId, user::UserId};

/// A transaction approval request is used to log a request for a
/// [`TransactionSignature`] under the specified key. The key
/// must be owned by the [`UserId`], and the transaction must involve the
/// specified [`AssetId`].
///
/// The [`Transaction`] should be a valid transaction format for the blockchain
/// that the key is associated with. This must be validated by the calling
/// application - it will not be checked by the [`TransactionApprovalRequest`]
/// constructor.
///
/// Assumption: TARs originate either with the asset owner or the service
/// provider. This is cryptographically enforced with an authenticated session
/// when the request is submitted from the client component. That is, TARs
/// should only be accepted by the key server if they are received via an
/// authenticated session between the key server and one of the asset owner or
/// the service provider.
#[derive(Debug, Serialize, Deserialize)]
#[allow(unused)]
pub struct TransactionApprovalRequest {
    key_id: KeyId,
    user_id: UserId,
    asset_id: AssetId,
    tar_id: TarId,
    transaction: Transaction,
}

impl Default for TransactionApprovalRequest {
    fn default() -> Self {
        Self {
            key_id: KeyId,
            user_id: UserId::default(),
            asset_id: AssetId,
            tar_id: TarId,
            transaction: Transaction,
        }
    }
}

/// Unique ID for a [`TransactionApprovalRequest`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TarId;

/// Unique ID for a digital asset.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AssetId;

/// A transaction describes the transfer of a digital asset owned by an asset
/// owner to another entity.
#[derive(Debug, Serialize, Deserialize)]
pub struct Transaction;

/// Signature on a [`Transaction`] under a digital asset key.
#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionSignature;
