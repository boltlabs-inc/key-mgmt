use crate::keys::KeyId;

/// A transaction approval request is used to log a request for a
/// [`TransactionSignature`] under key associated with the [`KeyId`]. The key
/// must be owned by the [`UserId`], and the transaction must involve the
/// specified [`AssetId`], and be originated by the associated [`OriginatorId`].
///
/// Future iterations may add some cryptographic proof that this request was
/// formed by the specified [`OriginatorId`].
///
/// The [`Transaction`] should be a valid transaction format for the blockchain
/// that the [`KeyId`] is associated with.
#[derive(Debug)]
#[allow(unused)]
pub struct TransactionApprovalRequest {
    key_id: KeyId,
    user_id: UserId,
    asset_id: AssetId,
    tar_id: TarId,
    originator_id: OriginatorId,
    transaction: Transaction,
}

/// Unique ID for a user. Assumption: this will be derived from an ID generated
/// in the Forte ecosystem.
#[derive(Debug, Clone, Copy)]
pub struct UserId;

/// Unique ID for a [`TransactionApprovalRequest`].
#[derive(Debug, Clone, Copy)]
pub struct TarId;

/// Unique ID for a digital asset.
#[derive(Debug, Clone, Copy)]
pub struct AssetId {}

/// Unique ID for the entity that originates a transaction.
#[derive(Debug, Clone, Copy)]
pub struct OriginatorId(UserId);

/// Transaction on a blockchain.
#[derive(Debug)]
pub struct Transaction {}

/// Signature on a [`Transaction`] under a [`DigitalAssetKey`]
#[derive(Debug)]
pub struct TransactionSignature {}
