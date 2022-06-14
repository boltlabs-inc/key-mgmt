use crate::keys::KeyId;

/// A transaction approval request is used to log a request for a
/// [`TransactionSignature`] under key associated with the [`KeyId`]. The key
/// must be owned by the [`UserId`], and the transaction must involve the
/// specified [`AssetId`], and be originated by the associated [`OriginatorId`].
///
/// The [`Transaction`] should be a valid transaction format for the blockchain
/// that the [`KeyId`] is associated with.
/// 
/// Assumption: TARs originate either with the asset owner or the service provider.
/// This is cryptographically enforced with an authenticated session when the request
/// is submitted from the client component. That is, TARs should only be accepted 
/// by the key servers if they are received via an authenticated session between
/// the key server and one of the asset owner or the service provider.
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
