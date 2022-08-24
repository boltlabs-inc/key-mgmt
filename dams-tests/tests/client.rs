use dams::{
    blockchain::Blockchain,
    crypto::KeyId,
    keys::{SelfCustodial, SharedControl, UserPolicySpecification},
    transaction::TransactionApprovalRequest,
    user::UserId,
};
use dams_client::api::*;

// TODO #172: put test for close session back in

#[test]
#[should_panic(expected = "not yet implemented")]
fn create_digital_asset_key_not_implemented() {
    let _result = create_digital_asset_key(
        UserId::default(),
        Blockchain::EVM,
        SelfCustodial::default(),
        SharedControl,
    );
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn set_user_key_policy_not_implemented() {
    let _result = set_user_key_policy(UserId::default(), KeyId, UserPolicySpecification);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn request_transaction_signature_not_implemented() {
    let tar = TransactionApprovalRequest::default();
    let _result = request_transaction_signature(tar);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn retrieve_public_keys_not_implemented() {
    let _result = retrieve_public_keys(UserId::default());
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn retrieve_public_key_by_id_not_implemented() {
    let _result = retrieve_public_key_by_id(UserId::default(), &KeyId);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn retrieve_audit_log_not_implemented() {
    let _result = retrieve_audit_log(UserId::default(), None);
}
