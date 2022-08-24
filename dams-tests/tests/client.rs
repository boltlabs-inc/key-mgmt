use dams::{
    blockchain::Blockchain,
    crypto::KeyId,
    keys::{SelfCustodial, SharedControl, UserPolicySpecification},
    transaction::TransactionApprovalRequest,
    user::UserId,
};
use dams_client::api::*;

#[test]
#[should_panic(expected = "not yet implemented")]
fn close_session_not_implemented() {
    let session = DamsClient::default();
    let _result = session.close();
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn create_digital_asset_key_not_implemented() {
    let _result = create_digital_asset_key(
        DamsClient::default(),
        UserId::default(),
        Blockchain::EVM,
        SelfCustodial::default(),
        SharedControl,
    );
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn set_user_key_policy_not_implemented() {
    let _result = set_user_key_policy(
        DamsClient::default(),
        UserId::default(),
        KeyId,
        UserPolicySpecification,
    );
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn request_transaction_signature_not_implemented() {
    let tar = TransactionApprovalRequest::default();
    let _result = request_transaction_signature(DamsClient::default(), tar);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn retrieve_public_keys_not_implemented() {
    let _result = retrieve_public_keys(DamsClient::default(), UserId::default());
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn retrieve_public_key_by_id_not_implemented() {
    let _result = retrieve_public_key_by_id(DamsClient::default(), UserId::default(), &KeyId);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn retrieve_audit_log_not_implemented() {
    let _result = retrieve_audit_log(DamsClient::default(), UserId::default(), None);
}
