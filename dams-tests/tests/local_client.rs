use dams::{
    blockchain::Blockchain,
    keys::{KeyId, SelfCustodial, SharedControl, UserPolicySpecification},
    transaction::TransactionApprovalRequest,
    user::UserId,
};
use dams_local_client::api::*;

#[test]
#[should_panic(expected = "not yet implemented")]
fn close_session_not_implemented() {
    let session = Session::default();
    let _result = session.close();
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn create_digital_asset_key_not_implemented() {
    let _result = create_digital_asset_key(
        Session::default(),
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
        Session::default(),
        UserId::default(),
        KeyId,
        UserPolicySpecification,
    );
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn request_transaction_signature_not_implemented() {
    let tar = TransactionApprovalRequest::default();
    let _result = request_transaction_signature(Session::default(), tar);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn retrieve_public_keys_not_implemented() {
    let _result = retrieve_public_keys(Session::default(), UserId::default());
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn retrieve_public_key_by_id_not_implemented() {
    let _result = retrieve_public_key_by_id(Session::default(), UserId::default(), &KeyId);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn retrieve_audit_log_not_implemented() {
    let _result = retrieve_audit_log(Session::default(), UserId::default(), None);
}
