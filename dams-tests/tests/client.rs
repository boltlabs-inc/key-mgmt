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
    let session = Session::default();
    let _result = session.close();
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn create_key_not_implemented() {
    let _result = create_key(
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
fn sign_transaction_not_implemented() {
    let tar = TransactionApprovalRequest::default();
    let _result = sign_transaction(Session::default(), tar);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn get_pub_keys_not_implemented() {
    let _result = get_pub_keys(Session::default(), UserId::default());
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn get_pub_key_by_id_not_implemented() {
    let _result = get_pub_key_by_id(Session::default(), UserId::default(), &KeyId);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn get_log_not_implemented() {
    let _result = get_log(Session::default(), UserId::default(), None);
}
