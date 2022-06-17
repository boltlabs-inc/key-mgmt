use key_mgmt::{
    keys::{KeyId, SelfCustodial, SharedControl, UserId, UserPolicySpecification},
    localclient::*,
    transaction::TransactionApprovalRequest,
};

#[test]
#[should_panic(expected = "not yet implemented")]
fn open_session_not_implemented() {
    let _result = Session::open(UserId, Password, &SessionConfig);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn register_session_not_implemented() {
    let _result = Session::register(UserId, Password, &SessionConfig);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn close_session_not_implemented() {
    let session = Session::register(UserId, Password, &SessionConfig).unwrap();
    let _result = session.close();
}

fn default_session() -> Session {
    Session::register(UserId, Password, &SessionConfig).unwrap()
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn create_digital_asset_key_not_implemented() {
    let _result = create_digital_asset_key(
        default_session(),
        UserId,
        None,
        SelfCustodial::default(),
        SharedControl,
    );
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn set_user_key_policy_not_implemented() {
    let _result = set_user_key_policy(default_session(), UserId, KeyId, UserPolicySpecification);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn request_transaction_signature_not_implemented() {
    let tar = TransactionApprovalRequest::default();
    let _result = request_transaction_signature(default_session(), tar);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn retrieve_public_keys_not_implemented() {
    let _result = retrieve_public_keys(default_session(), UserId);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn retrieve_public_key_by_id_not_implemented() {
    let _result = retrieve_public_key_by_id(default_session(), UserId, &KeyId);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn retrieve_audit_log_not_implemented() {
    let _result = retrieve_audit_log(default_session(), UserId, None);
}
