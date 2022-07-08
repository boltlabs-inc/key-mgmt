pub(crate) mod common;

use da_mgmt::local_client::{
    create_digital_asset_key, request_transaction_signature, retrieve_audit_log,
    retrieve_public_key_by_id, retrieve_public_keys, set_user_key_policy, Session, SessionConfig,
};
use da_mgmt::{
    blockchain::Blockchain,
    keys::{KeyId, SelfCustodial, SharedControl, UserId, UserPolicySpecification},
    transaction::TransactionApprovalRequest,
};

fn default_session() -> Session {
    Session::new(SessionConfig::default(), [0; 64])
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn close_session_not_implemented() {
    let session = default_session();
    let _result = session.close();
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn create_digital_asset_key_not_implemented() {
    let _result = create_digital_asset_key(
        default_session(),
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
        default_session(),
        UserId::default(),
        KeyId,
        UserPolicySpecification,
    );
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
    let _result = retrieve_public_keys(default_session(), UserId::default());
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn retrieve_public_key_by_id_not_implemented() {
    let _result = retrieve_public_key_by_id(default_session(), UserId::default(), &KeyId);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn retrieve_audit_log_not_implemented() {
    let _result = retrieve_audit_log(default_session(), UserId::default(), None);
}
