pub(crate) mod common;

use da_mgmt::transport::KeyMgmtAddress;
use da_mgmt::{
    blockchain::Blockchain,
    client,
    keys::{KeyId, SelfCustodial, SharedControl, UserId, UserPolicySpecification},
    local_client::*,
    transaction::TransactionApprovalRequest,
};
use std::fs::File;
use std::path::PathBuf;
use std::str::FromStr;

#[tokio::test]
async fn test_session() {
    let server_future = common::setup().await;
    test_register_session().await;
    test_open_session().await;
    common::teardown(server_future).await;
}

async fn test_open_session() {
    let client_config = client::Config::load(common::CLIENT_CONFIG)
        .await
        .expect("Failed to load client config");
    let config = SessionConfig {
        client_config,
        server: KeyMgmtAddress::from_str("keymgmt://localhost").unwrap(),
    };
    let _ = Session::register(
        UserId("test_user".to_string()),
        Password::default(),
        &config,
    )
    .await;
    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
    let result = Session::open(
        UserId("test_user".to_string()),
        Password::default(),
        &config,
    )
    .await;
    assert!(result.is_ok());
}

async fn test_register_session() {
    let client_config = client::Config::load(common::CLIENT_CONFIG)
        .await
        .expect("Failed to load client config");
    let config = SessionConfig {
        client_config,
        server: KeyMgmtAddress::from_str("keymgmt://localhost").unwrap(),
    };
    let result = Session::register(
        UserId("test_user".to_string()),
        Password::default(),
        &config,
    )
    .await;
    assert!(result.is_ok());
    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
    assert!(File::open(
        PathBuf::from_str("tests/gen/opaque")
            .unwrap()
            .join("test_user")
    )
    .is_ok());
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn close_session_not_implemented() {
    let session = Session {
        config: SessionConfig::default(),
        session_key: [0; 64],
    };
    let _result = session.close();
}

fn default_session() -> Session {
    Session {
        config: SessionConfig::default(),
        session_key: [0; 64],
    }
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
