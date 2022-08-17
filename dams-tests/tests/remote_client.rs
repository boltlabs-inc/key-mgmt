use dams::blockchain::Blockchain;
use dams::keys::{KeyId, KeyMaterial, SharedControl, UserId};
use dams::transaction::TransactionApprovalRequest;
use dams_remote_client::api::*;

#[test]
#[should_panic(expected = "not yet implemented")]
fn register_user_not_implemented() {
    let _result = register_user(UserId);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn create_key_not_implemented() {
    let _result = create_key(UserId, Blockchain::EVM, SharedControl);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn import_key_not_implemented() {
    let key_material = KeyMaterial::default();
    let _result = import_key(UserId, key_material, Blockchain::EVM, SharedControl);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn export_key_not_implemented() {
    let _result = export_key(UserId, &KeyId);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn sign_transaction_not_implemented() {
    let tar = TransactionApprovalRequest::default();
    let _result = sign_transaction(tar);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn get_keys_not_implemented() {
    let _result = get_keys(UserId);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn get_key_by_id_not_implemented() {
    let _result = get_key_by_id(UserId, &KeyId);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn get_log_not_implemented() {
    let _result = get_log(UserId, None);
}
