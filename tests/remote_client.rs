use da_mgmt::blockchain::Blockchain;
use da_mgmt::{
    keys::{KeyId, KeyMaterial, SharedControl, UserId},
    remote_client::*,
    transaction::TransactionApprovalRequest,
};

#[test]
#[should_panic(expected = "not yet implemented")]
fn register_passive_user_not_implemented() {
    let _result = register_passive_user(UserId::default());
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn create_passive_digital_asset_key_not_implemented() {
    let _result =
        create_passive_digital_asset_key(UserId::default(), Blockchain::EVM, SharedControl);
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn import_key_not_implemented() {
    let key_material = KeyMaterial::default();
    let _result = import_asset_key(
        UserId::default(),
        key_material,
        Blockchain::EVM,
        SharedControl,
    );
}

#[test]
#[should_panic(expected = "not yet implemented")]
fn export_key_not_implemented() {
    let _result = export_asset_key(UserId::default(), &KeyId);
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
