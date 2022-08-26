//! Module for operations on users in the database.
//!
//! Functions in this module are used to perform CRUD operations
//! on the [`User`] model in the MongoDB database.

use crate::constants;
use dams::{
    config::opaque::OpaqueCipherSuite,
    user::{AccountName, User, UserId},
};
use mongodb::{
    bson::{doc, oid::ObjectId},
    error::Error,
    Database,
};
use opaque_ke::ServerRegistration;

/// Create a new [`User`] with their authentication information and insert it
/// into the MongoDB database.
///
/// TODO: add constraint that user id and account name are both unique.
pub async fn create_user(
    db: &Database,
    user_id: &UserId,
    account_name: &AccountName,
    server_registration: ServerRegistration<OpaqueCipherSuite>,
) -> Result<Option<ObjectId>, Error> {
    let collection = db.collection::<User>(constants::USERS);
    let new_user = User::new(user_id.clone(), account_name.clone(), server_registration);
    let insert_one_res = collection.insert_one(new_user, None).await?;
    Ok(insert_one_res.inserted_id.as_object_id())
}

/// Find a [`User`] by their human-readable [`AccountName`].
pub async fn find_user(db: &Database, account_name: &AccountName) -> Result<Option<User>, Error> {
    let collection = db.collection::<User>(constants::USERS);
    let query = doc! {"account_name": account_name.to_string()};
    let user = collection.find_one(query, None).await?;
    Ok(user)
}
