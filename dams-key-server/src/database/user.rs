//! Module for operations on users in the database.
//!
//! Functions in this module are used to perform CRUD operations
//! on the [`User`] model in the MongoDB database.

use dams::{
    config::opaque::OpaqueCipherSuite,
    models::{User, UserId},
};
use mongodb::{
    bson::{doc, oid::ObjectId},
    error::Error,
    Database,
};
use opaque_ke::ServerRegistration;

/// Create a new [`User`] with their authentication information and insert it into the MongoDB database.
pub async fn create_user(
    db: &Database,
    user_id: UserId,
    server_registration: ServerRegistration<OpaqueCipherSuite>,
) -> Result<Option<ObjectId>, Error> {
    let collection = db.collection::<User>("users");
    let new_user = User {
        user_id,
        secrets: Vec::new(),
        server_registration,
    };
    let insert_one_res = collection.insert_one(new_user, None).await?;
    Ok(insert_one_res.inserted_id.as_object_id())
}

/// Find a [`User`] by their `user_id`. This is different from the Mongo-assigned `_id` field.
pub async fn find_user(db: &Database, user_id: UserId) -> Result<Option<User>, Error> {
    let collection = db.collection::<User>("users");
    let query = doc! {"user_id": user_id.to_string()};
    let user = collection.find_one(query, None).await?;
    Ok(user)
}
