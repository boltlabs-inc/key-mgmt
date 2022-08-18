use dams::user::UserId;
use std::str::FromStr;
use tonic::Status;

pub mod authenticate;
pub mod register;

pub(crate) fn user_id_from_message(message: &[u8]) -> Result<UserId, Status> {
    UserId::from_str(
        std::str::from_utf8(message).map_err(|_| Status::aborted("Unable to convert to UserID"))?,
    )
    .map_err(|_| Status::aborted("Unable to convert to UserID"))
}
