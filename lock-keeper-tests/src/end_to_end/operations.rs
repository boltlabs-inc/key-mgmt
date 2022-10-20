use lock_keeper::types::{audit_event::EventStatus, operations::ClientAction};
use lock_keeper_client::client::Password;

pub mod authenticate;
pub mod export;
pub mod generate;
pub mod import;
pub mod register;
pub mod remote_generate;
pub mod retrieve;

/// Set of operations that can be executed by the test harness
#[allow(unused)]
#[derive(Debug)]
pub enum Operation {
    Authenticate(Option<Password>),
    Export,
    ExportSigningKey,
    Generate,
    ImportSigningKey,
    Register,
    RemoteGenerate,
    Retrieve,
    SetFakeKeyId,
}

impl Operation {
    pub fn to_final_client_action(&self, status: &EventStatus) -> Option<ClientAction> {
        match self {
            Self::Authenticate(_) => {
                if status == &EventStatus::Failed {
                    None
                } else {
                    Some(ClientAction::Authenticate)
                }
            }
            Self::Export => Some(ClientAction::Export),
            Self::ExportSigningKey => Some(ClientAction::ExportSigningKey),
            Self::Generate => Some(ClientAction::Generate),
            Self::ImportSigningKey => Some(ClientAction::ImportSigningKey),
            Self::Register => {
                if status == &EventStatus::Successful {
                    Some(ClientAction::CreateStorageKey)
                } else {
                    Some(ClientAction::Register)
                }
            }
            Self::RemoteGenerate => Some(ClientAction::RemoteGenerate),
            Self::Retrieve => Some(ClientAction::Retrieve),
            Self::SetFakeKeyId => None,
        }
    }
}
