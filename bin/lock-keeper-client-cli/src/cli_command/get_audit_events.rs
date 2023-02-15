use std::{
    str::FromStr,
    time::{Duration, SystemTime},
};

use crate::{cli_command::CliCommand, state::State};
use anyhow::{anyhow, Error};
use async_trait::async_trait;
use lock_keeper::types::audit_event::{AuditEventOptions, EventType};
use lock_keeper_client::LockKeeperClient;
use time::{format_description::well_known::Iso8601, OffsetDateTime};
use uuid::Uuid;

#[derive(Debug)]
pub struct GetAuditEvents {
    event_type: EventType,
    key_names: Vec<String>,
    request_id: Option<Uuid>,
    before_date: Option<OffsetDateTime>,
    after_date: Option<OffsetDateTime>,
}

#[async_trait]
impl CliCommand for GetAuditEvents {
    async fn execute(self: Box<Self>, state: &mut State) -> Result<Duration, Error> {
        let mut key_ids = Vec::new();
        for key_name in self.key_names {
            key_ids.push(state.get_key_id(&key_name)?.key_id.clone());
        }

        let options = AuditEventOptions {
            key_ids,
            request_id: self.request_id,
            before_date: self.before_date,
            after_date: self.after_date,
        };

        let credentials = state.get_credentials()?;

        // Authenticate user to the key server
        let lock_keeper_client = LockKeeperClient::authenticated_client(
            &credentials.account_name,
            &credentials.password,
            &state.config,
        )
        .await
        .result?;

        let now = SystemTime::now();
        // If successful, proceed to generate a secret with the established session
        let audit_event_log = lock_keeper_client
            .retrieve_audit_event_log(self.event_type, options)
            .await
            .result?;
        let elapsed = now.elapsed()?;

        println!("Audit Events:");
        for event in audit_event_log {
            println!("----------------------------------");
            println!("{event}");
        }
        println!("----------------------------------");

        Ok(elapsed)
    }

    fn parse_command_args(slice: &[&str]) -> Option<Self> {
        match slice {
            [] => Some(GetAuditEvents {
                event_type: EventType::All,
                key_names: vec![],
                request_id: None,
                before_date: None,
                after_date: None,
            }),
            options => {
                let mut result = GetAuditEvents {
                    event_type: EventType::All,
                    key_names: vec![],
                    request_id: None,
                    before_date: None,
                    after_date: None,
                };

                for option in options {
                    let parsed_option = match parse_option(option) {
                        Ok(p) => p,
                        _ => return None,
                    };

                    match parsed_option {
                        ParsedAuditEventOption::EventType(event_type) => {
                            result.event_type = event_type;
                        }
                        ParsedAuditEventOption::KeyNames(key_names) => {
                            result.key_names = key_names;
                        }
                        ParsedAuditEventOption::RequestId(request_id) => {
                            result.request_id = Some(request_id);
                        }
                        ParsedAuditEventOption::BeforeDate(before) => {
                            result.before_date = Some(before);
                        }
                        ParsedAuditEventOption::AfterDate(before) => {
                            result.after_date = Some(before);
                        }
                    }
                }

                Some(result)
            }
        }
    }

    fn format() -> &'static str {
        "audit [query_options (see help)]"
    }

    fn aliases() -> Vec<&'static str>
    where
        Self: Sized,
    {
        vec!["audit"]
    }

    fn description() -> &'static str
    where
        Self: Sized,
    {
        "Retrieves audit events for the authenticated user.
         Additional query options are available with the following commands.
         Options:
            - type:event_type (all, key-only, system-only)
            - keys:key_name1,key_name_2
            - request-id:uuid
        "
    }
}

fn parse_option(text: &str) -> Result<ParsedAuditEventOption, Error> {
    const ERROR_MESSAGE: &str = "Invalid audit event option";

    let mut option_split = text.splitn(2, ':');

    let option_name = option_split.next().ok_or_else(|| anyhow!(ERROR_MESSAGE))?;
    let option_value = option_split.next().ok_or_else(|| anyhow!(ERROR_MESSAGE))?;

    match option_name {
        "type" => Ok(ParsedAuditEventOption::EventType(EventType::from_str(
            option_value,
        )?)),
        "keys" | "key" => {
            let key_names: Vec<String> = option_value.split(',').map(ToString::to_string).collect();
            Ok(ParsedAuditEventOption::KeyNames(key_names))
        }
        "request-id" => Ok(ParsedAuditEventOption::RequestId(option_value.parse()?)),
        "before" => Ok(ParsedAuditEventOption::BeforeDate(parse_date(
            option_value,
        )?)),
        "after" => Ok(ParsedAuditEventOption::AfterDate(parse_date(option_value)?)),
        _ => anyhow::bail!(ERROR_MESSAGE),
    }
}

fn parse_date(date_str: &str) -> Result<OffsetDateTime, Error> {
    match OffsetDateTime::parse(date_str, &Iso8601::DEFAULT) {
        Ok(date) => Ok(date),
        Err(_) => {
            let iso_format = format!("{date_str}T00:00:00Z");
            match OffsetDateTime::parse(&iso_format, &Iso8601::DEFAULT) {
                Ok(date) => Ok(date),
                Err(e) => Err(anyhow!("Invalid date format {:?}", e)),
            }
        }
    }
}

enum ParsedAuditEventOption {
    EventType(EventType),
    KeyNames(Vec<String>),
    RequestId(Uuid),
    BeforeDate(OffsetDateTime),
    AfterDate(OffsetDateTime),
}
