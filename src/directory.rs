//! The principals there are, as authd's identity socket lists them.
//!
//! Anyone may ask the identity socket, so the lists and every principal's
//! details are read there, by whoever is looking. lpsd's admin socket is
//! asked only for what changes the store, and whether this person may.
//!
//! Users and groups come from more than one source: authd's own well-known
//! principals and groups (SYSTEM, Administrators…), and the local ones lpsd
//! holds. A local principal's SID is under the machine's domain, `S-1-5-21-…`;
//! nothing else is lpsd's to change.

use libauthd::ident::{Fields, Key, Kind, Record, Value, WithheldReason};
use libauthd_client::ident::Ident;
use peios::security::SidRef;

/// What is read of every user for the list.
const USER_FIELDS: Fields = Fields(Fields::ENABLED.0 | Fields::DISPLAY_NAME.0 | Fields::UNIX_ID.0);
/// What is read of every group for the list.
const GROUP_FIELDS: Fields = Fields(Fields::UNIX_ID.0 | Fields::MEMBERS.0 | Fields::DESCRIPTION.0);

/// One user, as the list shows them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub sid: String,
    pub name: String,
    pub display_name: String,
    /// `None` where the source doesn't say.
    pub enabled: Option<bool>,
    pub local: bool,
}

/// One group, as the list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub sid: String,
    pub name: String,
    pub local: bool,
    pub members: Members,
    /// Empty where it has none, or its source doesn't say.
    pub description: String,
}

/// Who is in a group, as far as the list says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Members {
    /// This many, every one listed.
    Counted(usize),
    /// More than one answer holds: the details list them.
    Many,
    /// A rule the authority applies, such as everyone signed in, rather than
    /// a list anything keeps.
    Rule,
    /// Not said, and why.
    Unsaid(String),
}

/// Every user and group, as far as they could be read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Directory {
    pub users: Vec<User>,
    pub groups: Vec<Group>,
    /// The sources that didn't contribute, so a short list says it is one.
    pub incomplete: Vec<String>,
    /// Why the lists couldn't be read at all.
    pub trouble: Option<String>,
    /// This machine's services, by their SIDs, each derived from its name
    /// as authd derives it: what a policy record for a service is named by.
    pub services: Vec<(String, String)>,
}

impl Directory {
    /// The SID of the user or group called `name`, with or without its
    /// domain, in any case.
    pub fn sid_named(&self, name: &str) -> Option<&str> {
        let called = |listed: &str| listed.eq_ignore_ascii_case(name) || crate::accounts::short(listed).eq_ignore_ascii_case(name);
        let users = self.users.iter().filter(|user| called(&user.name)).map(|user| user.sid.as_str());
        let groups = self.groups.iter().filter(|group| called(&group.name)).map(|group| group.sid.as_str());
        users.chain(groups).next()
    }
}

/// A SID as it is written, or its bytes in hex where they aren't one.
pub fn sid_text(bytes: &[u8]) -> String {
    match SidRef::from_bytes(bytes) {
        Some(sid) => sid.to_string(),
        None => bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
    }
}

/// Whether the SID is a local principal's: one under a machine's domain,
/// which lpsd holds. The well-known ones are authd's.
pub fn local(sid: &str) -> bool {
    sid.starts_with("S-1-5-21-")
}

/// Whether the SID is a `BUILTIN` group's (`S-1-5-32-…`), whose members are
/// recorded on this machine rather than decided by a rule.
pub fn recorded(sid: &str) -> bool {
    sid.starts_with("S-1-5-32-")
}

fn enabled(record: &Record) -> Option<bool> {
    match record.value(Fields::ENABLED) {
        Some(Value::Enabled(enabled)) => Some(*enabled),
        _ => None,
    }
}

fn display_name(record: &Record) -> String {
    match record.value(Fields::DISPLAY_NAME) {
        Some(Value::DisplayName(name)) => name.clone(),
        _ => String::new(),
    }
}

/// What a group is for, or empty.
pub fn description(record: &Record) -> String {
    match record.value(Fields::DESCRIPTION) {
        Some(Value::Description(text)) => text.clone(),
        _ => String::new(),
    }
}

/// What a group's record says of its members.
pub fn members(record: &Record) -> Members {
    match (record.value(Fields::MEMBERS), record.reason(Fields::MEMBERS)) {
        (Some(Value::Members(members)), _) => Members::Counted(members.len()),
        (_, Some(WithheldReason::Absent)) => Members::Rule,
        (_, Some(WithheldReason::TooLarge)) => Members::Many,
        (_, Some(WithheldReason::Restricted)) => Members::Unsaid("You may not see who is in it.".into()),
        (_, Some(WithheldReason::Declined) | None) => Members::Unsaid("Its source doesn't say who is in it.".into()),
    }
}

/// The lists, from what the identity socket answered: users by name, then
/// groups, the well-known first, then the local, each by name.
pub fn from_records(users: Vec<Record>, groups: Vec<Record>, incomplete: Vec<String>) -> Directory {
    let mut users: Vec<User> = users
        .into_iter()
        .map(|record| {
            let sid = sid_text(&record.sid);
            User { local: local(&sid), enabled: enabled(&record), display_name: display_name(&record), name: record.qualified_name, sid }
        })
        .collect();
    users.sort_by_cached_key(|user| (user.name.to_lowercase(), user.sid.clone()));
    let mut groups: Vec<Group> = groups
        .into_iter()
        .map(|record| {
            let sid = sid_text(&record.sid);
            Group { local: local(&sid), members: members(&record), description: description(&record), name: record.qualified_name, sid }
        })
        .collect();
    groups.sort_by_cached_key(|group| (group.local, group.name.to_lowercase()));
    Directory { users, groups, incomplete, trouble: None, services: Vec::new() }
}

/// Reads every user and group, and the services there are.
pub fn read(ident: &Ident) -> Directory {
    let users = ident.enumerate(Kind::Principal, USER_FIELDS, None);
    let groups = ident.enumerate(Kind::Group, GROUP_FIELDS, None);
    let mut directory = match (users, groups) {
        (Ok(users), Ok(groups)) => {
            let mut incomplete = users.incomplete;
            for source in groups.incomplete {
                if !incomplete.contains(&source) {
                    incomplete.push(source);
                }
            }
            from_records(users.records, groups.records, incomplete)
        }
        (Err(e), _) | (_, Err(e)) => Directory { trouble: Some(format!("The principals could not be read: {e}.")), ..Directory::default() },
    };
    directory.services = services();
    directory
}

/// Where services are defined, one subkey each, named by the service.
const SERVICES: &str = "Machine\\System\\Services";

/// Each service there is, by its SID, and its name. A service whose key
/// can't be listed is simply not named: its records show their SIDs.
fn services() -> Vec<(String, String)> {
    let Ok(key) = peios::registry::Key::open(None, SERVICES, peios::registry::KeyAccess::ENUMERATE_SUB_KEYS, peios::registry::OpenFlags::empty()) else {
        return Vec::new();
    };
    key.subkeys(None)
        .filter_map(Result::ok)
        .filter_map(|subkey| String::from_utf8(subkey.name).ok())
        .filter_map(|name| Some((libauthd_policy::service_sid::of(&name)?.to_string(), name)))
        .collect()
}

/// One principal or group in full, by its SID.
pub fn details(ident: &Ident, sid: &str) -> Result<Record, String> {
    let bytes = sid.parse::<peios::security::Sid>().map_err(|_| format!("{sid} is not a SID."))?.as_bytes().to_vec();
    match ident.lookup(Key::Sid(bytes), Kind::Any, Fields::KNOWN) {
        Ok(Some(record)) => Ok(record),
        Ok(None) => Err("There is nobody by this SID any more.".into()),
        Err(e) => Err(format!("It could not be read: {e}.")),
    }
}

/// A group's members, when there are more than one answer holds.
pub fn all_members(ident: &Ident, sid: &str) -> Result<Vec<Record>, String> {
    let bytes = sid.parse::<peios::security::Sid>().map_err(|_| format!("{sid} is not a SID."))?.as_bytes().to_vec();
    ident.enumerate(Kind::Principal, Fields::empty(), Some(Key::Sid(bytes))).map(|listing| listing.records).map_err(|e| format!("Its members could not be read: {e}."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use libauthd::ident::{Reference, Withheld};

    fn sid(text: &str) -> Vec<u8> {
        text.parse::<peios::security::Sid>().unwrap().as_bytes().to_vec()
    }

    fn record(name: &str, at: &str, kind: Kind, values: Vec<Value>, withheld: Vec<Withheld>) -> Record {
        Record { sid: sid(at), qualified_name: name.into(), kind_found: kind, values, withheld }
    }

    #[test]
    fn users_and_groups_are_listed_by_name_and_the_local_ones_are_known() {
        let users = vec![
            record("dana", "S-1-5-21-1-2-3-1002", Kind::Principal, vec![Value::DisplayName("Dana Scully".into()), Value::Enabled(true)], vec![]),
            record("SYSTEM", "S-1-5-18", Kind::Principal, vec![], vec![]),
            record("alice", "S-1-5-21-1-2-3-1001", Kind::Principal, vec![Value::Enabled(false)], vec![]),
        ];
        let groups = vec![
            record("staff", "S-1-5-21-1-2-3-1100", Kind::Group, vec![Value::Members(vec![Reference::default(), Reference::default()]), Value::Description("Everyone who works here".into())], vec![]),
            record("Everyone", "S-1-1-0", Kind::Group, vec![], vec![Withheld { field: Fields::MEMBERS, reason: WithheldReason::Absent }]),
            record("Administrators", "S-1-5-32-544", Kind::Group, vec![], vec![Withheld { field: Fields::MEMBERS, reason: WithheldReason::TooLarge }]),
        ];
        let directory = from_records(users, groups, vec![]);
        let names: Vec<&str> = directory.users.iter().map(|user| user.name.as_str()).collect();
        assert_eq!(names, ["alice", "dana", "SYSTEM"]);
        assert!(directory.users[1].local && !directory.users[2].local);
        assert_eq!(directory.users[0].enabled, Some(false));
        assert_eq!(directory.users[1].display_name, "Dana Scully");
        let groups: Vec<(&str, &Members)> = directory.groups.iter().map(|group| (group.name.as_str(), &group.members)).collect();
        assert_eq!(groups, [("Administrators", &Members::Many), ("Everyone", &Members::Rule), ("staff", &Members::Counted(2))]);
        assert_eq!(directory.groups[2].description, "Everyone who works here");
        assert_eq!(directory.groups[0].description, "");
    }
}
