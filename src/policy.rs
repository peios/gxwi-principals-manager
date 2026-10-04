//! Privileges: what this machine grants each principal, from the policy key
//! authd reads at every sign-in (`Machine\Generic\Authn\Policy`), and what
//! that comes to for a person.
//!
//! The key is read, and what it comes to worked out, by libauthd-policy, the
//! code authd mints from, so what this window says someone gets is what authd
//! would give them, and a record authd ignores is shown as ignored. It is
//! changed in the registry directly, as whoever is looking: the key's own
//! descriptor decides who may, not lpsd.
//!
//! A record is keyed, and an owner named, as authd reads them: a well-known
//! name or a SID. A local user or group is named by its SID, since authd
//! can't ask lpsd what a name means.

use libauthd::wire::LogonType;
use libauthd_policy::write::{self, Draft};
use libauthd_policy::{Policy, Record, TIERS, well_known};
use libgxwi::{Fields, escape};
use peios::security::{IntegrityLevel, Privileges, Sid, SidRef};

use crate::accounts::{Doing, form};
use crate::directory::Directory;
use crate::words;

/// What the list's first row is picked as: the privileges denied to everyone.
pub const DENIED: &str = "denied";

/// What a principal is called: its well-known name, its name here, or its
/// SID.
pub fn called(sid: &SidRef, directory: &Directory) -> String {
    let text = sid.to_string();
    if let Some(name) = well_known::name_of(sid) {
        return name.to_string();
    }
    let user = directory.users.iter().find(|user| user.sid == text).map(|user| user.name.clone());
    let group = directory.groups.iter().find(|group| group.sid == text).map(|group| group.name.clone());
    let service = directory.services.iter().find(|(sid, _)| *sid == text).map(|(_, name)| format!("The {name} service"));
    user.or(group).or(service).unwrap_or(text)
}

/// The record a list row or link picks, by its SID.
fn record<'a>(policy: &'a Policy, picked: &str) -> Option<&'a Record> {
    let sid: Sid = picked.parse().ok()?;
    policy.record(sid.as_ref())
}

fn count(privileges: Option<Privileges>) -> String {
    match privileges {
        None => String::new(),
        Some(privileges) => words::count(privileges.canonical_names().count(), "privilege"),
    }
}

/// What a record says besides its privileges and integrity, for the list.
fn also(record: &Record) -> String {
    let mut said = Vec::new();
    if record.owner.is_some() {
        said.push("Owner");
    }
    if record.default_dacl.is_some() {
        said.push("Default DACL");
    }
    if record.logon_types.is_some() {
        said.push("Sign-ins it may ask for");
    }
    said.join(", ")
}

/// Above the list: whether the key is there, and what in it authd ignores.
pub fn notes(policy: &Policy) -> String {
    let mut notes = String::new();
    if !policy.configured {
        notes += "<p class=\"said\" role=\"status\">This machine has no policy key, so authd grants what it has built in: Everyone may pass through folders \
                  (SeChangeNotifyPrivilege), and nobody gets anything more. Saving a record makes the key, with that in it, since once the key is there \
                  it is the whole policy.</p>";
    }
    for problem in &policy.problems {
        // Each problem says what authd does about it: ignores a record, or
        // applies two where one was meant.
        notes += &format!("<p class=\"said bad\" role=\"alert\">authd warns: {}</p>", escape(problem));
    }
    notes
}

/// The list: the privileges denied to everyone, then each record.
pub fn listing(policy: &Policy, directory: &Directory, picked: Option<&str>, matches: impl Fn(&[&str]) -> bool) -> String {
    let row = |at: &str, name: &str, privileges: &str, level: &str, also: &str| {
        format!(
            "<li><button type=\"button\" fx-click=\"pick-record\" fx-value-record=\"{at}\" aria-selected=\"{picked}\">\
             <span class=\"name\">{name}</span><span class=\"privs\">{privileges}</span><span class=\"level\">{level}</span><span class=\"also\">{also}</span></button></li>",
            at = escape(at),
            picked = picked == Some(at),
            name = escape(name),
            privileges = escape(privileges),
            level = escape(level),
            also = escape(also),
        )
    };
    let mut rows = String::new();
    if matches(&["Denied to everyone"]) {
        rows += &row(DENIED, "Denied to everyone", &count(Some(policy.denied)), "", "");
    }
    for record in &policy.records {
        let name = called(record.sid.as_ref(), directory);
        let sid = record.sid.to_string();
        if !matches(&[&name, &sid, &record.name]) {
            continue;
        }
        rows += &row(&sid, &name, &count(record.privileges), &record.integrity.map(words::integrity).unwrap_or_default(), &also(record));
    }
    if rows.is_empty() {
        return "<p class=\"more\">Nothing matches.</p>".into();
    }
    format!("<ul class=\"entries\">{rows}</ul>")
}

/// Privileges as a list, each with what it lets its holder do, and marked
/// where it is denied to everyone.
fn privileges_list(privileges: Privileges, denied: Privileges) -> String {
    if privileges.is_empty() {
        return "<p class=\"more\">None.</p>".into();
    }
    let rows: String = Privileges::all_named()
        .filter(|(_, privilege)| privileges.contains(*privilege))
        .map(|(name, privilege)| {
            let off = if denied.contains(privilege) { "<span class=\"denied\">Denied to everyone, so not granted</span>" } else { "" };
            format!("<li><code>{}</code><span class=\"what\">{}</span>{off}</li>", escape(name), escape(words::privilege(name)))
        })
        .collect();
    format!("<ul class=\"privileges\">{rows}</ul>")
}

/// The picked record, or the privileges denied to everyone, in full.
/// `may` is whether this person may change the policy; `doing` and `asking`
/// what is happening in the pane.
pub fn details(policy: &Policy, directory: &Directory, picked: &str, may: &Result<(), String>, said: &str, doing: &Doing) -> String {
    let button = |event: &str, label: &str| format!("<button type=\"button\" fx-click=\"{event}\">{label}</button>");
    let may_note = match may {
        Ok(()) => String::new(),
        Err(why) => format!("<p class=\"may\">{}</p>", escape(why)),
    };
    if picked == DENIED {
        let actions = if may.is_ok() { button("edit-denied", "Edit") } else { String::new() };
        return format!(
            "<aside class=\"details\" aria-label=\"Details\"><h2>Denied to everyone</h2>\
             <p class=\"about\">No record can grant these. They are taken from every token after everything else, so one edit here outweighs every record.</p>\
             <p class=\"actions\">{actions}</p>{said}{may_note}<h3>Privileges</h3>{}</aside>",
            privileges_list(policy.denied, Privileges::empty()),
        );
    }
    let Some(record) = record(policy, picked) else {
        return format!("<aside class=\"details\" aria-label=\"Details\">{said}<p class=\"more\">There is no record for it now.</p></aside>");
    };
    let sid = record.sid.to_string();
    let row = |name: &str, value: &str| format!("<dt>{name}</dt><dd>{value}</dd>");
    let not_said = "<span class=\"unsaid\">Not said</span>";
    let mut facts = row("Record", &format!("<code>{}</code>", escape(&record.name)));
    facts += &row("SID", &format!("<code>{}</code>", escape(&sid)));
    facts += &row("Integrity", &record.integrity.map_or_else(|| not_said.to_string(), |level| escape(&words::integrity(level))));
    facts += &row("Owner of what they make", &record.owner.map_or_else(|| not_said.to_string(), |owner| escape(&called(owner.as_ref(), directory))));
    facts += &row(
        "Default DACL",
        &record.default_dacl.as_ref().map_or_else(|| not_said.to_string(), |dacl| format!("<code>{}</code>", escape(&dacl.sddl))),
    );
    let mut sections = String::from("<h3>Privileges</h3>");
    sections += &match record.privileges {
        None => "<p class=\"more\">Not said: this record grants none.</p>".to_string(),
        Some(privileges) => privileges_list(privileges, policy.denied),
    };
    if let Some(types) = record.logon_types {
        let asked: Vec<&str> = libauthd_policy::LOGON_TYPE_NAMES.iter().filter(|(_, logon_type)| types.bits() & (1 << *logon_type as u32) != 0).map(|(name, _)| *name).collect();
        sections += "<h3>Sign-ins it may ask authd for</h3>";
        sections += &if asked.is_empty() {
            "<p class=\"more\">None.</p>".to_string()
        } else {
            format!("<ul class=\"plain\">{}</ul>", asked.iter().map(|name| format!("<li>{}</li>", escape(name))).collect::<String>())
        };
    }
    let known = directory.users.iter().any(|user| user.sid == sid) || directory.groups.iter().any(|group| group.sid == sid);
    let mut actions = String::new();
    if may.is_ok() {
        actions += &button("edit-record", "Edit");
        actions += "<button type=\"button\" class=\"danger\" fx-click=\"delete-record\">Delete</button>";
    }
    if known {
        actions += &format!("<button type=\"button\" fx-click=\"show\" fx-value-sid=\"{}\">Show the principal</button>", escape(&sid));
    }
    let asking = if *doing == Doing::RecordDeleting && may.is_ok() {
        format!(
            "<div class=\"asking\" role=\"alertdialog\" aria-label=\"Delete the record\"><p>Delete the record for <strong>{}</strong>? \
             What it grants is no longer granted from their next sign-in.</p>\
             <button type=\"button\" class=\"danger\" fx-click=\"delete-record-yes\">Delete</button>\
             <button type=\"button\" fx-click=\"cancel\" fx-key=\"Escape\" fx-autofocus>Cancel</button></div>",
            escape(&called(record.sid.as_ref(), directory)),
        )
    } else {
        String::new()
    };
    format!(
        "<aside class=\"details\" aria-label=\"Details\"><h2>{}</h2><dl>{facts}</dl><p class=\"actions\">{actions}</p>{said}{asking}{may_note}{sections}</aside>",
        escape(&called(record.sid.as_ref(), directory)),
    )
}

/// Fills the form from `draft`: what a record says now, or nothing.
pub fn fill(draft: &Draft, principal: &str, fields: &mut Fields) {
    fields.set("principal", principal);
    for (index, (_, privilege)) in Privileges::all_named().enumerate() {
        let on = draft.privileges.is_some_and(|privileges| privileges.contains(privilege));
        fields.set(&format!("priv-{index}"), if on { "on" } else { "" });
    }
    fields.set(
        "integrity",
        &match draft.integrity {
            None => String::new(),
            Some(level) => libauthd_policy::tier_name(level).map_or_else(|| level.0.to_string(), str::to_string),
        },
    );
    fields.set("owner", draft.owner.as_deref().unwrap_or(""));
    fields.set("dacl", draft.default_dacl.as_deref().unwrap_or(""));
}

/// The privileges ticked, or `None` for none: a record granting none says
/// nothing, which grants the same.
fn ticked(fields: &Fields) -> Option<Privileges> {
    let privileges = Privileges::all_named()
        .enumerate()
        .filter(|(index, _)| !fields.get(&format!("priv-{index}")).is_empty())
        .fold(Privileges::empty(), |privileges, (_, (_, privilege))| privileges | privilege);
    (!privileges.is_empty()).then_some(privileges)
}

fn checkboxes(denied: Privileges) -> String {
    Privileges::all_named()
        .enumerate()
        .map(|(index, (name, privilege))| {
            let off = if denied.contains(privilege) { " <span class=\"denied\">Denied to everyone</span>" } else { "" };
            format!(
                "<label class=\"check privilege\"><input type=\"checkbox\" name=\"priv-{index}\"><span><code>{}</code>{off}<small>{}</small></span></label>",
                escape(name),
                escape(words::privilege(name)),
            )
        })
        .collect()
}

/// The form for a new record, the picked one, or the privileges denied to
/// everyone. A record's integrity between the tiers is offered as it is, so
/// saving keeps it.
pub fn render(doing: &Doing, policy: &Policy, directory: &Directory, picked: Option<&str>, said: &str) -> String {
    match doing {
        Doing::EditDenied => form(
            "Privileges denied to everyone",
            "Denied to everyone",
            "",
            &format!(
                "<p class=\"hint\">No record can grant what is ticked here: it is taken from every token after everything else.</p>\
                 <fieldset class=\"choice\"><legend>Privileges</legend>{}</fieldset>{said}",
                checkboxes(Privileges::empty())
            ),
            "Save",
        ),
        Doing::NewRecord | Doing::EditRecord => {
            let editing = picked.and_then(|picked| record(policy, picked)).filter(|_| *doing == Doing::EditRecord);
            let principal = match editing {
                Some(_) => String::new(),
                None => "<label>For<input name=\"principal\" autocomplete=\"off\" spellcheck=\"false\" fx-autofocus></label>\
                         <p class=\"hint\">A user or group here, a well-known name such as Everyone or Network, or a SID.</p>"
                    .to_string(),
            };
            let between = editing
                .and_then(|record| record.integrity)
                .filter(|level| libauthd_policy::tier_name(*level).is_none())
                .map(|level| format!("<option value=\"{}\">Level {} (as it is)</option>", level.0, level.0))
                .unwrap_or_default();
            let tiers: String = TIERS.iter().map(|(name, _)| format!("<option value=\"{name}\">{name}</option>")).collect();
            let body = format!(
                "{principal}<fieldset class=\"choice\"><legend>Privileges</legend>{checkboxes}</fieldset>\
                 <label>Integrity<select name=\"integrity\"><option value=\"\">Not said</option>{tiers}{between}</select></label>\
                 <p class=\"hint\">Their own record's level wins; otherwise the highest of their groups', or Medium.</p>\
                 <label>Owner of what they make<input name=\"owner\" autocomplete=\"off\" spellcheck=\"false\" placeholder=\"Themselves\"></label>\
                 <p class=\"hint\">A user or group here, a well-known name such as Administrators, or a SID. Empty, what they make is theirs.</p>\
                 <label>Default DACL<textarea name=\"dacl\" rows=\"3\" spellcheck=\"false\" placeholder=\"Not said\"></textarea></label>\
                 <p class=\"hint\">SDDL, such as <code>D:(A;;GA;;;OW)(A;;GA;;;SY)(A;;GA;;;BA)</code>: what an object they make gets when it has no parent to inherit from.</p>{said}",
                checkboxes = checkboxes(policy.denied),
            );
            match editing {
                Some(record) => form("Change the record", &called(record.sid.as_ref(), directory), &format!("Record {}", record.name), &body, "Save"),
                None => form("A new record", "New record", "", &body, "Create"),
            }
        }
        _ => String::new(),
    }
}

/// A user, group or well-known principal named as a person would, as the
/// SID a record or an owner is written with.
fn named(text: &str, directory: &Directory) -> Option<Sid> {
    let text = text.trim();
    libauthd_policy::resolve(text).or_else(|| directory.sid_named(text)?.parse().ok())
}

/// The draft the form describes.
pub fn draft(fields: &Fields, directory: &Directory) -> Result<Draft, String> {
    let integrity = match fields.get("integrity").trim() {
        "" => None,
        text => Some(libauthd_policy::tier(text).or_else(|| text.parse().ok().map(IntegrityLevel)).ok_or_else(|| format!("{text} is not an integrity level."))?),
    };
    let owner = match fields.get("owner").trim() {
        "" => None,
        text => Some(write::record_name(named(text, directory).ok_or_else(|| format!("{text} is not a user, a group or a SID."))?.as_ref())),
    };
    let dacl = fields.get("dacl").trim();
    let draft = Draft { privileges: ticked(fields), integrity, owner, default_dacl: (!dacl.is_empty()).then(|| dacl.to_string()) };
    draft.check()?;
    Ok(draft)
}

/// Why saving `draft` for the record `sid` deserves asking about first, if
/// it does: a record for Everyone or Administrators that no longer grants
/// passing through folders, without which no shell starts.
pub fn risk(sid: &SidRef, draft: &Draft, policy: &Policy) -> Option<String> {
    let guarded = ["Everyone", "Administrators"].into_iter().find(|name| well_known::by_name(name).is_some_and(|known| known.as_ref().as_bytes() == sid.as_bytes()))?;
    let had = policy.record(sid).and_then(|record| record.privileges).is_some_and(|privileges| privileges.contains(Privileges::CHANGE_NOTIFY));
    let has = draft.privileges.is_some_and(|privileges| privileges.contains(Privileges::CHANGE_NOTIFY));
    (had && !has).then(|| {
        format!(
            "Without SeChangeNotifyPrivilege on {guarded}, nobody who gets it only from there can pass through folders, so no shell starts for them. \
             Administrators keep it on their own record so that someone can put it back."
        )
    })
}

/// Saves the form: a new record, or the picked one. Answers what was done,
/// or why not.
pub fn save(doing: &Doing, policy: &Policy, directory: &Directory, picked: Option<&str>, fields: &Fields, asked: bool) -> Result<Saved, String> {
    let draft = draft(fields, directory)?;
    let sid = match doing {
        Doing::EditRecord => picked.and_then(|picked| record(policy, picked)).map(|record| record.sid).ok_or("There is no record for it now.")?,
        _ => {
            let text = fields.get("principal").trim();
            if text.is_empty() {
                return Err("Say who the record is for.".into());
            }
            let sid = named(text, directory).ok_or_else(|| format!("{text} is not a user, a group, a well-known name or a SID."))?;
            if policy.configured && policy.record(sid.as_ref()).is_some() {
                return Err(format!("There is a record for {} already. Change that one instead.", called(sid.as_ref(), directory)));
            }
            sid
        }
    };
    if !asked && let Some(why) = risk(sid.as_ref(), &draft, policy) {
        return Ok(Saved::Ask(why));
    }
    let name = match doing {
        Doing::EditRecord => policy.record(sid.as_ref()).map_or_else(|| write::record_name(sid.as_ref()), |record| record.name.clone()),
        _ => write::record_name(sid.as_ref()),
    };
    write::save(&name, &draft)?;
    Ok(Saved::Done(sid.to_string(), format!("The record for {} is saved. It applies from their next sign-in.", called(sid.as_ref(), directory))))
}

/// What came of saving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Saved {
    /// Saved: the record's SID, and what was done.
    Done(String, String),
    /// Not yet: why it is worth asking about first.
    Ask(String),
}

/// Saves the privileges denied to everyone.
pub fn save_denied(fields: &Fields) -> Result<String, String> {
    write::set_denied(ticked(fields))?;
    Ok("What is denied to everyone is saved. It applies from each next sign-in.".into())
}

/// The form's fields for the privileges denied to everyone.
pub fn fill_denied(policy: &Policy, fields: &mut Fields) {
    fill(&Draft { privileges: Some(policy.denied), ..Draft::default() }, "", fields);
}

/// What policy comes to for someone carrying `user` and `groups`, signed in
/// as `logon` (one of [`words::SIGN_INS`]'s values), with the records it
/// comes from, each a link to it.
pub fn effective(policy: &Policy, directory: &Directory, user: &SidRef, groups: &[Sid], logon: &str) -> String {
    let (logon_type, choices) = {
        let chosen = words::SIGN_INS.iter().find(|(value, _, _)| *value == logon).map_or(LogonType::Interactive, |(_, logon_type, _)| *logon_type);
        let choices: String = words::SIGN_INS.iter().map(|(value, _, said)| format!("<option value=\"{value}\">{said}</option>")).collect();
        (chosen, choices)
    };
    let mut carried: Vec<Sid> = groups.to_vec();
    carried.extend(libauthd_policy::derived_sids(logon_type));
    let refs: Vec<&SidRef> = carried.iter().map(Sid::as_ref).collect();
    let evaluation = policy.evaluate(user, &refs);
    let outcome = &evaluation.outcome;
    let from: String = evaluation
        .applied
        .iter()
        .map(|at| {
            let record = &policy.records[*at];
            format!(
                "<button type=\"button\" class=\"link\" fx-click=\"pick-record\" fx-value-record=\"{}\">{}</button>",
                escape(&record.sid.to_string()),
                escape(&called(record.sid.as_ref(), directory)),
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let row = |name: &str, value: &str| format!("<dt>{name}</dt><dd>{value}</dd>");
    let mut facts = row("Integrity", &escape(&words::integrity(outcome.integrity)));
    facts += &row("Owner of what they make", &escape(&outcome.owner.map_or_else(|| "Themselves".to_string(), |owner| called(owner.as_ref(), directory))));
    facts += &row("Default DACL", if outcome.default_dacl.is_some() { "Set" } else { "None: an object with no parent gets a null DACL" });
    let problems: String = evaluation.problems.iter().map(|problem| format!("<p class=\"note bad\">{}</p>", escape(problem))).collect();
    let floor = if policy.configured { "" } else { "<p class=\"note\">There is no policy key, so this is what authd has built in.</p>" };
    format!(
        "<div class=\"section\"><h3>Privileges</h3></div>\
         <label class=\"inline\">Signed in<select name=\"as\">{choices}</select></label>\
         <dl>{facts}</dl>{privileges}\
         <p class=\"note\">From {from}. It applies from their next sign-in; a session already signed in keeps what it got.</p>{floor}{problems}",
        privileges = privileges_list(outcome.privileges, Privileges::empty()),
        from = if from.is_empty() { "no record".to_string() } else { format!("the records for {from}") },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::{Group, Members, User};

    fn sid(text: &str) -> Sid {
        text.parse().unwrap()
    }

    fn directory() -> Directory {
        Directory {
            users: vec![User { sid: "S-1-5-21-1-2-3-1002".into(), name: "dana".into(), display_name: String::new(), enabled: Some(true), local: true }],
            groups: vec![Group { sid: "S-1-5-21-1-2-3-1100".into(), name: "developers".into(), local: true, members: Members::Counted(1), description: String::new() }],
            ..Directory::default()
        }
    }

    fn policy() -> Policy {
        Policy {
            configured: true,
            records: vec![
                Record { privileges: Some(Privileges::CHANGE_NOTIFY), ..Record::empty("Everyone", sid("S-1-1-0")) },
                Record {
                    privileges: Some(Privileges::CHANGE_NOTIFY | Privileges::BACKUP | Privileges::DEBUG),
                    integrity: Some(IntegrityLevel::HIGH),
                    ..Record::empty("Administrators", sid("S-1-5-32-544"))
                },
                Record { integrity: Some(IntegrityLevel::LOW), ..Record::empty("S-1-5-21-1-2-3-1100", sid("S-1-5-21-1-2-3-1100")) },
            ],
            denied: Privileges::DEBUG,
            problems: vec!["ignoring policy record Machine\\Generic\\Authn\\Policy\\developers: not a well-known principal and not a SID".into()],
        }
    }

    #[test]
    fn the_list_names_each_record_as_a_person_would_and_says_what_authd_ignores() {
        let listed = listing(&policy(), &directory(), None, |_| true);
        assert!(listed.contains("<span class=\"name\">Denied to everyone</span><span class=\"privs\">1 privilege</span>"), "{listed}");
        assert!(listed.contains("<span class=\"name\">Administrators</span><span class=\"privs\">3 privileges</span><span class=\"level\">High</span>"), "{listed}");
        assert!(listed.contains("<span class=\"name\">developers</span>"), "a local group's SID is named: {listed}");
        let mut known = directory();
        let lpsd = libauthd_policy::service_sid::of("lpsd").unwrap();
        known.services.push((lpsd.to_string(), "lpsd".into()));
        assert_eq!(called(lpsd.as_ref(), &known), "The lpsd service");
        assert!(notes(&policy()).contains("authd warns: ignoring policy record"));
        assert!(notes(&Policy::floor()).contains("no policy key"));
    }

    #[test]
    fn a_record_shows_what_it_grants_and_what_is_denied_anyway() {
        let shown = details(&policy(), &directory(), "S-1-5-32-544", &Ok(()), "", &Doing::Looking);
        assert!(shown.contains("<code>SeDebugPrivilege</code>") && shown.contains("Denied to everyone, so not granted"), "{shown}");
        assert!(shown.contains("fx-click=\"edit-record\"") && shown.contains("<dt>Integrity</dt><dd>High</dd>"), "{shown}");
        let looking = details(&policy(), &directory(), "S-1-5-32-544", &Err("You may not change this machine's policy.".into()), "", &Doing::Looking);
        assert!(!looking.contains("edit-record") && looking.contains("You may not change"), "{looking}");
    }

    #[test]
    fn what_someone_gets_is_worked_out_as_authd_would() {
        let dana = sid("S-1-5-21-1-2-3-1002");
        let shown = effective(&policy(), &directory(), dana.as_ref(), &[sid("S-1-5-32-544")], "interactive");
        assert!(shown.contains("<dt>Integrity</dt><dd>High</dd>"), "{shown}");
        assert!(shown.contains("<code>SeBackupPrivilege</code>") && !shown.contains("<code>SeDebugPrivilege</code>"), "denied is taken away: {shown}");
        assert!(shown.contains(">Everyone</button>, <button") && shown.contains(">Administrators</button>"), "{shown}");
        // Their own record's level wins: in developers they would be Low.
        let developer = effective(&policy(), &directory(), sid("S-1-5-21-1-2-3-1100").as_ref(), &[], "network");
        assert!(developer.contains("<dd>Low</dd>"), "{developer}");
    }

    #[test]
    fn a_form_reads_back_as_the_draft_it_was_filled_from() {
        let mut fields = Fields::default();
        let draft = Draft {
            privileges: Some(Privileges::BACKUP | Privileges::RESTORE),
            integrity: Some(IntegrityLevel::LOW),
            owner: Some("Administrators".into()),
            default_dacl: Some("D:(A;;GA;;;SY)".into()),
        };
        fill(&draft, "", &mut fields);
        assert_eq!(super::draft(&fields, &directory()), Ok(draft));
        // A local group is named by its SID, as authd reads it.
        fields.set("owner", "developers");
        assert_eq!(super::draft(&fields, &directory()).unwrap().owner.as_deref(), Some("S-1-5-21-1-2-3-1100"));
        fields.set("dacl", "D:(nonsense)");
        assert!(super::draft(&fields, &directory()).is_err());
    }

    #[test]
    fn taking_passing_through_folders_from_everyone_is_asked_about_first() {
        let everyone = sid("S-1-1-0");
        assert!(risk(everyone.as_ref(), &Draft::default(), &policy()).is_some());
        assert!(risk(everyone.as_ref(), &Draft { privileges: Some(Privileges::CHANGE_NOTIFY), ..Draft::default() }, &policy()).is_none());
        assert!(risk(sid("S-1-5-21-1-2-3-1100").as_ref(), &Draft::default(), &policy()).is_none(), "only the records everyone relies on");
    }
}
