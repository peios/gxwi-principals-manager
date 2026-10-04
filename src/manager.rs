//! The window: the users or the groups there are, and, beside them, the one
//! picked in full.
//!
//! Everything shown is read from authd's identity socket, which anyone may
//! ask. Whether this person may change the local ones is lpsd's to say, and
//! it is asked, not guessed: a refusal leaves the window to look, and says
//! why.

use std::sync::Weak;

use libauthd::ident::{Fields, Record, Value, WithheldReason};
use libauthd::wire::LogonTypes;
use libauthd_client::admin::Admin;
use libauthd_client::ident::Ident;
use libgxwi::{Facts, Fields as Typed, Live, Surface, Value as Pressed, escape};

use libauthd::credential::Policy as CredentialPolicy;
use libauthd::lps::KeyInfo;
use libauthd_policy::Policy;
use libauthd_policy::write::Draft;
use peios::security::{Sid, SidRef};

use crate::accounts::{self, Account, Doing};
use crate::directory::{self, Directory, Members};
use crate::groups::{self, Team};
use crate::policy::{self, Saved};
use crate::{claims, keys, words};

pub struct Manager {
    pub window: Weak<Surface<Manager>>,
    ident: Ident,
    admin: Admin,
    view: View,
    directory: Directory,
    /// The principal or group picked, by its SID, and what is known of it.
    picked: Option<String>,
    details: Option<Result<Record, String>>,
    /// The members of the group picked, where more than its record holds.
    members: Option<Result<Vec<Record>, String>>,
    /// What the local user picked signs in with, and their SSH keys, where
    /// this person may administer the store: lpsd tells nobody else.
    credentials: Option<Credentials>,
    /// Whether this person may change the store, and why not.
    authority: Result<(), String>,
    /// What is being done in the details pane.
    doing: Doing,
    /// What came of the last change: what was done, or why it wasn't.
    said: Option<Result<String, String>>,
    /// What this machine grants each principal, and whether this person may
    /// change it, which the policy key's own descriptor says.
    policy: Policy,
    may_policy: Result<(), String>,
    /// The policy record picked, by its SID, or [`policy::DENIED`].
    record: Option<String>,
    /// Why saving the record form is worth asking about first, while it is
    /// being asked.
    asked: Option<String>,
}

/// What the window reads again in the background, for the one picked then.
pub struct Heard {
    pub directory: Directory,
    pub picked: Option<String>,
    pub details: Option<Result<Record, String>>,
    pub credentials: Option<Credentials>,
    pub policy: Policy,
}

/// A user's credential policy and SSH keys, or why they couldn't be read.
pub type Credentials = Result<(CredentialPolicy, Vec<KeyInfo>), String>;

/// Which list is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Users,
    Groups,
    Privileges,
}

/// What changing the local principals needs, said where the person lacks it.
const NEEDS: &str = "Changing users and groups needs Administrators, enabled in your token.";

impl Manager {
    pub fn new(ident: Ident, admin: Admin) -> Manager {
        let mut manager = Manager {
            window: Weak::new(),
            ident,
            admin,
            view: View::Users,
            directory: Directory::default(),
            picked: None,
            details: None,
            members: None,
            credentials: None,
            authority: Ok(()),
            doing: Doing::Looking,
            said: None,
            policy: Policy::floor(),
            may_policy: Ok(()),
            record: None,
            asked: None,
        };
        manager.refresh();
        manager
    }

    pub fn ident(&self) -> &Ident {
        &self.ident
    }

    pub fn admin(&self) -> &Admin {
        &self.admin
    }

    pub fn picked(&self) -> Option<&str> {
        self.picked.as_deref()
    }

    /// The name of the user picked, if they are a local one whose
    /// credentials this person may read.
    pub fn local_user(&self) -> Option<String> {
        self.account().map(|account| account.name)
    }

    /// Reads everything again, and asks again whether this person may
    /// change it.
    fn refresh(&mut self) {
        self.directory = directory::read(&self.ident);
        self.authority = self.ask_authority();
        self.policy = Policy::read();
        self.may_policy = libauthd_policy::write::may_write();
        self.reread();
    }

    /// Whether this person may administer the store: the smallest request
    /// there is, which lpsd refuses to anyone who may not.
    fn ask_authority(&self) -> Result<(), String> {
        match self.admin.domain() {
            Ok(_) => Ok(()),
            Err(refusal) if refusal.denied() => Err(format!("You may look, but not change anything. {NEEDS}")),
            Err(refusal) => Err(format!("Nothing can be changed: {}.", refusal.reason)),
        }
    }

    /// Reads the one picked again.
    fn reread(&mut self) {
        match self.picked.clone() {
            Some(sid) => {
                let details = directory::details(&self.ident, &sid);
                self.members = match &details {
                    Ok(record) if record.reason(Fields::MEMBERS) == Some(WithheldReason::TooLarge) => Some(directory::all_members(&self.ident, &sid)),
                    _ => None,
                };
                self.details = Some(details);
            }
            None => {
                self.details = None;
                self.members = None;
            }
        }
        self.credentials = self.local_user().map(|name| self.admin.keys(&name).map_err(|refusal| refusal.reason));
    }

    /// Whether what has been read again in the background, for the one
    /// picked then, differs from what is shown.
    pub fn differs(&self, heard: &Heard) -> bool {
        heard.directory != self.directory
            || heard.policy != self.policy
            || (heard.picked.as_deref() == self.picked.as_deref()
                && (heard.details.as_ref().is_some_and(|details| Some(details) != self.details.as_ref()) || heard.credentials.as_ref() != self.credentials.as_ref()))
    }

    /// What has been read again in the background, shown, where the one it
    /// was read for is still the one picked. A group's long member list is
    /// read again with it.
    pub fn heard(&mut self, heard: Heard) {
        let Heard { directory, picked, details, credentials, policy } = heard;
        self.directory = directory;
        self.policy = policy;
        if details.is_some() && picked.as_deref() == self.picked.as_deref() {
            self.details = details;
            self.credentials = credentials;
            if self.members.is_some()
                && let Some(sid) = self.picked.clone()
            {
                self.members = Some(directory::all_members(&self.ident, &sid));
            }
        }
    }

    fn pick(&mut self, sid: &str) {
        self.picked = Some(sid.to_string());
        self.reread();
    }

    /// Shows the principal or group by its SID, in whichever list holds it.
    fn show(&mut self, sid: &str) {
        if self.directory.groups.iter().any(|group| group.sid == sid) {
            self.view = View::Groups;
        } else if self.directory.users.iter().any(|user| user.sid == sid) {
            self.view = View::Users;
        }
        self.pick(sid);
    }

    /// The user picked, if they are a local one this person may change.
    fn account(&self) -> Option<Account> {
        let Some(Ok(record)) = &self.details else { return None };
        let changeable = self.authority.is_ok() && record.kind_found == libauthd::ident::Kind::Principal && directory::local(&directory::sid_text(&record.sid));
        changeable.then(|| {
            let mut account = Account::of(record);
            if let Some(Ok((policy, keys))) = &self.credentials {
                account.policy = Some(*policy);
                account.keys = keys.clone();
            }
            account
        })
    }

    /// Stops whatever was being done in the pane, forgetting any password
    /// typed there.
    fn leave(&mut self, fields: &mut Typed) {
        self.doing = Doing::Looking;
        self.said = None;
        self.asked = None;
        accounts::forget(fields);
    }

    /// What came of the last change, to show at the top of the pane.
    fn said(&self) -> String {
        match &self.said {
            None => String::new(),
            Some(Ok(done)) => format!("<p class=\"note\" role=\"status\">{}</p>", escape(done)),
            Some(Err(why)) => format!("<p class=\"note bad\" role=\"alert\">{}</p>", escape(why)),
        }
    }

    /// Notes what came of a change, and reads everything again so it shows.
    fn changed(&mut self, outcome: Result<String, String>) {
        if outcome.is_ok() {
            self.doing = Doing::Looking;
            self.refresh();
        }
        self.said = Some(outcome);
    }

    /// The group picked, if this person may change who is in it: a local
    /// group, or a `BUILTIN` one, whose members are recorded here.
    fn team(&self) -> Option<Team> {
        let Some(Ok(record)) = &self.details else { return None };
        let sid = directory::sid_text(&record.sid);
        let changeable = self.authority.is_ok() && record.kind_found == libauthd::ident::Kind::Group && (directory::local(&sid) || directory::recorded(&sid));
        changeable.then(|| Team::of(record))
    }

    /// The SIDs of the members of the group picked, as far as they are known.
    fn member_sids(&self) -> Vec<String> {
        match (&self.details, &self.members) {
            (_, Some(Ok(members))) => members.iter().map(|member| directory::sid_text(&member.sid)).collect(),
            (Some(Ok(record)), _) => match record.value(Fields::MEMBERS) {
                Some(Value::Members(members)) => members.iter().map(|member| directory::sid_text(&member.sid)).collect(),
                _ => Vec::new(),
            },
            _ => Vec::new(),
        }
    }

    /// The groups a local user may be put in, by SID and name: this
    /// machine's own, and the `BUILTIN` ones, whose members are recorded
    /// here. `Authenticated Users` too where it may be a primary group.
    fn joinable(&self, primary: bool) -> Vec<(String, String)> {
        self.directory
            .groups
            .iter()
            .filter(|group| group.local || directory::recorded(&group.sid) || (primary && group.sid == "S-1-5-11"))
            .map(|group| (group.sid.clone(), group.name.clone()))
            .collect()
    }

    /// The groups a form offers, for what is being done.
    fn choices(&self) -> Vec<(String, String)> {
        match &self.doing {
            Doing::Profile => self.joinable(true),
            Doing::Join => {
                let joined: Vec<String> = match &self.details {
                    Some(Ok(record)) => match record.value(Fields::GROUPS) {
                        Some(Value::Groups(groups)) => groups.iter().map(|group| directory::sid_text(&group.sid)).collect(),
                        _ => Vec::new(),
                    },
                    _ => Vec::new(),
                };
                self.joinable(false).into_iter().filter(|(sid, _)| !joined.contains(sid)).collect()
            }
            Doing::AddMember => {
                let members = self.member_sids();
                self.directory
                    .users
                    .iter()
                    .filter(|user| user.local && !members.contains(&user.sid))
                    .map(|user| {
                        let name = accounts::short(&user.name).to_string();
                        let shown = if user.display_name.is_empty() { name.clone() } else { format!("{name} ({})", user.display_name) };
                        (name, shown)
                    })
                    .collect()
            }
            _ => Vec::new(),
        }
    }

    /// Makes what the new-user or new-group form describes, and shows it.
    fn make(&mut self, fields: &mut Typed) {
        let made = if self.doing == Doing::New { accounts::create(&self.admin, fields) } else { groups::create(&self.admin, fields) };
        accounts::forget(fields);
        match made {
            Ok((name, rid)) => {
                let sid = self.admin.domain().ok().map(|domain| format!("{}-{rid}", directory::sid_text(&domain)));
                self.changed(Ok(format!("{name} is made.")));
                accounts::clear(fields);
                if let Some(sid) = sid {
                    self.show(&sid);
                }
            }
            Err(why) => self.said = Some(Err(why)),
        }
    }

    /// Does what the person asked of the group picked.
    fn act_on_group(&mut self, name: &str, value: &Pressed, fields: &mut Typed) {
        let Some(team) = self.team() else { return };
        let admin = &self.admin;
        match name {
            "edit-group" | "rename-group" | "add-member" | "delete-group" => {
                self.doing = match name {
                    "edit-group" if team.local => Doing::GroupEdit,
                    "rename-group" if team.local => Doing::GroupRename,
                    "delete-group" if team.local => Doing::GroupDeleting,
                    "add-member" => Doing::AddMember,
                    _ => return,
                };
                self.said = None;
                groups::fill(&self.doing, &team, fields);
            }
            "delete-group-yes" if team.local => match admin.group_delete(&team.name) {
                Ok(()) => {
                    self.picked = None;
                    self.changed(Ok(format!("{} is deleted.", team.name)));
                }
                Err(refusal) => {
                    self.doing = Doing::Looking;
                    self.said = Some(Err(refusal.reason));
                }
            },
            "remove-member" => {
                let Some(member) = value["member"].as_str().filter(|member| !member.is_empty()) else { return };
                // A primary group is a membership no list holds, so taking
                // them out of the list would leave them in it.
                let primary = admin.show(member).is_ok_and(|detail| directory::sid_text(&detail.primary_group.sid) == team.sid);
                if primary {
                    self.said = Some(Err(format!("It is {member}'s primary group, so they are in it whatever else. Give them another under Edit first.")));
                    return;
                }
                let outcome = admin.group_remove(member, &team.sid).map(|()| format!("{member} is out of {}. It applies from their next sign-in.", team.name));
                self.changed(outcome.map_err(|refusal| refusal.reason));
            }
            "save" => {
                let outcome = match &self.doing {
                    Doing::GroupEdit => groups::save_description(admin, &team, fields),
                    Doing::GroupRename => groups::save_rename(admin, &team, fields),
                    Doing::AddMember => groups::save_member(admin, &team, fields),
                    _ => return,
                };
                self.changed(outcome);
            }
            _ => {}
        }
    }

    /// Does what the person asked in Privileges, or of a principal's record
    /// from its details. Answers whether it was a policy event at all.
    fn act_on_policy(&mut self, name: &str, value: &Pressed, fields: &mut Typed) -> bool {
        let editing = matches!(self.doing, Doing::NewRecord | Doing::EditRecord | Doing::EditDenied);
        match name {
            "pick-record" => {
                if let Some(record) = value["record"].as_str().filter(|record| !record.is_empty()) {
                    self.leave(fields);
                    self.view = View::Privileges;
                    self.record = Some(record.to_string());
                }
            }
            "new-record" | "own-record" if self.may_policy.is_ok() => {
                let sid = value["sid"].as_str().and_then(|sid| sid.parse::<Sid>().ok());
                self.leave(fields);
                self.view = View::Privileges;
                accounts::clear(fields);
                match sid.as_ref().and_then(|sid| self.policy.record(sid.as_ref())) {
                    Some(record) => {
                        self.record = Some(record.sid.to_string());
                        self.doing = Doing::EditRecord;
                        policy::fill(&Draft::of(record), "", fields);
                    }
                    None => {
                        self.doing = Doing::NewRecord;
                        let principal = sid.map(|sid| policy::called(sid.as_ref(), &self.directory)).unwrap_or_default();
                        policy::fill(&Draft::default(), &principal, fields);
                    }
                }
            }
            "edit-record" | "delete-record" | "delete-record-yes" | "edit-denied" if self.may_policy.is_ok() => {
                let picked = self.record.clone().unwrap_or_default();
                let record = picked.parse::<Sid>().ok().and_then(|sid| self.policy.record(sid.as_ref()).cloned());
                self.said = None;
                match (name, record) {
                    ("edit-denied", _) => {
                        self.doing = Doing::EditDenied;
                        accounts::clear(fields);
                        policy::fill_denied(&self.policy, fields);
                    }
                    ("edit-record", Some(record)) => {
                        self.doing = Doing::EditRecord;
                        accounts::clear(fields);
                        policy::fill(&Draft::of(&record), "", fields);
                    }
                    ("delete-record", Some(_)) => self.doing = Doing::RecordDeleting,
                    ("delete-record-yes", Some(record)) => {
                        let called = policy::called(record.sid.as_ref(), &self.directory);
                        let outcome = libauthd_policy::write::delete(&record.name)
                            .map(|()| format!("The record for {called} is deleted. What it granted is no longer granted from their next sign-in."));
                        if outcome.is_ok() {
                            self.record = None;
                        }
                        self.doing = Doing::Looking;
                        self.changed(outcome);
                    }
                    _ => {}
                }
            }
            "save" | "save-anyway" if editing => {
                let outcome = match self.doing {
                    Doing::EditDenied => policy::save_denied(fields).map(|said| Saved::Done(policy::DENIED.to_string(), said)),
                    _ => policy::save(&self.doing, &self.policy, &self.directory, self.record.as_deref(), fields, name == "save-anyway"),
                };
                match outcome {
                    Ok(Saved::Done(record, said)) => {
                        self.asked = None;
                        self.record = Some(record);
                        self.changed(Ok(said));
                    }
                    Ok(Saved::Ask(why)) => self.asked = Some(why),
                    Err(why) => {
                        self.asked = None;
                        self.said = Some(Err(why));
                    }
                }
            }
            "unask" => self.asked = None,
            _ => return false,
        }
        true
    }

    /// Does what the person asked: of the user or group picked, or a new one.
    fn act(&mut self, name: &str, value: &Pressed, fields: &mut Typed) {
        if name == "new" || name == "new-group" {
            self.doing = if name == "new" { Doing::New } else { Doing::NewGroup };
            self.said = None;
            accounts::clear(fields);
            return;
        }
        if name == "save" && matches!(self.doing, Doing::New | Doing::NewGroup) {
            self.make(fields);
            return;
        }
        if self.act_on_policy(name, value, fields) {
            return;
        }
        if self.team().is_some() {
            self.act_on_group(name, value, fields);
            return;
        }
        let Some(account) = self.account() else { return };
        let admin = &self.admin;
        match name {
            "join" => {
                self.doing = Doing::Join;
                self.said = None;
                accounts::fill(&self.doing, &account, fields);
            }
            "leave" => {
                let Some(group) = value["group"].as_str().filter(|group| !group.is_empty()) else { return };
                let called = value["called"].as_str().unwrap_or(group);
                let outcome = admin.group_remove(&account.name, group).map(|()| format!("{} is out of {called}. It applies from their next sign-in.", account.name));
                self.changed(outcome.map_err(|refusal| refusal.reason));
            }
            "edit" | "rename" | "sign-in" | "password" => {
                self.doing = match name {
                    "edit" => Doing::Profile,
                    "rename" => Doing::Rename,
                    "sign-in" => Doing::SignIn,
                    _ => Doing::Password(account.policy),
                };
                self.said = None;
                accounts::fill(&self.doing, &account, fields);
            }
            "add-key" => {
                self.doing = Doing::AddKey;
                self.said = None;
                accounts::clear(fields);
            }
            "remove-key" => {
                let Some(id) = value["key"].as_str().and_then(keys::id_of) else { return };
                let label = account.keys.iter().find(|key| key.id == id).map(|key| key.label.clone()).unwrap_or_default();
                let outcome = admin.key_remove(&account.name, id).map(|()| {
                    if label.is_empty() { "The key is removed.".to_string() } else { format!("The key {label} is removed.") }
                });
                self.changed(outcome.map_err(|refusal| refusal.reason));
            }
            "add-claim" | "edit-claim" => {
                let editing = value["claim"].as_str().and_then(|name| account.claims.iter().find(|claim| claim.name == name));
                accounts::clear(fields);
                self.said = None;
                match (name, editing) {
                    ("add-claim", _) => {
                        self.doing = Doing::NewClaim;
                        claims::fill(None, fields);
                    }
                    (_, Some(claim)) => {
                        self.doing = Doing::EditClaim(claim.name.clone());
                        claims::fill(Some(claim), fields);
                    }
                    _ => {}
                }
            }
            "remove-claim" => {
                let Some(claim) = value["claim"].as_str().filter(|claim| !claim.is_empty()) else { return };
                let outcome = admin
                    .remove_claim(&account.name, claim)
                    .map(|()| format!("{}'s claim {claim} is removed. It applies from their next sign-in.", account.name));
                self.changed(outcome.map_err(|refusal| refusal.reason));
            }
            "enable" | "disable" | "disable-instead" => {
                let enabled = name == "enable";
                let outcome = admin.set_enabled(&account.name, enabled).map(|()| format!("{} is {}.", account.name, if enabled { "enabled" } else { "disabled, and can't sign in" }));
                self.changed(outcome.map_err(|refusal| refusal.reason));
            }
            "delete" => {
                self.doing = Doing::Deleting;
                self.said = None;
            }
            "delete-yes" => match admin.remove(&account.name) {
                Ok(()) => {
                    self.picked = None;
                    self.changed(Ok(format!("{} is deleted.", account.name)));
                }
                Err(refusal) => {
                    self.doing = Doing::Looking;
                    self.said = Some(Err(refusal.reason));
                }
            },
            "save" => {
                let outcome = match &self.doing {
                    Doing::Profile => accounts::save_profile(admin, &account, fields),
                    Doing::Rename => accounts::save_rename(admin, &account, fields).map(|new_name| format!("{} is now called {new_name}.", account.name)),
                    Doing::Password(policy) => accounts::save_password(admin, &account, *policy, fields),
                    Doing::SignIn => accounts::save_sign_in(admin, &account, fields),
                    Doing::Join => accounts::save_join(admin, &account, fields),
                    Doing::AddKey => keys::save(admin, &account, fields),
                    Doing::NewClaim => claims::save(admin, &account, None, fields, &self.directory),
                    Doing::EditClaim(name) => {
                        let Some(claim) = account.claims.iter().find(|claim| claim.name == *name) else { return };
                        claims::save(admin, &account, Some(claim), fields, &self.directory)
                    }
                    _ => return,
                };
                accounts::forget(fields);
                self.changed(outcome);
            }
            _ => {}
        }
    }

    fn matches(filter: &str, texts: &[&str]) -> bool {
        let filter = filter.trim().to_lowercase();
        filter.is_empty() || texts.iter().any(|text| text.to_lowercase().contains(&filter))
    }

    fn listing(&self, filter: &str) -> String {
        if self.view == View::Privileges {
            return format!(
                "{}{}",
                policy::notes(&self.policy),
                policy::listing(&self.policy, &self.directory, self.record.as_deref(), |texts| Self::matches(filter, texts)),
            );
        }
        if let Some(why) = &self.directory.trouble {
            return format!("<p class=\"trouble\">{}</p>", escape(why));
        }
        let rows: String = match self.view {
            View::Privileges => String::new(),
            View::Users => self
                .directory
                .users
                .iter()
                .filter(|user| Self::matches(filter, &[&user.name, &user.display_name, &user.sid]))
                .map(|user| {
                    let state = match user.enabled {
                        Some(true) => "Enabled",
                        Some(false) => "Disabled",
                        None => "",
                    };
                    format!(
                        "<li><button type=\"button\" fx-click=\"pick\" fx-value-sid=\"{sid}\" aria-selected=\"{picked}\"{off}>\
                         <span class=\"name\">{name}</span><span class=\"full\">{full}</span><span class=\"kind\">{kind}</span><span class=\"state\">{state}</span></button></li>",
                        sid = escape(&user.sid),
                        picked = self.picked.as_deref() == Some(user.sid.as_str()),
                        off = if user.enabled == Some(false) { " class=\"off\"" } else { "" },
                        name = escape(&user.name),
                        full = escape(&user.display_name),
                        kind = if user.local { "Local" } else { "Built-in" },
                    )
                })
                .collect(),
            View::Groups => self
                .directory
                .groups
                .iter()
                .filter(|group| Self::matches(filter, &[&group.name, &group.sid, &group.description]))
                .map(|group| {
                    let members = match &group.members {
                        Members::Counted(n) => words::count(*n, "member"),
                        Members::Many => "Many".into(),
                        Members::Rule => "By rule".into(),
                        Members::Unsaid(_) => String::new(),
                    };
                    format!(
                        "<li><button type=\"button\" fx-click=\"pick\" fx-value-sid=\"{sid}\" aria-selected=\"{picked}\">\
                         <span class=\"name\">{name}</span><span class=\"kind\">{kind}</span><span class=\"members\">{members}</span><span class=\"about\">{about}</span></button></li>",
                        sid = escape(&group.sid),
                        picked = self.picked.as_deref() == Some(group.sid.as_str()),
                        name = escape(&group.name),
                        kind = if group.local { "Local" } else { "Built-in" },
                        members = escape(&members),
                        about = escape(&group.description),
                    )
                })
                .collect(),
        };
        if rows.is_empty() {
            let none = match (self.view, filter.trim().is_empty()) {
                (_, false) => "Nothing matches.",
                (View::Users, true) => "There are no users.",
                (View::Groups | View::Privileges, true) => "There are no groups.",
            };
            return format!("<p class=\"more\">{none}</p>");
        }
        format!("<ul class=\"entries\">{rows}</ul>")
    }

    /// A principal or group, as a button that shows it.
    fn reference(sid: &[u8], name: &str) -> String {
        let sid = directory::sid_text(sid);
        let shown = if name.is_empty() { sid.clone() } else { name.to_string() };
        format!("<button type=\"button\" class=\"link\" fx-click=\"show\" fx-value-sid=\"{}\">{}</button>", escape(&sid), escape(&shown))
    }

    /// The pane in Privileges: a record or what is denied to everyone, or
    /// the form changing one.
    fn policy_details(&self) -> String {
        let mut said = self.said();
        if let Some(why) = &self.asked {
            said += &format!(
                "<div class=\"asking\" role=\"alertdialog\" aria-label=\"Save anyway?\"><p>{}</p>\
                 <button type=\"button\" class=\"danger\" fx-click=\"save-anyway\">Save anyway</button>\
                 <button type=\"button\" fx-click=\"unask\" fx-autofocus>Go back</button></div>",
                escape(why),
            );
        }
        if matches!(self.doing, Doing::NewRecord | Doing::EditRecord | Doing::EditDenied) && self.may_policy.is_ok() {
            let form = policy::render(&self.doing, &self.policy, &self.directory, self.record.as_deref(), &said);
            if !form.is_empty() {
                return form;
            }
        }
        match &self.record {
            Some(picked) => policy::details(&self.policy, &self.directory, picked, &self.may_policy, &said, &self.doing),
            None => format!(
                "<aside class=\"details\" aria-label=\"Details\">{said}<p class=\"more\">Pick a record to see what it grants. \
                 Each user or group's own page says what they get in all.</p></aside>"
            ),
        }
    }

    /// The SIDs a principal's token carries before authd adds its own: them,
    /// their groups and their primary group.
    fn carried(record: &Record) -> Vec<Sid> {
        let mut sids: Vec<Sid> = Vec::new();
        if let Some(Value::Groups(groups)) = record.value(Fields::GROUPS) {
            sids.extend(groups.iter().filter_map(|group| SidRef::from_bytes(&group.sid).map(SidRef::to_sid)));
        }
        if let Some(Value::PrimaryGroup(group)) = record.value(Fields::PRIMARY_GROUP)
            && let Some(sid) = SidRef::from_bytes(&group.sid)
        {
            sids.push(sid.to_sid());
        }
        sids
    }

    /// What policy grants the principal or group shown: what a local user
    /// gets in all, or what a group's own record grants its members.
    fn privileges_section(&self, record: &Record, fields: &Typed) -> String {
        let Some(sid) = SidRef::from_bytes(&record.sid) else { return String::new() };
        let own = self.policy.record(sid);
        let may = self.may_policy.is_ok();
        let button = |label: &str| {
            if may {
                format!("<p class=\"actions\"><button type=\"button\" fx-click=\"own-record\" fx-value-sid=\"{}\">{label}</button></p>", escape(&sid.to_string()))
            } else {
                String::new()
            }
        };
        match record.kind_found {
            libauthd::ident::Kind::Principal if directory::local(&sid.to_string()) => {
                let effective = policy::effective(&self.policy, &self.directory, sid, &Self::carried(record), fields.get("as"));
                format!("{effective}{}", button(if own.is_some() { "Edit their own record" } else { "Give them their own record" }))
            }
            libauthd::ident::Kind::Group => {
                let said = match own {
                    None => "<p class=\"more\">No record: being in it grants nothing here on its own.</p>".to_string(),
                    Some(own) => {
                        let mut parts = Vec::new();
                        if let Some(privileges) = own.privileges {
                            parts.push(words::count(privileges.canonical_names().count(), "privilege"));
                        }
                        if let Some(level) = own.integrity {
                            parts.push(format!("integrity {}", words::integrity(level)));
                        }
                        format!(
                            "<p class=\"more\">Its record grants its members {}. <button type=\"button\" class=\"link\" fx-click=\"pick-record\" fx-value-record=\"{}\">See the record</button></p>",
                            escape(&if parts.is_empty() { "nothing".to_string() } else { parts.join(", ") }),
                            escape(&sid.to_string()),
                        )
                    }
                };
                format!("<h3>Privileges</h3>{said}{}", button(if own.is_some() { "Edit its record" } else { "Give it a record" }))
            }
            _ => String::new(),
        }
    }

    fn details(&self, fields: &Typed) -> String {
        if self.view == View::Privileges {
            return self.policy_details();
        }
        if !matches!(self.doing, Doing::Looking | Doing::Deleting | Doing::GroupDeleting) {
            let choices = self.choices();
            let mut form = accounts::render(&self.doing, self.account().as_ref(), fields, &self.said(), &choices);
            if form.is_empty() {
                form = groups::render(&self.doing, self.team().as_ref(), &self.said(), &choices);
            }
            if !form.is_empty() {
                return form;
            }
        }
        let Some(details) = &self.details else {
            if self.said.is_some() {
                return format!("<aside class=\"details\" aria-label=\"Details\">{}</aside>", self.said());
            }
            let what = match self.view {
                View::Users => "Pick a user to see them in full.",
                View::Groups | View::Privileges => "Pick a group to see who is in it.",
            };
            return format!("<aside class=\"details\" aria-label=\"Details\"><p class=\"more\">{what}</p></aside>");
        };
        let record = match details {
            Ok(record) => record,
            Err(why) => return format!("<aside class=\"details\" aria-label=\"Details\">{}<p class=\"note bad\">{}</p></aside>", self.said(), escape(why)),
        };
        let sid = directory::sid_text(&record.sid);
        let local = directory::local(&sid);
        let account = self.account();
        let team = self.team();
        // A small button beside a group or a member, taking one out of the other.
        let remove = |event: &str, values: &str, what: &str| {
            format!("<button type=\"button\" class=\"small\" fx-click=\"{event}\"{values} title=\"{}\">Remove</button>", escape(what))
        };
        let row = |name: &str, value: &str| format!("<dt>{name}</dt><dd>{value}</dd>");
        let mut facts = String::new();
        let mut sections = String::new();
        let display_name = match record.value(Fields::DISPLAY_NAME) {
            Some(Value::DisplayName(name)) if !name.is_empty() => Some(name.clone()),
            _ => None,
        };
        facts += &row("Kind", if local { "Local" } else { "Built-in" });
        if let Some(Value::Enabled(enabled)) = record.value(Fields::ENABLED) {
            facts += &row("State", if *enabled { "Enabled" } else { "Disabled: it can't sign in" });
        }
        if let Some(Value::UnixId(id)) = record.value(Fields::UNIX_ID) {
            let label = if record.kind_found == libauthd::ident::Kind::Group { "Group ID" } else { "User ID" };
            facts += &row(label, &id.to_string());
        }
        if let Some(Value::PrimaryGroup(group)) = record.value(Fields::PRIMARY_GROUP) {
            facts += &row("Primary group", &Self::reference(&group.sid, &group.name));
        }
        if let Some(Value::Home(home)) = record.value(Fields::HOME) {
            facts += &row("Home", &format!("<code>{}</code>", escape(home)));
        }
        if let Some(Value::Shell(shell)) = record.value(Fields::SHELL) {
            facts += &row("Shell", &format!("<code>{}</code>", escape(shell)));
        }
        facts += &row("SID", &format!("<code>{}</code>", escape(&sid)));
        if let Some(Value::LogonTypes(types)) = record.value(Fields::LOGON_TYPES) {
            let said: String = words::logon_types(*types).iter().map(|said| format!("<li>{}</li>", escape(said))).collect();
            let default = if *types == LogonTypes::UNSTATED { "<p class=\"note\">Nothing is stated, so the machine's default applies.</p>" } else { "" };
            sections += &format!("<h3>May sign in</h3><ul class=\"plain\">{said}</ul>{default}");
        }
        // A section's heading, with a button adding to it where there is one.
        let head = |title: &str, add: Option<(&str, &str)>| match add {
            Some((event, what)) => format!(
                "<div class=\"section\"><h3>{title}</h3><button type=\"button\" class=\"small go\" fx-click=\"{event}\" title=\"{}\">Add</button></div>",
                escape(what)
            ),
            None => format!("<h3>{title}</h3>"),
        };
        if account.is_some() {
            sections += &match &self.credentials {
                Some(Ok((policy, keys))) => {
                    let zone = jiff::tz::TimeZone::system();
                    let listed: String = keys
                        .iter()
                        .map(|key| {
                            format!(
                                "<li><span class=\"key\"><span>{label}</span><code>{fingerprint}</code><span class=\"added\">Added {added}</span></span>{remove}</li>",
                                label = escape(if key.label.is_empty() { "No label" } else { &key.label }),
                                fingerprint = escape(&key.fingerprint),
                                added = escape(&words::day(key.created, &zone)),
                                remove = remove("remove-key", &format!(" fx-value-key=\"{}\"", keys::id_text(&key.id)), &format!("Remove the key {}", key.label)),
                            )
                        })
                        .collect();
                    format!(
                        "<h3>Signs in with</h3><ul class=\"plain\"><li>{}</li></ul>{}{}",
                        escape(words::policy(*policy)),
                        head("SSH keys", Some(("add-key", "Add an SSH key"))),
                        if keys.is_empty() { "<p class=\"more\">No SSH keys.</p>".to_string() } else { format!("<ul class=\"plain keys\">{listed}</ul>") },
                    )
                }
                Some(Err(why)) => format!("<h3>Signs in with</h3><p class=\"note bad\">{}</p>", escape(why)),
                None => String::new(),
            };
        }
        if let Some(Value::Groups(groups)) = record.value(Fields::GROUPS) {
            let listed: String = groups
                .iter()
                .map(|group| {
                    let at = directory::sid_text(&group.sid);
                    let out = if account.is_some() && (directory::local(&at) || directory::recorded(&at)) {
                        remove(
                            "leave",
                            &format!(" fx-value-group=\"{}\" fx-value-called=\"{}\"", escape(&at), escape(&group.name)),
                            &format!("Take them out of {}", group.name),
                        )
                    } else {
                        String::new()
                    };
                    format!("<li>{}{out}</li>", Self::reference(&group.sid, &group.name))
                })
                .collect();
            sections += &if groups.is_empty() {
                "<h3>Groups</h3><p class=\"more\">In no groups but their primary group.</p>".to_string()
            } else {
                format!("<h3>Groups</h3><ul class=\"plain\">{listed}</ul>")
            };
        }
        if record.kind_found == libauthd::ident::Kind::Group {
            // A member lpsd holds may be taken out; one of another source is
            // that source's to change.
            let member = |at: &[u8], name: &str| {
                let out = if team.is_some() && directory::local(&directory::sid_text(at)) {
                    let short = accounts::short(name);
                    remove("remove-member", &format!(" fx-value-member=\"{}\"", escape(short)), &format!("Take {short} out of it"))
                } else {
                    String::new()
                };
                format!("<li>{}{out}</li>", Self::reference(at, name))
            };
            sections += "<h3>Members</h3>";
            sections += &match (record.value(Fields::MEMBERS), &self.members, directory::members(record)) {
                (Some(Value::Members(members)), _, _) if members.is_empty() => "<p class=\"more\">Nobody is in it.</p>".to_string(),
                (Some(Value::Members(members)), _, _) => format!("<ul class=\"plain\">{}</ul>", members.iter().map(|m| member(&m.sid, &m.name)).collect::<String>()),
                (_, Some(Ok(members)), _) => format!("<ul class=\"plain\">{}</ul>", members.iter().map(|m| member(&m.sid, &m.qualified_name)).collect::<String>()),
                (_, Some(Err(why)), _) => format!("<p class=\"note bad\">{}</p>", escape(why)),
                (_, None, Members::Rule) => "<p class=\"more\">Its members are decided by a rule, not listed: everyone it describes is in it as they sign in.</p>".to_string(),
                (_, None, Members::Unsaid(why)) => format!("<p class=\"more\">{}</p>", escape(&why)),
                _ => String::new(),
            };
        }
        sections += &self.privileges_section(record, fields);
        let claims = match record.value(Fields::CLAIMS) {
            Some(Value::Claims(claims)) => Some(claims.as_slice()),
            _ => None,
        };
        if claims.is_some() || account.is_some() {
            let claims = claims.unwrap_or_default();
            sections += &head("Claims", account.as_ref().map(|_| ("add-claim", "Add a claim")));
            sections += &if claims.is_empty() {
                "<p class=\"more\">No claims.</p>".to_string()
            } else {
                let rows: String = claims
                    .iter()
                    .map(|claim| {
                        let flags = words::claim_flags(claim);
                        let tools = if account.is_some() {
                            let named = format!(" fx-value-claim=\"{}\"", escape(&claim.name));
                            format!(
                                "<span class=\"tools\"><button type=\"button\" class=\"small go\" fx-click=\"edit-claim\"{named} title=\"Change {name}\">Edit</button>{}</span>",
                                remove("remove-claim", &named, &format!("Remove {}", claim.name)),
                                name = escape(&claim.name),
                            )
                        } else {
                            String::new()
                        };
                        format!(
                            "<li><span class=\"top\"><code>{name}</code>{tools}</span><span class=\"type\">{kind}{flags}</span><span class=\"values\">{values}</span></li>",
                            name = escape(&claim.name),
                            kind = escape(words::claim_type(&claim.values)),
                            flags = if flags.is_empty() { String::new() } else { escape(&format!(" · {}", flags.join(", "))) },
                            values = escape(&words::claim_values(&claim.values).join(", ")),
                        )
                    })
                    .collect();
                format!("<ul class=\"claims\">{rows}</ul>")
            };
        }
        let restricted: Vec<&str> = record
            .withheld
            .iter()
            .filter(|withheld| withheld.reason == WithheldReason::Restricted)
            .filter_map(|withheld| match withheld.field {
                Fields::GROUPS => Some("their groups"),
                Fields::MEMBERS => Some("its members"),
                Fields::CLAIMS => Some("their claims"),
                Fields::HOME | Fields::SHELL => Some("their home and shell"),
                _ => None,
            })
            .collect();
        if !restricted.is_empty() {
            sections += &format!("<p class=\"note\">You may not see {}.</p>", escape(&restricted.join(", ")));
        }
        let mut actions = String::new();
        let mut asking = String::new();
        let button = |event: &str, label: &str| format!("<button type=\"button\" fx-click=\"{event}\">{label}</button>");
        if let Some(account) = &account {
            actions += &button("edit", "Edit");
            actions += &button("rename", "Rename");
            actions += &button("password", "Set password");
            actions += &button("sign-in", "Sign-in");
            actions += &button("join", "Add to group");
            actions += &if account.enabled { button("disable", "Disable") } else { button("enable", "Enable") };
            actions += "<button type=\"button\" class=\"danger\" fx-click=\"delete\">Delete</button>";
            if self.doing == Doing::Deleting {
                asking = accounts::asking_delete(account);
            }
        }
        if let Some(team) = &team {
            if team.local {
                actions += &button("edit-group", "Edit");
                actions += &button("rename-group", "Rename");
            }
            actions += &button("add-member", "Add member");
            if team.local {
                actions += "<button type=\"button\" class=\"danger\" fx-click=\"delete-group\">Delete</button>";
                if self.doing == Doing::GroupDeleting {
                    asking = groups::asking_delete(team, self.member_sids().len());
                }
            }
        }
        let about = match record.value(Fields::DESCRIPTION) {
            Some(Value::Description(text)) if !text.is_empty() => format!("<p class=\"about\">{}</p>", escape(text)),
            _ => String::new(),
        };
        let may = if !local {
            let said = if record.kind_found != libauthd::ident::Kind::Group {
                "Built-in: authd defines it, and it can't be changed."
            } else if directory::recorded(&sid) {
                "Built-in: authd defines it, so it can't be renamed or deleted, but who is in it is recorded on this machine."
            } else {
                "Built-in: authd defines it, and who is in it is a rule."
            };
            format!("<p class=\"may\">{said}</p>")
        } else {
            match &self.authority {
                Ok(()) => String::new(),
                Err(why) => format!("<p class=\"may\">{}</p>", escape(why)),
            }
        };
        // A full name is the heading where there is one, and the name below.
        let (title, name) = match &display_name {
            Some(full) => (escape(full), format!("<p class=\"id\">{}</p>", escape(&record.qualified_name))),
            None => (escape(&record.qualified_name), String::new()),
        };
        format!(
            "<aside class=\"details\" aria-label=\"Details\"><h2>{title}</h2>{name}{about}<dl>{facts}</dl>\
             <p class=\"actions\">{actions}<button type=\"button\" fx-copy=\"sid\" fx-value-sid=\"{sid}\">Copy SID</button></p>{said}{asking}{may}{sections}</aside>",
            said = self.said(),
            sid = escape(&sid),
        )
    }

    fn footer(&self) -> String {
        let counted = format!("{} · {}", words::count(self.directory.users.len(), "user"), words::count(self.directory.groups.len(), "group"));
        let short = if self.directory.incomplete.is_empty() {
            String::new()
        } else {
            format!("<span class=\"bad\">Not every source answered: {}. These lists may be short.</span>", escape(&self.directory.incomplete.join(", ")))
        };
        format!("<footer class=\"status\">{short}<span>{}</span></footer>", escape(&counted))
    }
}

impl Live for Manager {
    fn render(&self, facts: &Facts) -> String {
        let filter = facts.fields.get("filter");
        let tab = |view: View, label: &str, event: &str| {
            format!("<button type=\"button\" class=\"tab\" fx-click=\"{event}\" aria-pressed=\"{}\">{label}</button>", self.view == view)
        };
        let authority = match &self.authority {
            Ok(()) => String::new(),
            Err(why) => format!("<p class=\"said\" role=\"status\">{}</p>", escape(why)),
        };
        let head = match self.view {
            View::Users => "<div class=\"head\"><span>Name</span><span>Full name</span><span>Kind</span><span>State</span></div>",
            View::Groups => "<div class=\"head\"><span>Name</span><span>Kind</span><span>Members</span><span>Description</span></div>",
            View::Privileges => "<div class=\"head\"><span>Principal</span><span>Privileges</span><span>Integrity</span><span>Also</span></div>",
        };
        let new = match (&self.authority, &self.may_policy, self.view) {
            (Ok(()), _, View::Users) => "<button type=\"button\" fx-click=\"new\" fx-key=\"Ctrl+N\" title=\"A new user (Ctrl+N)\">New user</button>",
            (Ok(()), _, View::Groups) => "<button type=\"button\" fx-click=\"new-group\" fx-key=\"Ctrl+N\" title=\"A new group (Ctrl+N)\">New group</button>",
            (_, Ok(()), View::Privileges) => "<button type=\"button\" fx-click=\"new-record\" fx-key=\"Ctrl+N\" title=\"A new record (Ctrl+N)\">New record</button>",
            _ => "",
        };
        // In Privileges, the key's descriptor says who may change it.
        let authority = match (self.view, &self.may_policy) {
            (View::Privileges, Ok(())) => String::new(),
            (View::Privileges, Err(why)) => format!("<p class=\"said\" role=\"status\">You may look, but not change anything. {}</p>", escape(why)),
            _ => authority,
        };
        format!(
            "<div class=\"bar\"><div class=\"tabs\" role=\"group\" aria-label=\"Show\">{users}{groups}{privileges}</div>\
             <input name=\"filter\" autocomplete=\"off\" spellcheck=\"false\" placeholder=\"Find by name or SID\" aria-label=\"Find\">\
             {new}<button type=\"button\" fx-click=\"refresh\" fx-key=\"F5\" title=\"Read again (F5)\">Refresh</button></div>{authority}\
             <div class=\"body\"><div class=\"list {class}\">{head}{listing}</div>{details}</div>{footer}",
            users = tab(View::Users, "Users", "users"),
            groups = tab(View::Groups, "Groups", "groups"),
            privileges = tab(View::Privileges, "Privileges", "privileges"),
            class = match self.view {
                View::Users => "users",
                View::Groups => "groups",
                View::Privileges => "records",
            },
            listing = self.listing(filter),
            details = self.details(facts.fields),
            footer = self.footer(),
        )
    }

    fn event(&mut self, name: &str, value: &Pressed, fields: &mut Typed) {
        let sid = value["sid"].as_str().filter(|sid| !sid.is_empty());
        match name {
            "users" | "groups" | "privileges" => {
                self.leave(fields);
                self.view = match name {
                    "users" => View::Users,
                    "groups" => View::Groups,
                    _ => View::Privileges,
                };
            }
            "refresh" => self.refresh(),
            "pick" | "show" => {
                if let Some(sid) = sid {
                    self.leave(fields);
                    if name == "pick" { self.pick(sid) } else { self.show(sid) }
                }
            }
            "cancel" => self.leave(fields),
            _ => self.act(name, value, fields),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::{Group, User};
    use libauthd::ident::{Kind, Reference};

    /// The window as it would be with this directory read: nothing asks
    /// authd or lpsd.
    fn seen(directory: Directory) -> Manager {
        Manager {
            window: Weak::new(),
            ident: Ident::at("/nonexistent"),
            admin: Admin::at("/nonexistent"),
            view: View::Users,
            directory,
            picked: None,
            details: None,
            members: None,
            credentials: None,
            authority: Ok(()),
            doing: Doing::Looking,
            said: None,
            policy: Policy::floor(),
            may_policy: Ok(()),
            record: None,
            asked: None,
        }
    }

    fn sid(text: &str) -> Vec<u8> {
        text.parse::<peios::security::Sid>().unwrap().as_bytes().to_vec()
    }

    fn directory() -> Directory {
        Directory {
            users: vec![
                User { sid: "S-1-5-21-1-2-3-1001".into(), name: "alice".into(), display_name: String::new(), enabled: Some(false), local: true },
                User { sid: "S-1-5-21-1-2-3-1002".into(), name: "dana".into(), display_name: "Dana Scully".into(), enabled: Some(true), local: true },
                User { sid: "S-1-5-18".into(), name: "SYSTEM".into(), display_name: String::new(), enabled: None, local: false },
            ],
            groups: vec![
                Group { sid: "S-1-5-32-544".into(), name: "Administrators".into(), local: false, members: Members::Counted(1), description: "May change anything".into() },
                Group { sid: "S-1-5-21-1-2-3-1100".into(), name: "developers".into(), local: true, members: Members::Counted(0), description: String::new() },
                Group { sid: "S-1-1-0".into(), name: "Everyone".into(), local: false, members: Members::Rule, description: String::new() },
            ],
            incomplete: Vec::new(),
            trouble: None,
            services: Vec::new(),
        }
    }

    #[test]
    fn the_lists_say_who_is_local_disabled_and_how_many_are_in_a_group() {
        let mut manager = seen(directory());
        let users = manager.listing("");
        assert!(users.contains(r#"fx-value-sid="S-1-5-21-1-2-3-1001" aria-selected="false" class="off"><span class="name">alice</span><span class="full"></span><span class="kind">Local</span><span class="state">Disabled</span>"#));
        assert!(users.contains(r#"<span class="name">SYSTEM</span><span class="full"></span><span class="kind">Built-in</span>"#));
        // Found by any part of the name, the full name or the SID.
        let found = manager.listing("scully");
        assert!(found.contains("dana") && !found.contains("alice"));
        assert_eq!(manager.listing("nobody"), r#"<p class="more">Nothing matches.</p>"#);
        manager.view = View::Groups;
        assert!(manager.listing("").contains(r#"<span class="name">Administrators</span><span class="kind">Built-in</span><span class="members">1 member</span>"#));
    }

    #[test]
    fn a_user_is_shown_in_full_and_their_groups_lead_to_the_group() {
        let mut manager = seen(directory());
        manager.picked = Some("S-1-5-21-1-2-3-1002".into());
        manager.details = Some(Ok(Record {
            sid: sid("S-1-5-21-1-2-3-1002"),
            qualified_name: "dana".into(),
            kind_found: Kind::Principal,
            values: vec![
                Value::UnixId(1001002),
                Value::PrimaryGroup(Reference { sid: sid("S-1-5-11"), name: "Authenticated Users".into(), unix_id: 101 }),
                Value::Home("/home/dana".into()),
                Value::DisplayName("Dana Scully".into()),
                Value::Groups(vec![Reference { sid: sid("S-1-5-32-544"), name: "Administrators".into(), unix_id: 102 }]),
                Value::Enabled(true),
                Value::LogonTypes(LogonTypes::UNSTATED),
            ],
            withheld: vec![],
        }));
        let details = manager.details(&Typed::default());
        assert!(details.contains("<h2>Dana Scully</h2><p class=\"id\">dana</p>"));
        assert!(details.contains("<dt>User ID</dt><dd>1001002</dd>"));
        assert!(details.contains(r#"<li><button type="button" class="link" fx-click="show" fx-value-sid="S-1-5-32-544">Administrators</button><button type="button" class="small" fx-click="leave" fx-value-group="S-1-5-32-544" fx-value-called="Administrators" title="Take them out of Administrators">Remove</button></li>"#), "{details}");
        assert!(details.contains("Nothing is stated, so the machine's default applies."));
        manager.show("S-1-5-32-544");
        assert_eq!(manager.view, View::Groups);
        assert_eq!(manager.picked(), Some("S-1-5-32-544"));
    }

    #[test]
    fn a_person_who_may_not_change_the_store_is_told_why() {
        let mut manager = seen(directory());
        manager.authority = Err(format!("You may look, but not change anything. {NEEDS}"));
        manager.details = Some(Ok(Record { sid: sid("S-1-5-21-1-2-3-1001"), qualified_name: "alice".into(), kind_found: Kind::Principal, values: vec![], withheld: vec![] }));
        assert!(manager.details(&Typed::default()).contains("Changing users and groups needs Administrators, enabled in your token."));
        manager.details = Some(Ok(Record { sid: sid("S-1-5-18"), qualified_name: "SYSTEM".into(), kind_found: Kind::Principal, values: vec![], withheld: vec![] }));
        assert!(manager.details(&Typed::default()).contains("Built-in: authd defines it, and it can't be changed."));
        manager.details = Some(Ok(Record { sid: sid("S-1-5-32-544"), qualified_name: "Administrators".into(), kind_found: Kind::Group, values: vec![], withheld: vec![] }));
        assert!(manager.details(&Typed::default()).contains("who is in it is recorded on this machine"));
    }

    #[test]
    fn a_local_user_may_be_changed_only_by_someone_who_may() {
        let mut manager = seen(directory());
        let dana = Record { sid: sid("S-1-5-21-1-2-3-1002"), qualified_name: "dana".into(), kind_found: Kind::Principal, values: vec![Value::Enabled(true)], withheld: vec![] };
        manager.details = Some(Ok(dana.clone()));
        let shown = manager.details(&Typed::default());
        assert!(shown.contains(r#"fx-click="rename""#) && shown.contains(r#"fx-click="disable""#), "{shown}");
        manager.doing = Doing::Deleting;
        assert!(manager.details(&Typed::default()).contains(r#"fx-click="disable-instead""#));
        manager.doing = Doing::Rename;
        assert!(manager.details(&Typed::default()).contains(r#"<input name="new-name""#));

        manager.doing = Doing::Looking;
        manager.authority = Err(format!("You may look, but not change anything. {NEEDS}"));
        assert!(!manager.details(&Typed::default()).contains(r#"fx-click="rename""#));
        manager.doing = Doing::Rename;
        assert!(!manager.details(&Typed::default()).contains("new-name"), "no form for someone who may not use it");

        manager.doing = Doing::Looking;
        manager.authority = Ok(());
        manager.details = Some(Ok(Record { sid: sid("S-1-5-18"), qualified_name: "SYSTEM".into(), kind_found: Kind::Principal, values: vec![], withheld: vec![] }));
        assert!(!manager.details(&Typed::default()).contains(r#"fx-click="rename""#), "a built-in user is authd's");
    }

    fn group(at: &str, name: &str, values: Vec<Value>) -> Record {
        Record { sid: sid(at), qualified_name: name.into(), kind_found: Kind::Group, values, withheld: vec![] }
    }

    fn member(at: &str, name: &str) -> Reference {
        Reference { sid: sid(at), name: name.into(), unix_id: 0 }
    }

    #[test]
    fn a_local_group_may_be_changed_a_builtin_one_only_in_its_members_and_a_rule_not_at_all() {
        let mut manager = seen(directory());
        manager.details = Some(Ok(group(
            "S-1-5-21-1-2-3-1100",
            "developers",
            vec![Value::Members(vec![member("S-1-5-21-1-2-3-1002", "dana")]), Value::Description("Builds the software".into())],
        )));
        let shown = manager.details(&Typed::default());
        assert!(shown.contains(r#"<p class="about">Builds the software</p>"#), "{shown}");
        for event in ["edit-group", "rename-group", "add-member", "delete-group"] {
            assert!(shown.contains(&format!("fx-click=\"{event}\"")), "{event}: {shown}");
        }
        assert!(shown.contains(r#"fx-click="remove-member" fx-value-member="dana""#), "{shown}");
        // Only alice may be added: dana is in it, and SYSTEM is not lpsd's.
        manager.doing = Doing::AddMember;
        assert_eq!(manager.choices(), vec![("alice".to_string(), "alice".to_string())]);
        manager.doing = Doing::GroupDeleting;
        assert!(manager.details(&Typed::default()).contains("has 1 member"));

        manager.doing = Doing::Looking;
        manager.details = Some(Ok(group("S-1-5-32-544", "Administrators", vec![Value::Members(vec![member("S-1-5-21-1-2-3-1002", "dana")])])));
        let shown = manager.details(&Typed::default());
        assert!(shown.contains(r#"fx-click="add-member""#) && shown.contains(r#"fx-click="remove-member""#));
        assert!(!shown.contains(r#"fx-click="rename-group""#) && !shown.contains(r#"fx-click="delete-group""#));

        manager.details = Some(Ok(group("S-1-1-0", "Everyone", vec![])));
        assert!(!manager.details(&Typed::default()).contains(r#"fx-click="add-member""#));
    }

    #[test]
    fn a_user_is_offered_the_groups_they_could_join_and_be_primary_in() {
        let mut manager = seen(directory());
        manager.details = Some(Ok(Record {
            sid: sid("S-1-5-21-1-2-3-1002"),
            qualified_name: "dana".into(),
            kind_found: Kind::Principal,
            values: vec![Value::Groups(vec![member("S-1-5-32-544", "Administrators")])],
            withheld: vec![],
        }));
        manager.doing = Doing::Join;
        assert_eq!(manager.choices(), vec![("S-1-5-21-1-2-3-1100".to_string(), "developers".to_string())]);
        manager.doing = Doing::Profile;
        let primaries: Vec<String> = manager.choices().into_iter().map(|(_, name)| name).collect();
        assert_eq!(primaries, ["Administrators", "developers"], "never a rule group such as Everyone");
    }

    #[test]
    fn an_administrator_sees_what_a_user_signs_in_with_their_keys_and_claims_to_change() {
        let mut manager = seen(directory());
        manager.picked = Some("S-1-5-21-1-2-3-1002".into());
        let claim = libauthd::claim::Claim { name: "Department".into(), flags: 0, values: libauthd::claim::Values::String(vec!["Engineering".into()]) };
        manager.details = Some(Ok(Record {
            sid: sid("S-1-5-21-1-2-3-1002"),
            qualified_name: "dana".into(),
            kind_found: Kind::Principal,
            values: vec![Value::Enabled(true), Value::Claims(vec![claim])],
            withheld: vec![],
        }));
        manager.credentials = Some(Ok((
            CredentialPolicy::PasswordOrKey,
            vec![KeyInfo { id: [0xab; 16], fingerprint: "SHA256:abc".into(), label: "laptop".into(), created: 1_791_072_000 }],
        )));
        let shown = manager.details(&Typed::default());
        assert!(shown.contains("<h3>Signs in with</h3><ul class=\"plain\"><li>A password or an SSH key</li></ul>"), "{shown}");
        assert!(shown.contains("<span>laptop</span><code>SHA256:abc</code>"), "{shown}");
        assert!(shown.contains(&format!("fx-click=\"remove-key\" fx-value-key=\"{}\"", "ab".repeat(16))), "{shown}");
        for event in ["add-key", "add-claim", "edit-claim", "remove-claim"] {
            assert!(shown.contains(&format!("fx-click=\"{event}\"")), "{event}: {shown}");
        }
        assert_eq!(manager.account().unwrap().policy, Some(CredentialPolicy::PasswordOrKey));

        // Someone who may only look sees the claims, and nothing lpsd keeps.
        manager.authority = Err(format!("You may look, but not change anything. {NEEDS}"));
        let shown = manager.details(&Typed::default());
        assert!(shown.contains("Engineering") && !shown.contains("Signs in with") && !shown.contains("add-claim"), "{shown}");
    }

    #[test]
    fn a_group_says_what_its_record_grants_and_offers_one_only_to_who_may_write_it() {
        let mut manager = seen(directory());
        manager.policy = libauthd_policy::Policy {
            configured: true,
            records: vec![libauthd_policy::Record {
                privileges: Some(peios::security::Privileges::BACKUP),
                ..libauthd_policy::Record::empty("Administrators", "S-1-5-32-544".parse().unwrap())
            }],
            denied: peios::security::Privileges::empty(),
            problems: Vec::new(),
        };
        manager.details = Some(Ok(group("S-1-5-32-544", "Administrators", vec![])));
        let shown = manager.details(&Typed::default());
        assert!(shown.contains("Its record grants its members 1 privilege.") && shown.contains("Edit its record"), "{shown}");
        manager.details = Some(Ok(group("S-1-5-21-1-2-3-1100", "developers", vec![])));
        assert!(manager.details(&Typed::default()).contains("No record: being in it grants nothing here on its own."));
        manager.may_policy = Err("You may not change this machine's policy.".into());
        assert!(!manager.details(&Typed::default()).contains("own-record"));

        manager.view = View::Privileges;
        manager.record = Some("S-1-5-32-544".into());
        let record = manager.details(&Typed::default());
        assert!(record.contains("<code>SeBackupPrivilege</code>") && !record.contains("edit-record"), "{record}");
    }

    #[test]
    fn what_came_of_a_change_is_said_at_the_top_of_the_pane() {
        let mut manager = seen(directory());
        manager.said = Some(Err("dana is the only principal who can administer this machine".into()));
        assert!(manager.details(&Typed::default()).contains(r#"<p class="note bad" role="alert">dana is the only principal"#));
    }

    #[test]
    fn a_group_s_members_by_rule_are_said_to_be_one() {
        let mut manager = seen(directory());
        manager.details = Some(Ok(Record {
            sid: sid("S-1-1-0"),
            qualified_name: "Everyone".into(),
            kind_found: Kind::Group,
            values: vec![],
            withheld: vec![libauthd::ident::Withheld { field: Fields::MEMBERS, reason: WithheldReason::Absent }],
        }));
        assert!(manager.details(&Typed::default()).contains("Its members are decided by a rule, not listed"));
    }
}
