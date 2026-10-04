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

use crate::accounts::{self, Account, Doing};
use crate::directory::{self, Directory, Members};
use crate::groups::{self, Team};
use crate::words;

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
    /// Whether this person may change the store, and why not.
    authority: Result<(), String>,
    /// What is being done in the details pane.
    doing: Doing,
    /// What came of the last change: what was done, or why it wasn't.
    said: Option<Result<String, String>>,
}

/// Which list is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Users,
    Groups,
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
            authority: Ok(()),
            doing: Doing::Looking,
            said: None,
        };
        manager.refresh();
        manager
    }

    pub fn ident(&self) -> &Ident {
        &self.ident
    }

    pub fn picked(&self) -> Option<&str> {
        self.picked.as_deref()
    }

    /// Reads everything again, and asks again whether this person may
    /// change it.
    fn refresh(&mut self) {
        self.directory = directory::read(&self.ident);
        self.authority = self.ask_authority();
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
    }

    /// Whether what has been read again in the background differs from what
    /// is shown.
    pub fn differs(&self, directory: &Directory, details: Option<&Result<Record, String>>) -> bool {
        *directory != self.directory || details.is_some_and(|details| Some(details) != self.details.as_ref())
    }

    /// What has been read again in the background, shown. A group's long
    /// member list is read again with it.
    pub fn heard(&mut self, directory: Directory, details: Option<Result<Record, String>>) {
        self.directory = directory;
        if details.is_some() {
            self.details = details;
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
        changeable.then(|| Account::of(record))
    }

    /// Stops whatever was being done in the pane, forgetting any password
    /// typed there.
    fn leave(&mut self, fields: &mut Typed) {
        self.doing = Doing::Looking;
        self.said = None;
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
                    _ => Doing::Password(admin.show(&account.name).ok().and_then(|detail| detail.credential_policy)),
                };
                self.said = None;
                accounts::fill(&self.doing, &account, fields);
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
        if let Some(why) = &self.directory.trouble {
            return format!("<p class=\"trouble\">{}</p>", escape(why));
        }
        let rows: String = match self.view {
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
                (View::Groups, true) => "There are no groups.",
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

    fn details(&self, fields: &Typed) -> String {
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
                View::Groups => "Pick a group to see who is in it.",
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
        if let Some(Value::Claims(claims)) = record.value(Fields::CLAIMS) {
            sections += "<h3>Claims</h3>";
            sections += &if claims.is_empty() {
                "<p class=\"more\">No claims.</p>".to_string()
            } else {
                let rows: String = claims
                    .iter()
                    .map(|claim| {
                        let flags = words::claim_flags(claim);
                        format!(
                            "<li><code>{name}</code><span class=\"type\">{kind}{flags}</span><span class=\"values\">{values}</span></li>",
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
        };
        let new = match (&self.authority, self.view) {
            (Ok(()), View::Users) => "<button type=\"button\" fx-click=\"new\" fx-key=\"Ctrl+N\" title=\"A new user (Ctrl+N)\">New user</button>",
            (Ok(()), View::Groups) => "<button type=\"button\" fx-click=\"new-group\" fx-key=\"Ctrl+N\" title=\"A new group (Ctrl+N)\">New group</button>",
            (Err(_), _) => "",
        };
        format!(
            "<div class=\"bar\"><div class=\"tabs\" role=\"group\" aria-label=\"Show\">{users}{groups}</div>\
             <input name=\"filter\" autocomplete=\"off\" spellcheck=\"false\" placeholder=\"Find by name or SID\" aria-label=\"Find\">\
             {new}<button type=\"button\" fx-click=\"refresh\" fx-key=\"F5\" title=\"Read again (F5)\">Refresh</button></div>{authority}\
             <div class=\"body\"><div class=\"list {class}\">{head}{listing}</div>{details}</div>{footer}",
            users = tab(View::Users, "Users", "users"),
            groups = tab(View::Groups, "Groups", "groups"),
            class = if self.view == View::Users { "users" } else { "groups" },
            listing = self.listing(filter),
            details = self.details(facts.fields),
            footer = self.footer(),
        )
    }

    fn event(&mut self, name: &str, value: &Pressed, fields: &mut Typed) {
        let sid = value["sid"].as_str().filter(|sid| !sid.is_empty());
        match name {
            "users" | "groups" => {
                self.leave(fields);
                self.view = if name == "users" { View::Users } else { View::Groups };
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
            authority: Ok(()),
            doing: Doing::Looking,
            said: None,
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
