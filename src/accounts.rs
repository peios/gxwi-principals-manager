//! Changing a local user: making one, its profile, its name, its password,
//! how it may sign in, enabling, disabling and deleting it.
//!
//! Every change is a request to lpsd's admin socket, as whoever is looking;
//! lpsd decides, and a refusal is shown in its own words. The forms here are
//! drawn in the details pane, in place of the user they change.
//!
//! A password typed here is a field like any other, which every page
//! showing the window is sent, so it is cleared as soon as it is used or the
//! form is left.

use libauthd::claim::Claim;
use libauthd::credential::Policy;
use libauthd::ident::{Fields as Asked, Record, Value};
use libauthd::lps::{self, KeyInfo, LogonTypes};
use libauthd_client::admin::Admin;
use libgxwi::{Fields, escape};

use crate::{claims, directory, keys, words};

/// What is being done in the details pane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Doing {
    Looking,
    /// A new user.
    New,
    /// The picked user's full name, home and shell.
    Profile,
    Rename,
    /// A new password, and the user's credential policy when it was asked
    /// for, which says whether the password will be used.
    Password(Option<Policy>),
    /// What the user signs in with, and which kinds of sign-in they may use.
    SignIn,
    /// An SSH key for the user.
    AddKey,
    /// A new claim for the user.
    NewClaim,
    /// The user's claim of this name.
    EditClaim(String),
    /// Asking before the user is deleted.
    Deleting,
    /// A group for the picked user to join.
    Join,
    /// A new local group.
    NewGroup,
    /// The picked group's description.
    GroupEdit,
    GroupRename,
    /// Asking before the picked group is deleted.
    GroupDeleting,
    /// A user to put in the picked group.
    AddMember,
    /// A new policy record.
    NewRecord,
    /// The picked policy record.
    EditRecord,
    /// Asking before the picked policy record is deleted.
    RecordDeleting,
    /// The privileges denied to everyone.
    EditDenied,
}

/// The fields a password is typed in, cleared whenever a form is left.
const SECRETS: &[&str] = &["password", "again"];

/// A local user, as the forms need them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// The name lpsd knows them by.
    pub name: String,
    pub full: String,
    pub home: String,
    pub shell: String,
    pub enabled: bool,
    pub types: LogonTypes,
    /// Their primary group's SID, as text; empty where it wasn't said.
    pub primary: String,
    pub claims: Vec<Claim>,
    /// What they may sign in with, and their SSH keys: lpsd's to say, and
    /// only to an administrator, so `None` and none until it has.
    pub policy: Option<Policy>,
    pub keys: Vec<KeyInfo>,
}

impl Account {
    pub fn of(record: &Record) -> Account {
        let text = |field| match record.value(field) {
            Some(Value::DisplayName(text) | Value::Home(text) | Value::Shell(text)) => text.clone(),
            _ => String::new(),
        };
        Account {
            name: short(&record.qualified_name).to_string(),
            full: text(Asked::DISPLAY_NAME),
            home: text(Asked::HOME),
            shell: text(Asked::SHELL),
            enabled: !matches!(record.value(Asked::ENABLED), Some(Value::Enabled(false))),
            types: match record.value(Asked::LOGON_TYPES) {
                Some(Value::LogonTypes(types)) => *types,
                _ => LogonTypes::UNSTATED,
            },
            primary: match record.value(Asked::PRIMARY_GROUP) {
                Some(Value::PrimaryGroup(group)) => directory::sid_text(&group.sid),
                _ => String::new(),
            },
            claims: match record.value(Asked::CLAIMS) {
                Some(Value::Claims(claims)) => claims.clone(),
                _ => Vec::new(),
            },
            policy: None,
            keys: Vec::new(),
        }
    }

    /// What they are called to a person: their full name, if they have one.
    pub fn called(&self) -> &str {
        if self.full.is_empty() { &self.name } else { &self.full }
    }
}

/// A name without the domain it is qualified with. lpsd's names can't hold
/// a backslash, so what follows the last one is the name.
pub fn short(qualified: &str) -> &str {
    qualified.rsplit('\\').next().unwrap_or(qualified)
}

/// Empties the fields a form fills, so each starts afresh.
pub fn clear(fields: &mut Fields) {
    for name in [
        "name", "full", "home", "shell", "no-password", "administrator", "new-name", "which", "credential", "primary", "description", "member", "group", "key",
        "key-label", "claim-name", "claim-type", "claim-values", "principal", "integrity", "owner", "dacl",
    ] {
        fields.set(name, "");
    }
    for index in 0..peios::security::Privileges::all_named().count() {
        fields.set(&format!("priv-{index}"), "");
    }
    forget(fields);
    for index in 0..words::LOGON_TYPES.len() {
        fields.set(&format!("type-{index}"), "");
    }
}

/// Empties the password fields.
pub fn forget(fields: &mut Fields) {
    for name in SECRETS {
        fields.set(name, "");
    }
}

/// Fills a form's fields from the user it changes.
pub fn fill(doing: &Doing, account: &Account, fields: &mut Fields) {
    clear(fields);
    match doing {
        Doing::Profile => {
            fields.set("full", &account.full);
            fields.set("home", &account.home);
            fields.set("shell", &account.shell);
            fields.set("primary", &account.primary);
        }
        Doing::Rename => fields.set("new-name", &account.name),
        Doing::SignIn => {
            fields.set("credential", account.policy.map_or("", words::policy_value));
            fields.set("which", if account.types.is_unstated() { "default" } else { "chosen" });
            for (index, (logon_type, _)) in words::LOGON_TYPES.iter().enumerate() {
                if account.types.permits(*logon_type) {
                    fields.set(&format!("type-{index}"), "on");
                }
            }
        }
        _ => {}
    }
}

fn buttons(save: &str) -> String {
    format!(
        "<p class=\"actions\"><button type=\"submit\" class=\"primary\">{save}</button>\
         <button type=\"button\" fx-click=\"cancel\" fx-key=\"Escape\">Cancel</button></p>"
    )
}

/// A form in the details pane: its title, the name below it where there is
/// one, its fields and its buttons.
pub fn form(label: &str, title: &str, id: &str, body: &str, save: &str) -> String {
    // The name below the title only where the title is something else.
    let id = if id.is_empty() || id == title { String::new() } else { format!("<p class=\"id\">{}</p>", escape(id)) };
    format!(
        "<aside class=\"details\" aria-label=\"{label}\"><form class=\"edit\" fx-submit=\"save\"><h2>{title}</h2>{id}{body}{}</form></aside>",
        buttons(save),
        title = escape(title),
    )
}

/// A list's options: each group's SID as its value, and its name shown.
pub fn options(choices: &[(String, String)]) -> String {
    choices.iter().map(|(sid, name)| format!("<option value=\"{}\">{}</option>", escape(sid), escape(name))).collect()
}

/// The form for what is being done, for `account` where there is one, with
/// what came of saving it just above its buttons, where it was pressed.
/// `choices` are the groups the form may offer, by SID and name.
pub fn render(doing: &Doing, account: Option<&Account>, fields: &Fields, said: &str, choices: &[(String, String)]) -> String {
    let form = |label: &str, title: &str, id: &str, body: &str, save: &str| form(label, title, id, &format!("{body}{said}"), save);
    match (doing, account) {
        (Doing::New, _) => form(
            "A new user",
            "New user",
            "",
            &format!(
                "<label>Name<input name=\"name\" autocomplete=\"off\" spellcheck=\"false\" fx-autofocus></label>\
                 <label>Full name<input name=\"full\" autocomplete=\"off\"></label>\
                 {password}\
                 <label class=\"check\"><input type=\"checkbox\" name=\"no-password\"> Signs in without a password</label>\
                 <label class=\"check\"><input type=\"checkbox\" name=\"administrator\"> Administrator</label>\
                 <p class=\"hint\">An administrator may change this machine, and its users and groups.</p>\
                 <label>Home<input name=\"home\" autocomplete=\"off\" spellcheck=\"false\" placeholder=\"/home/name\"></label>\
                 <label>Shell<input name=\"shell\" autocomplete=\"off\" spellcheck=\"false\" placeholder=\"/bin/sh\"></label>",
                password = if fields.get("no-password").is_empty() { password_fields(false) } else { String::new() },
            ),
            "Create",
        ),
        (Doing::Profile, Some(account)) => form(
            "Edit the user",
            account.called(),
            &account.name,
            &format!(
                "<label>Full name<input name=\"full\" autocomplete=\"off\" fx-autofocus></label>\
                 <label>Home<input name=\"home\" autocomplete=\"off\" spellcheck=\"false\"></label>\
                 <p class=\"hint\">Where they start when they sign in. The folder is made at their first sign-in, and not moved if this changes.</p>\
                 <label>Shell<input name=\"shell\" autocomplete=\"off\" spellcheck=\"false\"></label>\
                 <label>Primary group<select name=\"primary\">{}</select></label>\
                 <p class=\"hint\">The group their new files belong to. They are in it, whatever their other groups.</p>",
                options(choices),
            ),
            "Save",
        ),
        (Doing::Join, Some(account)) if choices.is_empty() => form(
            "Add the user to a group",
            account.called(),
            &account.name,
            "<p class=\"more\">They are in every group they could be put in already.</p>",
            "Add",
        ),
        (Doing::Join, Some(account)) => form(
            "Add the user to a group",
            account.called(),
            &account.name,
            &format!(
                "<label>Add them to<select name=\"group\" fx-autofocus>{}</select></label>\
                 <p class=\"hint\">It applies from their next sign-in.</p>",
                options(choices),
            ),
            "Add",
        ),
        (Doing::Rename, Some(account)) => form(
            "Rename the user",
            account.called(),
            &account.name,
            &format!(
                "<label>New name<input name=\"new-name\" autocomplete=\"off\" spellcheck=\"false\" fx-autofocus></label>\
                 <p class=\"hint\">They keep their SID, so their files, permissions and groups stay theirs. They sign in by the new name.</p>\
                 <p class=\"hint\">Their home stays <code>{}</code>; change it under Edit if it should follow.</p>",
                escape(&account.home),
            ),
            "Rename",
        ),
        (Doing::Password(policy), Some(account)) => {
            let note = match policy {
                Some(Policy::NoCredential) => "<p class=\"note\">They sign in without a password now. Once this is set, they will need it.</p>",
                Some(Policy::SshPublicKey) => "<p class=\"note\">They sign in only with an SSH key, so this password won't be used until passwords are allowed.</p>",
                Some(Policy::Denied) => "<p class=\"note\">Signing in is denied to them whatever they use, so this password won't be used until that changes.</p>",
                _ => "",
            };
            form(
                "Set the password",
                account.called(),
                &account.name,
                &format!("{}{note}<p class=\"hint\">Their sessions already signed in carry on.</p>", password_fields(true)),
                "Set password",
            )
        }
        (Doing::SignIn, Some(account)) => {
            let default = fields.get("which") != "chosen";
            let off = if default { " disabled" } else { "" };
            let types: String = words::LOGON_TYPES
                .iter()
                .enumerate()
                .map(|(index, (_, said))| format!("<label class=\"check\"><input type=\"checkbox\" name=\"type-{index}\"{off}> {}</label>", escape(said)))
                .collect();
            let defaults = words::logon_types(LogonTypes::UNSTATED).join(", ").to_lowercase();
            // What they sign in with is lpsd's to say; where it hasn't, it
            // isn't offered, rather than guessed at.
            let credential = match account.policy {
                None => String::new(),
                Some(_) => {
                    let policies: String = words::POLICIES
                        .iter()
                        .map(|(_, sent, said)| format!("<label class=\"check\"><input type=\"radio\" name=\"credential\" value=\"{sent}\"> {}</label>", escape(said)))
                        .collect();
                    let note = match words::policy_of(fields.get("credential")) {
                        Some(Policy::Password) => "<p class=\"hint\">If they have no password yet, set one under Set password.</p>",
                        Some(Policy::SshPublicKey) if account.keys.is_empty() => {
                            "<p class=\"note\">They have no SSH key yet. Add one under SSH keys, or they can't sign in.</p>"
                        }
                        Some(Policy::NoCredential) => "<p class=\"note\">Anyone at a sign-in prompt on this machine can sign in as them.</p>",
                        Some(Policy::Denied) => "<p class=\"hint\">They can't sign in however they try. Disable them instead if that is what you mean: it says so.</p>",
                        _ => "",
                    };
                    format!("<fieldset class=\"choice\"><legend>Signs in with</legend>{policies}</fieldset>{note}")
                }
            };
            form(
                "How the user may sign in",
                account.called(),
                &account.name,
                &format!(
                    "{credential}<fieldset class=\"choice\"><legend>May sign in</legend>\
                     <label class=\"check\"><input type=\"radio\" name=\"which\" value=\"default\"> As the machine's default allows</label>\
                     <p class=\"hint\">{}.</p>\
                     <label class=\"check\"><input type=\"radio\" name=\"which\" value=\"chosen\"> Only these ways</label>\
                     <div class=\"types\">{types}</div></fieldset>\
                     <p class=\"hint\">To run a service lets the service manager start a service as them without any password. To stop them signing in at all, disable them.</p>",
                    escape(&capital(&defaults)),
                ),
                "Save",
            )
        }
        (Doing::AddKey, Some(account)) => keys::render(account, said),
        (Doing::NewClaim, Some(account)) => claims::render(account, None, fields, said),
        (Doing::EditClaim(name), Some(account)) => match account.claims.iter().find(|claim| claim.name == *name) {
            Some(claim) => claims::render(account, Some(claim), fields, said),
            None => String::new(),
        },
        _ => String::new(),
    }
}

/// The password and its confirmation.
fn password_fields(focus: bool) -> String {
    format!(
        "<label>Password<input type=\"password\" name=\"password\" autocomplete=\"new-password\"{}></label>\
         <label>Again<input type=\"password\" name=\"again\" autocomplete=\"new-password\"></label>",
        if focus { " fx-autofocus" } else { "" },
    )
}

fn capital(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map(|first| first.to_uppercase().chain(chars).collect()).unwrap_or_default()
}

/// Asking before a user is deleted, offering to disable them instead.
pub fn asking_delete(account: &Account) -> String {
    let instead = if account.enabled {
        "<button type=\"button\" fx-click=\"disable-instead\">Disable instead</button>"
    } else {
        ""
    };
    format!(
        "<div class=\"asking\" role=\"alertdialog\" aria-label=\"Delete the user\"><p>Delete <strong>{name}</strong>? This can't be undone.</p>\
         <p>Their SID is never given to anyone again, so files and permissions that name it will name nobody. \
         Disabling them keeps everything and stops them signing in.</p>\
         <button type=\"button\" class=\"danger\" fx-click=\"delete-yes\">Delete</button>{instead}\
         <button type=\"button\" fx-click=\"cancel\" fx-key=\"Escape\" fx-autofocus>Cancel</button></div>",
        name = escape(account.called()),
    )
}

/// The password typed, if it was typed the same twice.
fn password(fields: &Fields) -> Result<String, String> {
    let password = fields.get("password");
    if password.is_empty() {
        return Err("Type a password.".into());
    }
    if password != fields.get("again") {
        return Err("The two passwords differ.".into());
    }
    Ok(password.to_string())
}

/// `None` for an empty field: lpsd's default.
fn given(fields: &Fields, name: &str) -> Option<String> {
    let value = fields.get(name).trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// Makes the user the form describes, and answers their name and RID.
pub fn create(admin: &Admin, fields: &Fields) -> Result<(String, u32), String> {
    let name = fields.get("name").trim().to_string();
    if name.is_empty() {
        return Err("Give them a name.".into());
    }
    let secret = if fields.get("no-password").is_empty() { Some(password(fields)?) } else { None };
    let rid = admin
        .add(&lps::Add {
            name: name.clone(),
            credential: match &secret {
                Some(secret) => lps::Credential::Password(secret.as_bytes()),
                None => lps::Credential::None,
            },
            enabled: true,
            groups: if fields.get("administrator").is_empty() { Vec::new() } else { vec!["Administrators".into()] },
            permitted_logon_types: LogonTypes::UNSTATED,
            primary_group: None,
            home: given(fields, "home"),
            shell: given(fields, "shell"),
            display_name: given(fields, "full"),
        })
        .map_err(|refusal| refusal.reason)?;
    Ok((name, rid))
}

/// Saves the profile form. Answers what was done.
pub fn save_profile(admin: &Admin, account: &Account, fields: &Fields) -> Result<String, String> {
    let changed = |now: &str, was: &str| (now.trim() != was).then(|| now.trim().to_string());
    let profile = lps::SetProfile {
        name: account.name.clone(),
        display_name: changed(fields.get("full"), &account.full),
        home: changed(fields.get("home"), &account.home),
        shell: changed(fields.get("shell"), &account.shell),
    };
    let primary = changed(fields.get("primary"), &account.primary).filter(|primary| !primary.is_empty());
    if profile.display_name.is_none() && profile.home.is_none() && profile.shell.is_none() && primary.is_none() {
        return Ok("Nothing was changed.".into());
    }
    if profile.display_name.is_some() || profile.home.is_some() || profile.shell.is_some() {
        admin.set_profile(&profile).map_err(|refusal| refusal.reason)?;
    }
    if let Some(primary) = primary {
        admin.set_primary_group(&account.name, &primary).map_err(|refusal| refusal.reason)?;
    }
    Ok(format!("{} is changed.", account.name))
}

/// Saves the form adding the user to a group, sent as its SID.
pub fn save_join(admin: &Admin, account: &Account, fields: &Fields) -> Result<String, String> {
    let group = fields.get("group");
    if group.is_empty() {
        return Err("Choose a group.".into());
    }
    admin.group_add(&account.name, group).map_err(|refusal| refusal.reason)?;
    Ok(format!("{} is added. It applies from their next sign-in.", account.name))
}

/// Saves the rename form. Answers the new name.
pub fn save_rename(admin: &Admin, account: &Account, fields: &Fields) -> Result<String, String> {
    let new_name = fields.get("new-name").trim().to_string();
    if new_name.is_empty() {
        return Err("Give them a name.".into());
    }
    admin.rename(&account.name, &new_name).map_err(|refusal| refusal.reason)?;
    Ok(new_name)
}

/// Saves the password form, letting a user who needed no password sign in
/// with the one set: what giving them one means (PSPU §10.5).
pub fn save_password(admin: &Admin, account: &Account, policy: Option<Policy>, fields: &Fields) -> Result<String, String> {
    let secret = password(fields)?;
    admin.set_password(&account.name, secret.as_bytes()).map_err(|refusal| refusal.reason)?;
    if policy == Some(Policy::NoCredential) {
        admin
            .set_credential_policy(&account.name, Policy::Password)
            .map_err(|refusal| format!("The password is set, but they still sign in without it: {}", refusal.reason))?;
        return Ok(format!("{}'s password is set, and they now sign in with it.", account.name));
    }
    Ok(format!("{}'s password is set.", account.name))
}

/// The kinds of sign-in the form chose.
pub fn chosen_types(fields: &Fields) -> Result<LogonTypes, String> {
    if fields.get("which") != "chosen" {
        return Ok(LogonTypes::UNSTATED);
    }
    let types = words::LOGON_TYPES
        .iter()
        .enumerate()
        .filter(|(index, _)| !fields.get(&format!("type-{index}")).is_empty())
        .fold(LogonTypes::UNSTATED, |types, (_, (logon_type, _))| types.with(*logon_type));
    if types.is_unstated() {
        return Err("Choose at least one way, or disable them to stop them signing in.".into());
    }
    Ok(types)
}

/// Saves the sign-in form: what they sign in with, then the kinds of
/// sign-in, each only if it changed. They are two requests, so a refusal of
/// the second says the first was made.
pub fn save_sign_in(admin: &Admin, account: &Account, fields: &Fields) -> Result<String, String> {
    let types = chosen_types(fields)?;
    let policy = words::policy_of(fields.get("credential")).filter(|policy| Some(*policy) != account.policy);
    if policy.is_none() && types == account.types {
        return Ok("Nothing was changed.".into());
    }
    if let Some(policy) = policy {
        admin.set_credential_policy(&account.name, policy).map_err(|refusal| refusal.reason)?;
    }
    if types != account.types {
        admin.set_logon_types(&account.name, types).map_err(|refusal| match policy {
            Some(_) => format!("What they sign in with is changed, but not the ways they may: {}", refusal.reason),
            None => refusal.reason,
        })?;
    }
    Ok(format!("How {} may sign in is changed. It applies from their next sign-in.", account.name))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use libauthd::ident::Kind;
    use libauthd::wire::LogonType;

    pub fn dana() -> Account {
        Account {
            name: "dana".into(),
            full: "Dana Scully".into(),
            home: "/home/dana".into(),
            shell: "/bin/sh".into(),
            enabled: true,
            types: LogonTypes::UNSTATED,
            primary: "S-1-5-11".into(),
            claims: Vec::new(),
            policy: Some(Policy::Password),
            keys: Vec::new(),
        }
    }

    #[test]
    fn the_sign_in_form_offers_what_they_sign_in_with_only_where_lpsd_said() {
        let mut fields = Fields::default();
        fill(&Doing::SignIn, &dana(), &mut fields);
        assert_eq!(fields.get("credential"), "password");
        let form = render(&Doing::SignIn, Some(&dana()), &fields, "", &[]);
        assert!(form.contains("<legend>Signs in with</legend>") && form.contains("value=\"either\""), "{form}");

        fields.set("credential", "key");
        assert!(render(&Doing::SignIn, Some(&dana()), &fields, "", &[]).contains("They have no SSH key yet."));

        let unsaid = Account { policy: None, ..dana() };
        fill(&Doing::SignIn, &unsaid, &mut fields);
        assert!(!render(&Doing::SignIn, Some(&unsaid), &fields, "", &[]).contains("Signs in with"));
    }

    #[test]
    fn an_account_is_read_from_its_record() {
        let record = Record {
            sid: Vec::new(),
            qualified_name: "PEIOS\\dana".into(),
            kind_found: Kind::Principal,
            values: vec![
                Value::DisplayName("Dana Scully".into()),
                Value::Home("/home/dana".into()),
                Value::Enabled(false),
                Value::LogonTypes(LogonTypes::SERVICE_ONLY),
            ],
            withheld: vec![],
        };
        let account = Account::of(&record);
        assert_eq!(account.name, "dana");
        assert_eq!(account.called(), "Dana Scully");
        assert_eq!(account.home, "/home/dana");
        assert_eq!(account.shell, "");
        assert!(!account.enabled);
        assert_eq!(account.types, LogonTypes::SERVICE_ONLY);
    }

    #[test]
    fn a_password_must_be_typed_the_same_twice() {
        let mut fields = Fields::default();
        assert!(password(&fields).is_err());
        fields.set("password", "hunter2");
        fields.set("again", "hunter3");
        assert_eq!(password(&fields).unwrap_err(), "The two passwords differ.");
        fields.set("again", "hunter2");
        assert_eq!(password(&fields).unwrap(), "hunter2");
        forget(&mut fields);
        assert_eq!(fields.get("password"), "");
        assert_eq!(fields.get("again"), "");
    }

    #[test]
    fn the_sign_in_form_starts_from_what_they_may_do_and_says_what_was_chosen() {
        let mut fields = Fields::default();
        fill(&Doing::SignIn, &dana(), &mut fields);
        assert_eq!(fields.get("which"), "default");
        assert_eq!(chosen_types(&fields).unwrap(), LogonTypes::UNSTATED);
        // The default's ways are ticked, ready to narrow.
        assert_eq!(fields.get("type-0"), "on");
        assert!(render(&Doing::SignIn, Some(&dana()), &fields, "", &[]).contains("name=\"type-0\" disabled"));

        fields.set("which", "chosen");
        for index in 0..words::LOGON_TYPES.len() {
            fields.set(&format!("type-{index}"), "");
        }
        assert!(chosen_types(&fields).is_err(), "nothing chosen is not a way to stop them signing in");
        let network = words::LOGON_TYPES.iter().position(|(logon_type, _)| *logon_type == LogonType::Network).unwrap();
        fields.set(&format!("type-{network}"), "on");
        assert_eq!(chosen_types(&fields).unwrap(), LogonTypes::UNSTATED.with(LogonType::Network));
    }

    #[test]
    fn the_new_user_form_asks_for_a_password_unless_none_is_needed() {
        let mut fields = Fields::default();
        assert!(render(&Doing::New, None, &fields, "", &[]).contains("type=\"password\" name=\"password\""));
        fields.set("no-password", "on");
        assert!(!render(&Doing::New, None, &fields, "", &[]).contains("type=\"password\""));
    }

    #[test]
    fn deleting_says_what_is_lost_and_offers_to_disable_instead() {
        let asked = asking_delete(&dana());
        assert!(asked.contains("Their SID is never given to anyone again"));
        assert!(asked.contains("fx-click=\"disable-instead\""));
        let off = Account { enabled: false, ..dana() };
        assert!(!asking_delete(&off).contains("disable-instead"));
    }
}
