//! Changing groups: making a local one, describing, renaming and deleting
//! it, and who is in a group, local or `BUILTIN`.
//!
//! As for users, each change is a request to lpsd, whose refusals are shown
//! in its words. A local group is named to lpsd by its name; a group someone
//! is put in or taken out of is named by its SID, which lpsd reads as
//! readily, and which can't mean a different group.

use libauthd::ident::Record;
use libauthd_client::admin::Admin;
use libgxwi::{Fields, escape};

use crate::accounts::{self, Doing, form, options, short};
use crate::directory;

/// A group, as the forms need it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Team {
    /// The name lpsd knows a local group by.
    pub name: String,
    pub sid: String,
    pub description: String,
    /// One of this machine's, which may be renamed, described and deleted.
    pub local: bool,
}

impl Team {
    pub fn of(record: &Record) -> Team {
        let sid = directory::sid_text(&record.sid);
        Team { name: short(&record.qualified_name).to_string(), description: directory::description(record), local: directory::local(&sid), sid }
    }
}

/// Fills a form's fields from the group it changes.
pub fn fill(doing: &Doing, team: &Team, fields: &mut Fields) {
    accounts::clear(fields);
    match doing {
        Doing::GroupEdit => fields.set("description", &team.description),
        Doing::GroupRename => fields.set("new-name", &team.name),
        _ => {}
    }
}

/// The form for what is being done to a group, or a new one. `choices` are
/// the users who may be added, by name and how they are shown.
pub fn render(doing: &Doing, team: Option<&Team>, said: &str, choices: &[(String, String)]) -> String {
    let form = |label: &str, title: &str, id: &str, body: &str, save: &str| form(label, title, id, &format!("{body}{said}"), save);
    match (doing, team) {
        (Doing::NewGroup, _) => form(
            "A new group",
            "New group",
            "",
            "<label>Name<input name=\"name\" autocomplete=\"off\" spellcheck=\"false\" fx-autofocus></label>\
             <label>Description<input name=\"description\" autocomplete=\"off\"></label>\
             <p class=\"hint\">What the group is for. Anyone may read it.</p>",
            "Create",
        ),
        (Doing::GroupEdit, Some(team)) => form(
            "Describe the group",
            &team.name,
            "",
            "<label>Description<input name=\"description\" autocomplete=\"off\" fx-autofocus></label>\
             <p class=\"hint\">What the group is for. Anyone may read it. Empty, it has none.</p>",
            "Save",
        ),
        (Doing::GroupRename, Some(team)) => form(
            "Rename the group",
            &team.name,
            "",
            "<label>New name<input name=\"new-name\" autocomplete=\"off\" spellcheck=\"false\" fx-autofocus></label>\
             <p class=\"hint\">It keeps its SID, so its members, and the permissions that name it, stay as they are.</p>",
            "Rename",
        ),
        (Doing::AddMember, Some(team)) if choices.is_empty() => form(
            "Add a member",
            &team.name,
            "",
            "<p class=\"more\">Every local user is in it already.</p>",
            "Add",
        ),
        (Doing::AddMember, Some(team)) => form(
            "Add a member",
            &team.name,
            "",
            &format!(
                "<label>Add<select name=\"member\" fx-autofocus>{}</select></label>\
                 <p class=\"hint\">It applies from their next sign-in.</p>",
                options(choices),
            ),
            "Add",
        ),
        _ => String::new(),
    }
}

/// Asking before a local group is deleted. lpsd refuses to delete one
/// anyone is in, so a group with members says so rather than offering to.
pub fn asking_delete(team: &Team, members: usize) -> String {
    if members > 0 {
        return format!(
            "<div class=\"asking\" role=\"alertdialog\" aria-label=\"Delete the group\"><p><strong>{name}</strong> has {members}. \
             Take them out of it before deleting it, and give anyone whose primary group it is another.</p>\
             <button type=\"button\" fx-click=\"cancel\" fx-key=\"Escape\" fx-autofocus>Cancel</button></div>",
            name = escape(&team.name),
            members = escape(&crate::words::count(members, "member")),
        );
    }
    format!(
        "<div class=\"asking\" role=\"alertdialog\" aria-label=\"Delete the group\"><p>Delete <strong>{name}</strong>? This can't be undone.</p>\
         <p>Its SID is never given to anything again, so permissions that name it will name nothing.</p>\
         <button type=\"button\" class=\"danger\" fx-click=\"delete-group-yes\">Delete</button>\
         <button type=\"button\" fx-click=\"cancel\" fx-key=\"Escape\" fx-autofocus>Cancel</button></div>",
        name = escape(&team.name),
    )
}

/// Makes the group the form describes, and answers its name and RID.
pub fn create(admin: &Admin, fields: &Fields) -> Result<(String, u32), String> {
    let name = fields.get("name").trim().to_string();
    if name.is_empty() {
        return Err("Give it a name.".into());
    }
    let rid = admin.group_create(&name, fields.get("description").trim()).map_err(|refusal| refusal.reason)?;
    Ok((name, rid))
}

/// Saves the description form.
pub fn save_description(admin: &Admin, team: &Team, fields: &Fields) -> Result<String, String> {
    let description = fields.get("description").trim();
    if description == team.description {
        return Ok("Nothing was changed.".into());
    }
    admin.group_describe(&team.name, description).map_err(|refusal| refusal.reason)?;
    Ok(format!("{}'s description is {}.", team.name, if description.is_empty() { "cleared" } else { "set" }))
}

/// Saves the rename form. Answers what was done.
pub fn save_rename(admin: &Admin, team: &Team, fields: &Fields) -> Result<String, String> {
    let new_name = fields.get("new-name").trim().to_string();
    if new_name.is_empty() {
        return Err("Give it a name.".into());
    }
    admin.group_rename(&team.name, &new_name).map_err(|refusal| refusal.reason)?;
    Ok(format!("{} is now called {new_name}.", team.name))
}

/// Saves the form adding a member.
pub fn save_member(admin: &Admin, team: &Team, fields: &Fields) -> Result<String, String> {
    let member = fields.get("member");
    if member.is_empty() {
        return Err("Choose someone to add.".into());
    }
    admin.group_add(member, &team.sid).map_err(|refusal| refusal.reason)?;
    Ok(format!("{member} is in {}. It applies from their next sign-in.", team.name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use libauthd::ident::{Kind, Value};

    fn developers() -> Team {
        Team { name: "developers".into(), sid: "S-1-5-21-1-2-3-1100".into(), description: "Builds the software".into(), local: true }
    }

    #[test]
    fn a_group_is_read_from_its_record() {
        let record = Record {
            sid: "S-1-5-21-1-2-3-1100".parse::<peios::security::Sid>().unwrap().as_bytes().to_vec(),
            qualified_name: "PEIOS\\developers".into(),
            kind_found: Kind::Group,
            values: vec![Value::Description("Builds the software".into())],
            withheld: vec![],
        };
        assert_eq!(Team::of(&record), developers());
    }

    #[test]
    fn a_group_with_members_is_not_offered_for_deleting() {
        let asked = asking_delete(&developers(), 2);
        assert!(asked.contains("has 2 members") && !asked.contains("delete-group-yes"), "{asked}");
        assert!(asking_delete(&developers(), 0).contains("delete-group-yes"));
    }

    #[test]
    fn adding_a_member_offers_who_may_be_added() {
        let choices = vec![("alice".to_string(), "alice".to_string())];
        assert!(render(&Doing::AddMember, Some(&developers()), "", &choices).contains("<option value=\"alice\">alice</option>"));
        assert!(render(&Doing::AddMember, Some(&developers()), "", &[]).contains("Every local user is in it already."));
    }
}
