//! Changing a local user's claims: the named, typed values that permissions
//! written with conditions are checked against.
//!
//! A claim's values are typed in one box, one to a line, and read as its type
//! says, so a number that isn't one is said to be wrong here, in words,
//! before lpsd is asked. The claim made is checked as lpsd checks it
//! (`Claim::validate`), so what one refuses the other does, for the same
//! reasons.

use libauthd::claim::{Claim, Values};
use libauthd_client::admin::Admin;
use libgxwi::{Fields, escape};

use crate::accounts::{Account, form};
use crate::directory::Directory;
use crate::words;

/// Fills the claim form: for a new claim, or from the claim being changed.
pub fn fill(claim: Option<&Claim>, fields: &mut Fields) {
    match claim {
        Some(claim) => {
            fields.set("claim-name", &claim.name);
            fields.set("claim-type", claim.values.type_name());
            fields.set("claim-values", &words::claim_values(&claim.values).join("\n"));
        }
        None => fields.set("claim-type", "string"),
    }
}

/// The form for a new claim, or for `editing`.
pub fn render(account: &Account, editing: Option<&Claim>, fields: &Fields, said: &str) -> String {
    let chosen = fields.get("claim-type");
    let types: String = words::CLAIM_TYPES
        .iter()
        .map(|(name, shown, _)| format!("<option value=\"{name}\">{shown}</option>"))
        .collect();
    let how = words::CLAIM_TYPES.iter().find(|(name, _, _)| *name == chosen).map_or("", |(_, _, how)| *how);
    let name = match editing {
        None => "<label>Name<input name=\"claim-name\" autocomplete=\"off\" spellcheck=\"false\" fx-autofocus></label>\
                 <p class=\"hint\">What conditions name it by, such as Department. Upper and lower case are the same.</p>",
        Some(_) => "",
    };
    let body = format!(
        "{name}<label>Type<select name=\"claim-type\">{types}</select></label>\
         <label>Values<textarea name=\"claim-values\" rows=\"5\" spellcheck=\"false\"{focus}></textarea></label>\
         <p class=\"hint\">{how}</p>\
         <p class=\"hint\">With none, they have the claim, empty, which isn't the same as not having it.</p>{said}",
        how = escape(how),
        focus = if editing.is_some() { " fx-autofocus" } else { "" },
    );
    match editing {
        None => form("A new claim", "New claim", account.called(), &body, "Add"),
        Some(claim) => form("Change the claim", &claim.name, &format!("A claim of {}", account.name), &body, "Save"),
    }
}

/// The values typed, one to a line, read as `kind` says. Empty lines are
/// left out. A SID may be given as the name of a user or group `directory`
/// holds.
pub fn values(kind: &str, typed: &str, directory: &Directory) -> Result<Values, String> {
    let lines = || typed.lines().map(str::trim).filter(|line| !line.is_empty());
    let bad = |line: &str, what: &str| format!("“{line}” is not {what}.");
    Ok(match kind {
        "string" => Values::String(lines().map(str::to_string).collect()),
        "int64" => Values::Int64(lines().map(|line| line.parse().map_err(|_| bad(line, "a whole number"))).collect::<Result<_, _>>()?),
        "uint64" => Values::Uint64(lines().map(|line| line.parse().map_err(|_| bad(line, "a whole number of 0 or more"))).collect::<Result<_, _>>()?),
        "boolean" => Values::Boolean(
            lines()
                .map(|line| match line.to_lowercase().as_str() {
                    "yes" | "true" | "1" => Ok(true),
                    "no" | "false" | "0" => Ok(false),
                    _ => Err(bad(line, "Yes or No")),
                })
                .collect::<Result<_, _>>()?,
        ),
        "sid" => Values::Sid(
            lines()
                .map(|line| {
                    let text = directory.sid_named(line).unwrap_or(line);
                    text.parse::<peios::security::Sid>()
                        .map(|sid| sid.as_bytes().to_vec())
                        .map_err(|_| bad(line, "a SID, or the name of a user or group here"))
                })
                .collect::<Result<_, _>>()?,
        ),
        "octet" => Values::Octet(lines().map(|line| hex(line).ok_or_else(|| bad(line, "bytes in hexadecimal, such as 0a1b2c"))).collect::<Result<_, _>>()?),
        _ => return Err("Choose a type.".into()),
    })
}

/// Bytes written in hexadecimal, two digits each, spaces and colons between
/// them allowed.
fn hex(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text.bytes().filter(|byte| !matches!(byte, b' ' | b':')).collect();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    digits.chunks(2).map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()).collect()
}

/// Saves the claim form. Answers what was done.
pub fn save(admin: &Admin, account: &Account, editing: Option<&Claim>, fields: &Fields, directory: &Directory) -> Result<String, String> {
    let name = match editing {
        Some(claim) => claim.name.clone(),
        None => fields.get("claim-name").trim().to_string(),
    };
    if name.is_empty() {
        return Err("Give it a name.".into());
    }
    // lpsd would replace it: one name is one claim, whatever its case.
    if editing.is_none() && account.claims.iter().any(|claim| claim.name.eq_ignore_ascii_case(&name)) {
        return Err(format!("They have a claim called {name} already. Change that one instead."));
    }
    let claim = Claim {
        name: name.clone(),
        // Kept as they are: nothing here sets them, as nothing in lps does.
        flags: editing.map_or(0, |claim| claim.flags),
        values: values(fields.get("claim-type"), fields.get("claim-values"), directory)?,
    };
    claim.validate().map_err(|error| words::sentence(&error.to_string()))?;
    if editing == Some(&claim) {
        return Ok("Nothing was changed.".into());
    }
    admin.set_claim(&account.name, claim).map_err(|refusal| refusal.reason)?;
    Ok(format!(
        "{}'s claim {name} is {}. It applies from their next sign-in.",
        account.name,
        if editing.is_some() { "changed" } else { "added" },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::Group;

    fn directory() -> Directory {
        Directory {
            groups: vec![Group {
                sid: "S-1-5-21-1-2-3-1100".into(),
                name: "PEIOS\\developers".into(),
                local: true,
                members: crate::directory::Members::Counted(0),
                description: String::new(),
            }],
            ..Directory::default()
        }
    }

    #[test]
    fn values_are_read_as_their_type_says_one_to_a_line() {
        let directory = directory();
        assert_eq!(values("int64", "-3\n\n 7 ", &directory), Ok(Values::Int64(vec![-3, 7])));
        assert_eq!(values("boolean", "Yes\nno", &directory), Ok(Values::Boolean(vec![true, false])));
        assert_eq!(values("octet", "de:ad be ef", &directory), Ok(Values::Octet(vec![vec![0xde, 0xad, 0xbe, 0xef]])));
        assert_eq!(values("string", "", &directory), Ok(Values::String(vec![])), "no values is an empty claim");
        let Ok(Values::Sid(sids)) = values("sid", "S-1-5-32-544\ndevelopers", &directory) else { panic!("a SID and a name are SIDs") };
        assert_eq!(crate::directory::sid_text(&sids[1]), "S-1-5-21-1-2-3-1100");

        assert_eq!(values("uint64", "-1", &directory), Err("“-1” is not a whole number of 0 or more.".into()));
        assert_eq!(values("boolean", "maybe", &directory), Err("“maybe” is not Yes or No.".into()));
        assert!(values("sid", "nobody", &directory).is_err());
        assert!(values("octet", "abc", &directory).is_err());
    }

    #[test]
    fn a_claim_being_changed_fills_the_form_as_it_would_be_typed() {
        let mut fields = Fields::default();
        let claim = Claim { name: "Cleared".into(), flags: 0, values: Values::Boolean(vec![true, false]) };
        fill(Some(&claim), &mut fields);
        assert_eq!(fields.get("claim-type"), "boolean");
        assert_eq!(values(fields.get("claim-type"), fields.get("claim-values"), &directory()), Ok(claim.values.clone()));
        let account = Account { claims: vec![claim.clone()], ..crate::accounts::tests::dana() };
        let form = render(&account, Some(&claim), &fields, "");
        assert!(form.contains("<h2>Cleared</h2><p class=\"id\">A claim of dana</p>") && !form.contains("claim-name"), "{form}");
        assert!(form.contains("Yes or No, one to a line."), "the type's own hint: {form}");
    }
}
