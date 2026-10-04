//! A local user's SSH public keys: adding one, and the ID a key is removed
//! by.
//!
//! A key is what they may sign in with by SSH, but only once Sign-in allows
//! a key: lpsd keeps adding a key and allowing one apart (PSPU §10.8), and
//! so does this, saying so where it matters.

use libauthd_client::admin::Admin;

use crate::accounts::{Account, form};

/// The form adding a key.
pub fn render(account: &Account, said: &str) -> String {
    let note = match account.policy {
        Some(policy) if !policy.ssh() => {
            "<p class=\"note\">Sign-in doesn't allow them a key now, so this one won't be used until it does.</p>"
        }
        _ => "",
    };
    form(
        "Add an SSH key",
        "Add an SSH key",
        account.called(),
        &format!(
            "<label>Public key<textarea name=\"key\" rows=\"4\" spellcheck=\"false\" fx-autofocus></textarea></label>\
             <p class=\"hint\">One line of their <code>.pub</code> file, such as <code>~/.ssh/id_ed25519.pub</code>: Ed25519, or RSA of 3072 bits or more.</p>\
             <label>Label<input name=\"key-label\" autocomplete=\"off\"></label>\
             <p class=\"hint\">What the key is, such as the machine it is on. Empty, it is the key's own comment.</p>{note}{said}"
        ),
        "Add",
    )
}

/// Saves the form adding a key.
pub fn save(admin: &Admin, account: &Account, fields: &libgxwi::Fields) -> Result<String, String> {
    let key = fields.get("key").trim();
    if key.is_empty() {
        return Err("Paste their public key.".into());
    }
    admin.key_add(&account.name, key, fields.get("key-label").trim()).map_err(|refusal| refusal.reason)?;
    Ok(match account.policy {
        Some(policy) if !policy.ssh() => format!("The key is added. {} can't sign in with it until Sign-in allows a key.", account.name),
        _ => "The key is added.".into(),
    })
}

/// A key's ID as a form sends it.
pub fn id_text(id: &[u8; 16]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A key's ID from a form.
pub fn id_of(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 || !text.is_ascii() {
        return None;
    }
    let mut id = [0; 16];
    for (at, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[at * 2..at * 2 + 2], 16).ok()?;
    }
    Some(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libauthd::credential::Policy;

    #[test]
    fn a_key_s_id_goes_and_comes_back() {
        let id = [0xab; 16];
        assert_eq!(id_of(&id_text(&id)), Some(id));
        assert_eq!(id_of("not an id"), None);
    }

    #[test]
    fn a_key_not_yet_allowed_is_said_to_be() {
        let account = Account { policy: Some(Policy::Password), ..crate::accounts::tests::dana() };
        assert!(render(&account, "").contains("won't be used until it does"));
        let account = Account { policy: Some(Policy::PasswordOrKey), ..account };
        assert!(!render(&account, "").contains("won't be used"));
    }
}
