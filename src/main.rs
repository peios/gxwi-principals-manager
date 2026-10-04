//! Principals Manager: this machine's users and groups, who is in which, and
//! what each may do, as far as the person looking may see and change them.
//!
//! It reads from authd's identity socket and changes the local store through
//! lpsd's admin socket, as whoever is looking, with no more authority than
//! they have. What `lps` does on a terminal, this does in a window.

use std::sync::{Arc, Weak};
use std::time::Duration;

use libauthd_client::admin::Admin;
use libauthd_client::ident::Ident;
use libgxwi::{App, Surface};

mod accounts;
mod claims;
mod directory;
mod groups;
mod keys;
mod manager;
mod policy;
mod words;

use manager::{Heard, Manager};

// What this program looks like, to whatever lists it. The icon itself is
// `gxwi-principals-manager.svg` at the repo root, installed as the base
// theme's.
libgxwi::icon!(b"dev.peios.gxwi-principals-manager");

/// How often the lists are read again. Nothing tells a client when a
/// principal changes, so the window looks.
const LOOK_AGAIN: Duration = Duration::from_secs(5);

/// Reads the lists, and the one picked, again every little while, for as
/// long as the window is there; the window is changed only if they differ.
fn look_again(window: Weak<Surface<Manager>>) {
    loop {
        std::thread::sleep(LOOK_AGAIN);
        let Some(shown) = window.upgrade() else { return };
        let (ident, admin, picked, user) = shown.look(|manager, _, _| {
            (manager.ident().clone(), manager.admin().clone(), manager.picked().map(str::to_string), manager.local_user())
        });
        drop(shown);
        let heard = Heard {
            directory: directory::read(&ident),
            details: picked.as_deref().map(|sid| directory::details(&ident, sid)),
            // Keys and how they sign in are lpsd's, asked of it only where
            // this person may administer it.
            credentials: user.map(|name| admin.keys(&name).map_err(|refusal| refusal.reason)),
            policy: libauthd_policy::Policy::read(),
            picked,
        };
        let Some(shown) = window.upgrade() else { return };
        // An update shows every page the window again, so only one that
        // changes something is made.
        if shown.look(|manager, _, _| manager.differs(&heard)) {
            shown.update(|manager, _| manager.heard(heard));
        }
    }
}

fn main() {
    if std::env::args().nth(1).is_some() {
        eprintln!("gxwi-principals-manager: usage: gxwi-principals-manager");
        std::process::exit(64);
    }
    let mut app = match App::connect() {
        Ok(app) => app,
        Err(e) => {
            eprintln!("gxwi-principals-manager: no desktop to open on: {e}");
            eprintln!("gxwi-principals-manager: on a terminal, lps does what this does");
            std::process::exit(1);
        }
    };
    app.stylesheet("/gxwi-principals-manager.css", include_str!("gxwi-principals-manager.css"));
    let window = app.live("Principals Manager", Manager::new(Ident::new(), Admin::new()));
    let aside = Arc::downgrade(&window);
    window.update(|manager, _| manager.window = aside.clone());
    std::thread::spawn(move || look_again(aside));
    if let Err(e) = app.run() {
        eprintln!("gxwi-principals-manager: {e}");
        std::process::exit(1);
    }
}
