//! What the protocols' values are, in words.

use jiff::Timestamp;
use jiff::tz::TimeZone;
use libauthd::claim::{self, Claim, Values};
use libauthd::credential::Policy;
use libauthd::wire::{LogonType, LogonTypes};
use libauthd_policy::tier_name;
use peios::security::IntegrityLevel;

use crate::directory;

/// Every kind of sign-in, as a person would say it, in the order shown.
pub const LOGON_TYPES: &[(LogonType, &str)] = &[
    (LogonType::Interactive, "At the machine"),
    (LogonType::RemoteInteractive, "On a remote desktop"),
    (LogonType::Network, "Over the network"),
    (LogonType::NetworkCleartext, "Over the network, with a password sent in the clear"),
    (LogonType::Batch, "To run scheduled jobs"),
    (LogonType::NewCredentials, "As other credentials, for a program"),
    (LogonType::Service, "To run a service"),
];

/// The kinds of sign-in a set permits, in words. Nothing stated means the
/// authority's default, which is said as such.
pub fn logon_types(types: LogonTypes) -> Vec<&'static str> {
    LOGON_TYPES.iter().filter(|(logon_type, _)| types.permits(*logon_type)).map(|(_, said)| *said).collect()
}

/// What a user may sign in with: each credential policy, the value a form
/// sends for it, and in words.
pub const POLICIES: &[(Policy, &str, &str)] = &[
    (Policy::Password, "password", "A password"),
    (Policy::SshPublicKey, "key", "An SSH key"),
    (Policy::PasswordOrKey, "either", "A password or an SSH key"),
    (Policy::NoCredential, "none", "Nothing: no password is asked for"),
    (Policy::Denied, "denied", "Nothing is accepted: every sign-in is refused"),
];

/// A credential policy, in words.
pub fn policy(policy: Policy) -> &'static str {
    POLICIES.iter().find(|(known, _, _)| *known == policy).map_or("", |(_, _, said)| *said)
}

/// The credential policy a form's value names.
pub fn policy_of(value: &str) -> Option<Policy> {
    POLICIES.iter().find(|(_, sent, _)| *sent == value).map(|(policy, _, _)| *policy)
}

/// The value a form sends for a credential policy.
pub fn policy_value(policy: Policy) -> &'static str {
    POLICIES.iter().find(|(known, _, _)| *known == policy).map_or("", |(_, sent, _)| *sent)
}

/// What each privilege lets its holder do, in a person's words, by its name.
pub const PRIVILEGES: &[(&str, &str)] = &[
    ("SeCreateTokenPrivilege", "Make a token for anyone, without signing in. authd's alone."),
    ("SeAssignPrimaryTokenPrivilege", "Start a process as someone else. peinit's, to start services."),
    ("SeLockMemoryPrivilege", "Keep memory from being swapped out."),
    ("SeIncreaseQuotaPrivilege", "Lift a process's resource limits."),
    ("SeTcbPrivilege", "Act as part of the trusted core of the system."),
    ("SeSecurityPrivilege", "Read and change what any object audits."),
    ("SeLoadDriverPrivilege", "Load and unload kernel modules."),
    ("SeSystemtimePrivilege", "Set the system clock."),
    ("SeProfileSingleProcessPrivilege", "Profile another process."),
    ("SeIncreaseBasePriorityPrivilege", "Raise another process's priority, or pin it to processors."),
    ("SeBackupPrivilege", "Read anything, whatever its permissions, when backing it up."),
    ("SeRestorePrivilege", "Write anything, and give it any owner, when restoring it."),
    ("SeShutdownPrivilege", "Shut down and restart this machine."),
    ("SeDebugPrivilege", "Look into and change other processes, whatever their permissions."),
    ("SeAuditPrivilege", "Write to the audit log."),
    ("SeChangeNotifyPrivilege", "Pass through folders on the way to a file. No shell starts without it."),
    ("SeRemoteShutdownPrivilege", "Shut down this machine from another."),
    ("SeManageVolumePrivilege", "Mount, unmount and reshape filesystems. Near the trusted core in what it allows."),
    ("SeImpersonatePrivilege", "Act as a client who connects to it."),
    ("SeCreateSymbolicLinkPrivilege", "Make symbolic links."),
];

/// What a privilege lets its holder do, or nothing for one without words.
pub fn privilege(name: &str) -> &'static str {
    PRIVILEGES.iter().find(|(known, _)| *known == name).map_or("", |(_, said)| *said)
}

/// An integrity level in words: its tier's name, or its number between them.
pub fn integrity(level: IntegrityLevel) -> String {
    tier_name(level).map_or_else(|| format!("Level {}", level.0), str::to_string)
}

/// The kinds of sign-in what someone gets may be worked out for: a form's
/// value for each, and in words.
pub const SIGN_INS: &[(&str, LogonType, &str)] = &[
    ("interactive", LogonType::Interactive, "At the machine"),
    ("remote", LogonType::RemoteInteractive, "On a remote desktop"),
    ("network", LogonType::Network, "Over the network"),
    ("batch", LogonType::Batch, "To run scheduled jobs"),
    ("service", LogonType::Service, "To run a service"),
];

/// The claim types, by the names libauthd gives them, in words, and how to
/// type a value of each, in the order the claim form offers them.
pub const CLAIM_TYPES: &[(&str, &str, &str)] = &[
    ("string", "Text", "Text, one value to a line."),
    ("int64", "Whole number", "Whole numbers, such as 42 or -7, one to a line."),
    ("uint64", "Whole number, not negative", "Whole numbers of 0 or more, one to a line."),
    ("boolean", "Yes or no", "Yes or No, one to a line."),
    ("sid", "SID", "SIDs, such as S-1-5-32-544, or the names of users and groups here, one to a line."),
    ("octet", "Bytes", "Bytes in hexadecimal, such as 0a1b2c, one value to a line."),
];

/// A claim's type, in words.
pub fn claim_type(values: &Values) -> &'static str {
    CLAIM_TYPES.iter().find(|(name, _, _)| *name == values.type_name()).map_or("", |(_, said, _)| *said)
}

/// The day something happened, on `zone`'s clock, from seconds since 1970.
pub fn day(seconds: u64, zone: &TimeZone) -> String {
    match i64::try_from(seconds).ok().and_then(|seconds| Timestamp::from_second(seconds).ok()) {
        Some(at) => at.to_zoned(zone.clone()).strftime("%-d %B %Y").to_string(),
        None => seconds.to_string(),
    }
}

/// A refusal's words as a sentence: begun with a capital, ended with a stop.
pub fn sentence(text: &str) -> String {
    let mut chars = text.chars();
    let mut said: String = chars.next().map(|first| first.to_uppercase().chain(chars).collect()).unwrap_or_default();
    if !said.ends_with('.') {
        said.push('.');
    }
    said
}

/// A claim's values, in words, one each.
pub fn claim_values(values: &Values) -> Vec<String> {
    match values {
        Values::Int64(values) => values.iter().map(i64::to_string).collect(),
        Values::Uint64(values) => values.iter().map(u64::to_string).collect(),
        Values::Boolean(values) => values.iter().map(|value| if *value { "Yes" } else { "No" }.to_string()).collect(),
        Values::String(values) => values.clone(),
        Values::Sid(values) => values.iter().map(|sid| directory::sid_text(sid)).collect(),
        Values::Octet(values) => values.iter().map(|bytes| bytes.iter().map(|byte| format!("{byte:02x}")).collect()).collect(),
    }
}

/// What a claim's flags say, in words.
pub fn claim_flags(claim: &Claim) -> Vec<&'static str> {
    [
        (claim::FLAG_DISABLED, "Off"),
        (claim::FLAG_MANDATORY, "Mandatory"),
        (claim::FLAG_USE_FOR_DENY_ONLY, "Only to deny"),
        (claim::FLAG_CASE_SENSITIVE, "Case matters"),
        (claim::FLAG_NON_INHERITABLE, "Not inherited"),
    ]
    .into_iter()
    .filter(|(flag, _)| claim.flags & flag != 0)
    .map(|(_, said)| said)
    .collect()
}

/// `n` of something, said properly.
pub fn count(n: usize, one: &str) -> String {
    match n {
        1 => format!("1 {one}"),
        n => format!("{n} {one}s"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_in_types_are_said_and_nothing_stated_is_the_default() {
        assert_eq!(logon_types(LogonTypes::SERVICE_ONLY), ["To run a service"]);
        let default = logon_types(LogonTypes::UNSTATED);
        assert!(default.contains(&"At the machine") && !default.contains(&"To run a service"));
    }

    #[test]
    fn a_claim_is_said_with_its_type_values_and_flags() {
        let claim = Claim { name: "clearance".into(), flags: claim::FLAG_MANDATORY, values: Values::Boolean(vec![true, false]) };
        assert_eq!(claim_type(&claim.values), "Yes or no");
        assert_eq!(claim_values(&claim.values), ["Yes", "No"]);
        assert_eq!(claim_flags(&claim), ["Mandatory"]);
    }

    #[test]
    fn every_policy_and_claim_type_has_words() {
        for (policy, sent, _) in POLICIES {
            assert_eq!(policy_of(sent), Some(*policy));
            assert_eq!(policy_value(*policy), *sent);
        }
        for code in [claim::TYPE_INT64, claim::TYPE_UINT64, claim::TYPE_BOOLEAN, claim::TYPE_STRING, claim::TYPE_SID, claim::TYPE_OCTET] {
            assert!(!claim_type(&Values::empty_of(code).unwrap()).is_empty());
        }
    }

    /// Every privilege a record may grant has words, and no words name one
    /// that isn't.
    #[test]
    fn every_privilege_is_said_in_words() {
        use peios::security::Privileges;
        for (name, _) in Privileges::all_named() {
            assert!(!privilege(name).is_empty(), "{name} has no words");
        }
        for (name, _) in PRIVILEGES {
            assert!(Privileges::parse_name(name).is_some(), "{name} is not a privilege");
        }
        assert_eq!(integrity(IntegrityLevel::HIGH), "High");
        assert_eq!(integrity(IntegrityLevel(8193)), "Level 8193");
    }

    #[test]
    fn a_day_is_said_on_the_clock_given() {
        assert_eq!(day(1_791_072_000, &TimeZone::UTC), "4 October 2026");
        assert_eq!(day(1_791_072_000, &TimeZone::fixed(jiff::tz::offset(-1))), "3 October 2026");
        assert_eq!(sentence("a claim may carry at most 64 values"), "A claim may carry at most 64 values.");
    }
}
