//! What the protocols' values are, in words.

use libauthd::claim::{self, Claim, Values};
use libauthd::wire::{LogonType, LogonTypes};

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

/// A claim's type, in words.
pub fn claim_type(values: &Values) -> &'static str {
    match values {
        Values::Int64(_) => "Whole number",
        Values::Uint64(_) => "Whole number, not negative",
        Values::Boolean(_) => "Yes or no",
        Values::String(_) => "Text",
        Values::Sid(_) => "SID",
        Values::Octet(_) => "Bytes",
    }
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
}
