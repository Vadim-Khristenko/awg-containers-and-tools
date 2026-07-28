//! Fetching container logs, and the one boundary key material cannot cross.
//!
//! [`logs`] redacts before it returns. The raw text never leaves this function,
//! so no caller can leak what it was never given — which is the whole reason
//! the redaction lives here rather than at each print site. One boundary is
//! testable; five sprinkled `replace` calls are not.
//!
//! Two rules, applied in this order:
//!
//! 1. A value attached to a name in [`SECRET_NAMES`] is replaced, whatever it
//!    looks like — so a truncated or malformed key does not survive either.
//! 2. Any remaining token shaped like 32 bytes of key material is replaced,
//!    unless it is attached to a name in [`PUBLIC_NAMES`].
//!
//! The second rule is what makes this hold against log formats nobody has seen
//! yet: a bare key on a line of its own has no name to match, and is still
//! removed. The [`PUBLIC_NAMES`] exception exists because a peer's *public* key
//! has the same shape as a private one, and it is the only thing that
//! identifies a peer in the event log — redacting it would make the log
//! useless without making anything safer.

use super::host::{Host, safe_name};
use crate::{Error, Result};

/// What a redacted value is replaced with.
pub const REDACTED: &str = "[redacted]";

/// Field names whose value is key material. Compared with punctuation and case
/// removed, so `PrivateKey`, `private_key` and `PRIVATE-KEY` are one name.
const SECRET_NAMES: [&str; 9] = [
    "privatekey",
    "preshared",
    "presharedkey",
    "psk",
    "headerprotectionkey",
    "headercipherkey",
    "secretkey",
    "password",
    "passphrase",
];

/// Field names whose value is public by construction.
const PUBLIC_NAMES: [&str; 8] = [
    "publickey",
    "peer",
    "sha256",
    "image",
    "imageid",
    "containerid",
    "id",
    "label",
];

fn normalise_name(s: &str) -> String {
    s.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Does this token look like 32 bytes of key material?
///
/// Base64 of 32 bytes is 43 characters plus one `=`; hex is 64 characters. A
/// 64-character container id has the same shape as a hex key and is redacted if
/// it appears unlabelled — over-redaction is the safe direction, and `sha256:`
/// and `id=` are in [`PUBLIC_NAMES`] for the cases that matter.
pub fn looks_like_key_material(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() == 44
        && b[43] == b'='
        && b[..43]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'+' || *c == b'/')
    {
        return true;
    }
    b.len() == 64 && b.iter().all(u8::is_ascii_hexdigit)
}

/// Split off surrounding punctuation so `"<key>",` is still recognised as a key.
///
/// A token that is *entirely* punctuation — the `>>` the entrypoint prefixes its
/// log lines with — comes back with an empty core rather than an inverted range.
fn trim_wrapping(s: &str) -> (&str, &str, &str) {
    const WRAP: &[char] = &['"', '\'', '(', ')', '[', ']', '{', '}', ',', ';', '<', '>'];
    let after_lead = s.trim_start_matches(WRAP);
    let start = s.len() - after_lead.len();
    let core = after_lead.trim_end_matches(WRAP);
    (&s[..start], core, &s[start + core.len()..])
}

fn redact_value(value: &str) -> String {
    let (lead, core, trail) = trim_wrapping(value);
    if looks_like_key_material(core) {
        format!("{lead}{REDACTED}{trail}")
    } else {
        value.to_string()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pending {
    None,
    Secret,
    Public,
}

fn redact_line(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut pending = Pending::None;
    let mut rest = line;

    while !rest.is_empty() {
        let gap_len = rest.len() - rest.trim_start().len();
        out.push_str(&rest[..gap_len]);
        rest = &rest[gap_len..];
        if rest.is_empty() {
            break;
        }
        let word_len = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let word = &rest[..word_len];
        rest = &rest[word_len..];

        // A lone separator between `Name` and `value` keeps the pending state,
        // so `PrivateKey = <key>` is handled as one unit.
        if word == "=" || word == ":" {
            out.push_str(word);
            continue;
        }

        let (lead, core, trail) = trim_wrapping(word);

        // A name in SECRET_NAMES claims the next word, whatever it looks like.
        // This has to run before the `name=value` split below, because base64
        // ends in `=` and would otherwise be mistaken for a pair of its own.
        if pending == Pending::Secret && !core.is_empty() {
            out.push_str(lead);
            out.push_str(REDACTED);
            out.push_str(trail);
            pending = Pending::None;
            continue;
        }

        // A bare token of key shape, with nothing naming it — the case a
        // name-driven rule cannot see.
        if looks_like_key_material(core) {
            if pending == Pending::Public {
                out.push_str(word);
            } else {
                out.push_str(lead);
                out.push_str(REDACTED);
                out.push_str(trail);
            }
            pending = Pending::None;
            continue;
        }

        let sep = word
            .find('=')
            .into_iter()
            .chain(word.find(':'))
            .min()
            .filter(|i| *i > 0);
        if let Some(i) = sep {
            let (name, value) = (&word[..i], &word[i + 1..]);
            let n = normalise_name(name);
            out.push_str(name);
            out.push_str(&word[i..=i]);
            if SECRET_NAMES.contains(&n.as_str()) {
                out.push_str(REDACTED);
            } else if PUBLIC_NAMES.contains(&n.as_str()) {
                out.push_str(value);
            } else {
                out.push_str(&redact_value(value));
            }
            pending = Pending::None;
            continue;
        }

        let n = normalise_name(core);
        pending = if SECRET_NAMES.contains(&n.as_str()) {
            Pending::Secret
        } else if PUBLIC_NAMES.contains(&n.as_str()) {
            Pending::Public
        } else {
            Pending::None
        };
        out.push_str(word);
    }
    out
}

/// Remove key material from text. See the module note for the rules.
pub fn redact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (i, line) in text.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&redact_line(line));
    }
    out
}

pub fn logs_command(container: &str, lines: u32) -> Result<String> {
    Ok(format!(
        "docker logs --tail {lines} {} 2>&1",
        safe_name(container)?
    ))
}

/// Container logs, redacted before they are returned.
pub fn logs(host: &Host, container: &str, lines: u32) -> Result<String> {
    let (out, err, code) = host.run_docker(&logs_command(container, lines)?)?;
    if code != 0 && out.trim().is_empty() {
        return Err(Error::Ssh(format!(
            "`docker logs {container}` failed (exit {code}): {}",
            redact(err.trim())
        )));
    }
    Ok(redact(&format!("{out}{err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE_B64: &str = "yNMDBJ4Vd3nZuJ2FZ1ChNTvHNQg1KgLpOaOtQC8LSXY=";
    const PSK_B64: &str = "dGVzdHBza3Rlc3Rwc2t0ZXN0cHNrdGVzdHBza3Rlc3Q=";
    const KEY_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const PUBLIC_B64: &str = "7DHFY2VYRZ7Ag+K7C6X0i9FfHkw+q4H0dqIiRCyEXHM=";

    #[test]
    fn a_log_line_carrying_a_private_key_does_not_survive_redaction() {
        let line = format!(
            "2026-07-28T21:00:00Z iface=awg0 event=debug PrivateKey = {PRIVATE_B64} MTU = 1420"
        );
        let clean = redact(&line);
        assert!(!clean.contains(PRIVATE_B64), "the key survived: {clean}");
        assert!(clean.contains(REDACTED));
        // Everything that is not a secret is still readable.
        assert!(clean.contains("iface=awg0"));
        assert!(clean.contains("2026-07-28T21:00:00Z"));
        assert!(clean.contains("MTU = 1420"));
    }

    #[test]
    fn every_shape_a_key_reaches_a_log_in_is_removed() {
        for case in [
            format!("PresharedKey = {PSK_B64}"),
            format!("preshared_key={KEY_HEX}"),
            format!("HeaderProtectionKey = {PSK_B64}"),
            format!("header_protection_key={KEY_HEX}"),
            format!("PRIVATE-KEY: {PSK_B64}"),
            format!("private_key={KEY_HEX}"),
            // Unlabelled, which is the case a name-based rule would miss.
            PSK_B64.to_string(),
            format!("  {KEY_HEX}  "),
            format!("set=1\nprivate_key={KEY_HEX}\nlisten_port=51820"),
            format!("wrote key \"{PSK_B64}\" to disk"),
            format!("[{KEY_HEX}]"),
        ] {
            let clean = redact(&case);
            assert!(!clean.contains(PSK_B64), "base64 key survived in: {clean}");
            assert!(!clean.contains(KEY_HEX), "hex key survived in: {clean}");
        }
    }

    #[test]
    fn a_malformed_secret_is_removed_even_though_it_is_not_key_shaped() {
        // Rule 1 exists for this: a truncated key is still a key.
        let clean = redact("PrivateKey = yNMDBJ4Vd3nZ");
        assert!(!clean.contains("yNMDBJ4Vd3nZ"), "{clean}");
    }

    #[test]
    fn a_peers_public_key_is_left_alone_because_it_names_the_peer() {
        let line = format!(
            "2026-07-28T21:00:00Z iface=awg0 event=peer-add peer={PUBLIC_B64} label=laptop address=10.8.1.5/32"
        );
        let clean = redact(&line);
        assert!(clean.contains(PUBLIC_B64), "the event log became useless");
        assert!(clean.contains("label=laptop"));
        assert!(clean.contains("address=10.8.1.5/32"));

        // The same key spelled as a `.conf` field.
        assert!(redact(&format!("PublicKey = {PUBLIC_B64}")).contains(PUBLIC_B64));
        assert!(redact(&format!("public_key={PUBLIC_B64}")).contains(PUBLIC_B64));
    }

    #[test]
    fn ordinary_log_lines_come_back_unchanged() {
        for line in [
            ">> awg0 is up",
            ">> configuration accepted by amneziawg-go (31 UAPI lines, errno=0)",
            "2026-07-28T21:00:00Z iface=awg0 event=iface-up addr=10.8.1.1/24 mtu=1420 port=51820 nat=1",
            "!! RTNETLINK answers: Operation not permitted",
            "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        ] {
            assert_eq!(redact(line), line, "a plain line was altered");
        }
    }

    #[test]
    fn redaction_preserves_the_shape_of_the_text() {
        let text = "line one\nline two\n";
        assert_eq!(redact(text), text);
        assert_eq!(redact(""), "");
        assert_eq!(redact("\n\n"), "\n\n");
        assert_eq!(redact("  indented  "), "  indented  ");
    }

    #[test]
    fn the_key_shape_test_is_neither_too_wide_nor_too_narrow() {
        assert!(looks_like_key_material(PSK_B64));
        assert!(looks_like_key_material(KEY_HEX));
        assert!(!looks_like_key_material("10.8.1.1/24"));
        assert!(!looks_like_key_material("1420"));
        assert!(!looks_like_key_material(""));
        // 43 characters is not 32 bytes.
        assert!(!looks_like_key_material(&PSK_B64[..43]));
    }

    #[test]
    fn a_token_that_is_nothing_but_punctuation_does_not_derail_the_scanner() {
        // The entrypoint prefixes every line with `>>` or `!!`.
        assert_eq!(redact(">> awg0 is up"), ">> awg0 is up");
        assert_eq!(redact("<<>>"), "<<>>");
        assert_eq!(redact("[] {} ,,"), "[] {} ,,");
    }

    #[test]
    fn shell_metacharacters_never_reach_a_command() {
        assert!(logs_command("$(whoami)", 10).is_err());
        assert_eq!(
            logs_command("awg-server", 50).unwrap(),
            "docker logs --tail 50 awg-server 2>&1"
        );
    }
}
