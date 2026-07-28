//! Rendering a parameter set into the three shapes that matter.
//!
//! * `.conf`  — what humans and clients read. Keys are base64.
//! * UAPI     — what `amneziawg-go` accepts on its socket. Keys are hex.
//!
//! The UAPI path exists because `amneziawg-tools` — on tags *and* on master —
//! parses only the 2.0 keys, so `awg-quick` physically cannot bring up a 3.0
//! interface. Talking to the daemon directly sidesteps the tooling lag and
//! keeps one code path for every protocol version.

use crate::awg3::Awg3Params;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The 3.0 lines of an `[Interface]` block.
pub fn awg3_conf_lines(p: &Awg3Params) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(k) = &p.header_protection_key {
        out.push("# AWG 3.0 — shared header-protection key (identical on both sides)".into());
        out.push(format!("HeaderProtectionKey = {}", B64.encode(k)));
    }
    if let Some(r) = p.content_padding_addition {
        out.push("# AWG 3.0 — random transport-packet padding".into());
        out.push(format!("ContentPaddingAddition = {r}"));
    }
    if p.rekey_after_time.is_some() {
        out.push("# AWG 3.0 — randomised protocol timings".into());
    }
    for (name, val) in [
        ("RekeyAfterTime", p.rekey_after_time),
        ("RekeyTimeout", p.rekey_timeout),
        ("RejectAfterTime", p.reject_after_time),
        ("KeepaliveTimeout", p.keepalive_timeout),
        ("MaxHandshakeAttempts", p.max_handshake_attempts),
    ] {
        if let Some(r) = val {
            out.push(format!("{name} = {r}"));
        }
    }
    out
}

/// The 3.0 lines of a UAPI `set=1` request.
///
/// Key names come from `amneziawg-go v3.0.1` `device/uapi.go`.
pub fn awg3_uapi_lines(p: &Awg3Params) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(k) = &p.header_protection_key {
        out.push(format!("header_protection_key={}", hex(k)));
    }
    if let Some(r) = p.content_padding_addition {
        out.push(format!("content_padding_addition={r}"));
    }
    for (name, val) in [
        ("rekey_after_time", p.rekey_after_time),
        ("rekey_timeout", p.rekey_timeout),
        ("reject_after_time", p.reject_after_time),
        ("keepalive_timeout", p.keepalive_timeout),
        ("max_handshake_attempts", p.max_handshake_attempts),
    ] {
        if let Some(r) = val {
            out.push(format!("{name}={r}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::awg3::{Awg3Options, generate};
    use crate::rng::SeededRng;

    #[test]
    fn conf_uses_base64_and_uapi_uses_hex_for_the_same_key() {
        let mut rng = SeededRng::new(7);
        let p = generate(&mut rng, Awg3Options::default()).unwrap();

        let conf = awg3_conf_lines(&p).join("\n");
        let uapi = awg3_uapi_lines(&p).join("\n");
        let key = p.header_protection_key.unwrap();

        assert!(conf.contains(&B64.encode(key)));
        assert!(uapi.contains(&hex(&key)));
        // 32 bytes -> 64 hex chars; a truncated key would still "work" and
        // silently weaken the cipher, so pin the length.
        assert_eq!(hex(&key).len(), 64);
    }

    #[test]
    fn every_generated_parameter_reaches_both_renderers() {
        let mut rng = SeededRng::new(11);
        let p = generate(&mut rng, Awg3Options::default()).unwrap();
        for name in [
            "RekeyAfterTime",
            "RekeyTimeout",
            "RejectAfterTime",
            "KeepaliveTimeout",
            "MaxHandshakeAttempts",
            "ContentPaddingAddition",
            "HeaderProtectionKey",
        ] {
            assert!(
                awg3_conf_lines(&p).iter().any(|l| l.starts_with(name)),
                "{name} missing from .conf output"
            );
        }
        assert_eq!(awg3_uapi_lines(&p).len(), 7);
    }
}
