//! Checking a `.conf` (or a `vpn://` link) someone else wrote.
//!
//! The generator's output is checked by [`crate::versions::validate_for`]; a
//! pasted config goes through the same rules, so a finding reads the same
//! whichever door the config came in through. What is added here is what only
//! a foreign file can get wrong: its structure (ported from Architect's
//! `audit.ts`), keys amneziawg-tools does not know, values that are not numbers,
//! and which protocol generation it is for, read off the fields it carries.

use std::collections::BTreeSet;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

use crate::awg3::{Awg3Params, HEADER_PROTECTION_KEY_BYTES, UintRange};
use crate::deploy::config::{BaseObfuscation, SERVER_KEY_PLACEHOLDER};
use crate::engines::Engine;
use crate::mimic::MimicProfile;
use crate::versions::{
    self, AwgVersion, ClientCapability, Level, VersionedParams, Violation, default_client,
};

// ------------------------------------------------------------------ parsing

/// One `[Section]` of a `.conf`, entries in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub entries: Vec<(String, String)>,
}

/// A `.conf` as wg-quick reads it: sections of `Key = Value`, `#` and `;`
/// comments skipped. Keys before any header land in an implicit `Interface`,
/// which is how a pasted parameter block reads.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConfFile {
    pub sections: Vec<Section>,
}

impl ConfFile {
    pub fn parse(text: &str) -> Self {
        let mut sections: Vec<Section> = Vec::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                sections.push(Section {
                    name: name.trim().to_string(),
                    entries: Vec::new(),
                });
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            if sections.is_empty() {
                sections.push(Section {
                    name: "Interface".into(),
                    entries: Vec::new(),
                });
            }
            let last = sections.last_mut().expect("pushed above");
            last.entries
                .push((k.trim().to_string(), v.trim().to_string()));
        }
        Self { sections }
    }

    pub fn interface(&self) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == "Interface")
    }

    pub fn peers(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter().filter(|s| s.name == "Peer")
    }

    /// The first value of `key` in `[Interface]`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.interface()?
            .entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

impl Section {
    fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

// ------------------------------------------------------------------ options

#[derive(Debug, Clone, Copy)]
pub struct CheckOptions {
    pub client: &'static ClientCapability,
    pub server_engine: Engine,
    /// Read the file as this generation instead of inferring it.
    pub version: Option<AwgVersion>,
}

impl Default for CheckOptions {
    fn default() -> Self {
        Self {
            client: default_client(),
            server_engine: Engine::Go,
            version: None,
        }
    }
}

/// What a check found.
#[derive(Debug, Clone)]
pub struct CheckReport {
    /// The generation the file was read as; `None` when it carries no
    /// obfuscation at all.
    pub version: Option<AwgVersion>,
    /// True when the version came from the fields rather than the caller.
    pub version_inferred: bool,
    pub params: Option<VersionedParams>,
    pub findings: Vec<Violation>,
}

impl CheckReport {
    /// The most serious finding, for an exit code.
    pub fn worst(&self) -> Option<Level> {
        let rank = |l: Level| match l {
            Level::Error => 2,
            Level::Warn => 1,
            Level::Info => 0,
        };
        self.findings
            .iter()
            .map(|f| f.level)
            .max_by_key(|l| rank(*l))
    }
}

// --------------------------------------------------------------- the check

/// Fields that make a config an AmneziaWG config rather than a WireGuard one.
const AWG_FIELDS: &[&str] = &[
    "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4",
    "I5",
];

/// `[Interface]` keys amneziawg-tools reads. Anything else is `Line
/// unrecognized`, and the whole config is refused.
const INTERFACE_KEYS: &[&str] = &[
    "PrivateKey",
    "Address",
    "ListenPort",
    "DNS",
    "MTU",
    "Table",
    "FwMark",
    "PreUp",
    "PostUp",
    "PreDown",
    "PostDown",
    "SaveConfig",
    "Jc",
    "Jmin",
    "Jmax",
    "S1",
    "S2",
    "S3",
    "S4",
    "H1",
    "H2",
    "H3",
    "H4",
    "I1",
    "I2",
    "I3",
    "I4",
    "I5",
    "Itime",
    "J1",
    "J2",
    "J3",
    "HeaderProtectionKey",
    "ContentPaddingAddition",
    "RekeyAfterTime",
    "RekeyTimeout",
    "RejectAfterTime",
    "KeepaliveTimeout",
    "MaxHandshakeAttempts",
    "RandomTrailers",
    "DisableCookies",
];

const PEER_KEYS: &[&str] = &[
    "PublicKey",
    "PresharedKey",
    "AllowedIPs",
    "Endpoint",
    "PersistentKeepalive",
];

/// Check a `.conf`, or a `vpn://` link holding one.
pub fn check(input: &str, opts: &CheckOptions) -> CheckReport {
    let text = if input.trim_start().starts_with("vpn://") {
        match crate::vpn::conf_from_link(input) {
            Ok(conf) => conf,
            Err(e) => {
                return CheckReport {
                    version: None,
                    version_inferred: false,
                    params: None,
                    findings: vec![Violation::err(
                        "vpn://",
                        "conf.bad_link",
                        format!("the link does not hold a config: {e}"),
                    )],
                };
            }
        }
    } else {
        input.to_string()
    };
    check_conf(&text, opts)
}

/// Check the text of a `.conf`.
pub fn check_conf(text: &str, opts: &CheckOptions) -> CheckReport {
    let conf = ConfFile::parse(text);
    let mut findings = audit(text, &conf);

    let present: BTreeSet<&str> = conf
        .interface()
        .map(|s| s.entries.iter().map(|(k, _)| k.as_str()).collect())
        .unwrap_or_default();
    if !AWG_FIELDS.iter().any(|k| present.contains(k)) {
        // A plain WireGuard config is not broken; it is just not the thing
        // this check is for.
        findings.push(Violation::warn(
            "AWG",
            "conf.not_obfuscated",
            "no AmneziaWG parameters: this is a plain WireGuard config",
        ));
        return CheckReport {
            version: None,
            version_inferred: false,
            params: None,
            findings,
        };
    }

    let (version, inferred) = match opts.version {
        Some(v) => (v, false),
        None => (infer_version(&conf), true),
    };
    let (params, mut parse_findings) = params_from_conf(&conf, version);
    findings.append(&mut parse_findings);

    // The generator's rules, minus what only makes sense of a generated set
    // and what names a field the file never wrote.
    const GENERATION_ONLY: [&str; 2] = ["version.cps_missing", "version.awg3_missing"];
    // "H1/H2" names two fields that must both be written; "I1-I5" names a
    // group, absent only when none of it was written.
    let absent = |f: &str| is_param(f) && !present.contains(f);
    let mentions_absent = |field: &str| {
        field.split('/').any(|part| {
            let ends: Vec<&str> = part.split('-').filter(|f| !f.is_empty()).collect();
            !ends.is_empty() && ends.iter().all(|f| absent(f))
        })
    };
    for v in versions::validate_for(&params, opts.client, opts.server_engine) {
        if GENERATION_ONLY.contains(&v.code) || mentions_absent(&v.field) {
            continue;
        }
        findings.push(v);
    }

    // Jmax against the interface MTU: a junk packet bigger than the path
    // fragments, and a fragmented burst before every handshake stands out.
    let mtu = conf
        .get("MTU")
        .and_then(|m| m.parse::<u32>().ok())
        .unwrap_or(1280);
    if present.contains("Jmax") && params.base.jmax >= mtu {
        findings.push(Violation::warn(
            "Jmax",
            "j.over_mtu",
            format!(
                "Jmax = {} is not below the MTU ({mtu}): the largest junk packets fragment",
                params.base.jmax
            ),
        ));
    }

    CheckReport {
        version: Some(version),
        version_inferred: inferred,
        params: Some(params),
        findings,
    }
}

/// A field name the obfuscation rules talk about.
fn is_param(f: &str) -> bool {
    AWG_FIELDS.contains(&f) || INTERFACE_KEYS.contains(&f)
}

/// Which generation a file is for, from the newest fields it carries.
///
/// Every generation's keys are a superset of the one before, so the newest
/// key present names the oldest generation that can read the file. A file
/// that could be several is read as the oldest of them, since that is the
/// strictest reading of the rules that differ.
pub fn infer_version(conf: &ConfFile) -> AwgVersion {
    let has = |k: &str| conf.get(k).is_some();
    let ranged = ["H1", "H2", "H3", "H4"]
        .iter()
        .any(|k| conf.get(k).is_some_and(|v| v.contains('-')));
    if has("RandomTrailers") || has("DisableCookies") {
        AwgVersion::V3_1
    } else if [
        "HeaderProtectionKey",
        "ContentPaddingAddition",
        "RekeyAfterTime",
        "RekeyTimeout",
        "RejectAfterTime",
        "KeepaliveTimeout",
        "MaxHandshakeAttempts",
    ]
    .iter()
    .any(|k| has(k))
    {
        AwgVersion::V3_0
    } else if has("S3") || has("S4") || ranged {
        AwgVersion::V2_0
    } else if ["I1", "I2", "I3", "I4", "I5"].iter().any(|k| has(k)) {
        AwgVersion::V1_5
    } else {
        AwgVersion::V1_0
    }
}

/// `"lo-hi"` or a single value, as the daemon parses a range.
fn parse_range(v: &str) -> Option<UintRange> {
    match v.split_once('-') {
        Some((lo, hi)) => Some(UintRange::new(
            lo.trim().parse().ok()?,
            hi.trim().parse().ok()?,
        )),
        None => {
            let n = v.trim().parse().ok()?;
            Some(UintRange::new(n, n))
        }
    }
}

/// amneziawg-tools `parse_bool`.
fn parse_switch(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// The file's numbers as a [`VersionedParams`], with a finding for every value
/// that is not one. A missing field reads as zero; the caller drops findings
/// that name it.
fn params_from_conf(conf: &ConfFile, version: AwgVersion) -> (VersionedParams, Vec<Violation>) {
    let mut found = Vec::new();
    let mut num = |key: &str| -> u32 {
        match conf.get(key) {
            None => 0,
            Some(v) => v.trim().parse().unwrap_or_else(|_| {
                found.push(Violation::err(
                    key,
                    "conf.not_a_number",
                    format!("{key} = {v} is not a number the daemon can read"),
                ));
                0
            }),
        }
    };
    let jc = num("Jc");
    let jmin = num("Jmin");
    let jmax = num("Jmax");
    let s = [num("S1"), num("S2"), num("S3"), num("S4")];

    let mut h = [0u32; 4];
    let mut hi = [0u32; 4];
    for i in 0..4 {
        let key = format!("H{}", i + 1);
        if let Some(v) = conf.get(&key) {
            match parse_range(v) {
                Some(r) => {
                    h[i] = r.lo;
                    hi[i] = r.hi;
                }
                None => found.push(Violation::err(
                    key.clone(),
                    "conf.not_a_number",
                    format!("{key} = {v} is neither a number nor a lo-hi range"),
                )),
            }
        }
    }

    let chains = (version.supports_cps()
        && ["I1", "I2", "I3", "I4", "I5"]
            .iter()
            .any(|k| conf.get(k).is_some()))
    .then(|| ["I1", "I2", "I3", "I4", "I5"].map(|k| conf.get(k).unwrap_or("").trim().to_string()));

    let awg3 = version.supports_awg3().then(|| {
        let mut p = Awg3Params::default();
        if let Some(v) = conf.get("HeaderProtectionKey") {
            match B64.decode(v.trim()) {
                Ok(raw) if raw.len() == HEADER_PROTECTION_KEY_BYTES => {
                    let mut key = [0u8; HEADER_PROTECTION_KEY_BYTES];
                    key.copy_from_slice(&raw);
                    p.header_protection_key = Some(key);
                }
                _ => found.push(Violation::err(
                    "HeaderProtectionKey",
                    "conf.bad_hpk",
                    "HeaderProtectionKey is not 32 bytes of base64",
                )),
            }
        }
        let mut range = |key: &str| {
            let v = conf.get(key)?;
            let r = parse_range(v);
            if r.is_none() {
                found.push(Violation::err(
                    key,
                    "conf.not_a_number",
                    format!("{key} = {v} is neither a number nor a lo-hi range"),
                ));
            }
            r
        };
        p.content_padding_addition = range("ContentPaddingAddition");
        p.rekey_after_time = range("RekeyAfterTime");
        p.rekey_timeout = range("RekeyTimeout");
        p.reject_after_time = range("RejectAfterTime");
        p.keepalive_timeout = range("KeepaliveTimeout");
        p.max_handshake_attempts = range("MaxHandshakeAttempts");
        p.random_trailers = conf.get("RandomTrailers").is_some_and(parse_switch);
        p.disable_cookies = conf.get("DisableCookies").is_some_and(parse_switch);
        p
    });

    let params = VersionedParams {
        version,
        // A pasted file names no profile; the field only labels output.
        profile: MimicProfile::Random,
        base: BaseObfuscation {
            jc,
            jmin,
            jmax,
            s,
            h,
        },
        h_hi: version.h_is_range().then_some(hi),
        chains,
        awg3,
    };
    (params, found)
}

// --------------------------------------------------------------- structure

/// A WireGuard key: 32 bytes of standard base64, 44 characters with one `=`.
fn is_wireguard_key(v: &str) -> bool {
    let v = v.trim();
    v.len() == 44
        && v.ends_with('=')
        && v[..43]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// `host:port`, `[v6]:port` or `ip:port`.
fn is_endpoint(v: &str) -> bool {
    let v = v.trim();
    let Some((host, port)) = v.rsplit_once(':') else {
        return false;
    };
    let port_ok = !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit());
    let host_ok = if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        !inner.is_empty() && inner.bytes().all(|b| b.is_ascii_hexdigit() || b == b':')
    } else {
        !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
    };
    port_ok && host_ok
}

fn has_section(text: &str, name: &str) -> bool {
    text.lines()
        .any(|l| l.trim().eq_ignore_ascii_case(&format!("[{name}]")))
}

/// Written but commented out: a placeholder to fill in.
fn has_commented_field(text: &str, key: &str) -> bool {
    text.lines().any(|l| {
        let l = l.trim_start();
        (l.starts_with('#') || l.starts_with(';'))
            && l[1..].trim_start().split('=').next().map(str::trim) == Some(key)
    })
}

/// The shape of the file, ported from Architect's `audit.ts`.
///
/// A bare block of obfuscation parameters (what `gen` prints, what people
/// paste out of a support thread) is left alone: demanding a PrivateKey of it
/// would report a tunnel as broken when nobody claimed to have pasted one.
pub fn audit(text: &str, conf: &ConfFile) -> Vec<Violation> {
    let mut found = Vec::new();
    let peers: Vec<&Section> = conf.peers().collect();
    let looks_like_tunnel = !peers.is_empty()
        || has_section(text, "Interface")
        || has_section(text, "Peer")
        || conf
            .sections
            .iter()
            .flat_map(|s| s.entries.iter())
            .any(|(k, _)| {
                matches!(
                    k.as_str(),
                    "PrivateKey" | "PublicKey" | "Address" | "Endpoint"
                )
            });

    // Unknown keys are refused by amneziawg-tools whatever the shape.
    for section in &conf.sections {
        let known: &[&str] = match section.name.as_str() {
            "Interface" => INTERFACE_KEYS,
            "Peer" => PEER_KEYS,
            other => {
                found.push(Violation::err(
                    format!("[{other}]"),
                    "conf.unknown_section",
                    format!("[{other}] is not a section wg-quick knows"),
                ));
                continue;
            }
        };
        let mut seen = BTreeSet::new();
        for (k, _) in &section.entries {
            if !known.contains(&k.as_str()) {
                found.push(Violation::err(
                    k.clone(),
                    "conf.unknown_key",
                    format!(
                        "{k} is not a key amneziawg-tools reads in [{}]: it answers `Line \
                         unrecognized` and refuses the whole config",
                        section.name
                    ),
                ));
            }
            if !seen.insert(k.as_str())
                && section.name == "Interface"
                && k != "Address"
                && k != "DNS"
            {
                found.push(Violation::warn(
                    k.clone(),
                    "conf.duplicate_key",
                    format!("{k} is set twice; only one of the values will be used"),
                ));
            }
        }
    }

    if !looks_like_tunnel {
        return found;
    }
    if !has_section(text, "Interface") {
        found.push(Violation::err(
            "[Interface]",
            "conf.no_interface",
            "there is no [Interface] section",
        ));
        return found;
    }

    let missing: Vec<&str> = ["PrivateKey", "Address"]
        .into_iter()
        .filter(|k| conf.get(k).is_none())
        .collect();
    if !missing.is_empty() && missing.iter().all(|k| has_commented_field(text, k)) {
        found.push(Violation::info(
            "[Interface]",
            "conf.template",
            format!(
                "a template: {} left commented out to fill in",
                missing.join(" and ")
            ),
        ));
        return found;
    }

    let server = conf.get("ListenPort").is_some();
    if peers.is_empty() {
        found.push(Violation::warn(
            "[Peer]",
            "conf.no_peer",
            "there is no [Peer] section",
        ));
    }
    for k in missing {
        found.push(Violation::err(
            k,
            "conf.missing_field",
            format!("{k} is required and missing"),
        ));
    }
    match conf.get("PrivateKey") {
        Some(SERVER_KEY_PLACEHOLDER) => found.push(Violation::info(
            "PrivateKey",
            "conf.key_placeholder",
            "the private key is the placeholder install fills in on the server",
        )),
        Some(k) if !is_wireguard_key(k) => found.push(Violation::err(
            "PrivateKey",
            "conf.bad_key",
            "PrivateKey is not a WireGuard key: 32 bytes of base64, 44 characters",
        )),
        _ => {}
    }

    for (i, peer) in peers.iter().enumerate() {
        let n = i + 1;
        match peer.get("PublicKey") {
            None => found.push(Violation::err(
                format!("PublicKey#{n}"),
                "conf.peer_missing_field",
                format!("peer #{n} has no PublicKey"),
            )),
            Some(k) if !is_wireguard_key(k) => found.push(Violation::err(
                format!("PublicKey#{n}"),
                "conf.peer_bad_key",
                format!("peer #{n}: PublicKey is not a WireGuard key"),
            )),
            _ => {}
        }
        // A server's peers are the clients, and it does not dial them.
        match peer.get("Endpoint") {
            None if !server => found.push(Violation::err(
                format!("Endpoint#{n}"),
                "conf.peer_missing_field",
                format!(
                    "peer #{n} has no Endpoint, and this side has no ListenPort to be dialled on"
                ),
            )),
            Some(e) if !is_endpoint(e) => found.push(Violation::warn(
                format!("Endpoint#{n}"),
                "conf.peer_bad_endpoint",
                format!("peer #{n}: Endpoint {e} is not host:port"),
            )),
            _ => {}
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::config::{Keys, NetworkSpec, Tunnel, client_conf, server_conf};
    use crate::rng::SeededRng;
    use crate::versions::GenOptions;

    fn codes(r: &CheckReport) -> Vec<&'static str> {
        r.findings.iter().map(|f| f.code).collect()
    }

    fn keys() -> Keys {
        Keys {
            server_public: "0RSyG3nCXLBLGvNGqIzfhAqxV5s+RBgs1cq5AhCUcng=".into(),
            client_private: "yNMDBJ4Vd3nZuJ2FZ1ChNTvHNQg1KgLpOaOtQC8LSXY=".into(),
            client_public: "7DHFY2VYRZ7Ag+K7C6X0i9FfHkw+q4H0dqIiRCyEXHM=".into(),
            preshared: Some("dGVzdHBza3Rlc3Rwc2t0ZXN0cHNrdGVzdHBza3Rlc3Q=".into()),
        }
    }

    fn net() -> NetworkSpec {
        NetworkSpec {
            endpoint_host: "203.0.113.9".into(),
            ..Default::default()
        }
    }

    #[test]
    fn what_this_tool_writes_checks_clean_for_every_version() {
        for version in AwgVersion::ALL {
            for seed in 0..10u64 {
                let t =
                    Tunnel::generate(&mut SeededRng::new(seed), &GenOptions::for_version(version))
                        .unwrap();
                for (side, text) in [
                    ("client", client_conf(&net(), &t, &keys())),
                    ("server", server_conf(&net(), &t, &keys())),
                ] {
                    let r = check(&text, &CheckOptions::default());
                    assert_eq!(
                        r.version,
                        Some(version),
                        "{side} {version} read as {:?}",
                        r.version
                    );
                    assert!(
                        r.findings.iter().all(|f| f.level != Level::Error),
                        "{side} {version} seed {seed}: {:?}",
                        r.findings
                    );
                }
            }
        }
    }

    #[test]
    fn the_version_is_read_off_the_newest_field() {
        let v = |text: &str| infer_version(&ConfFile::parse(text));
        assert_eq!(v("Jc = 4\nH1 = 5"), AwgVersion::V1_0);
        assert_eq!(v("Jc = 4\nI1 = <r 10>"), AwgVersion::V1_5);
        assert_eq!(v("H1 = 100-200"), AwgVersion::V2_0);
        assert_eq!(v("S3 = 20"), AwgVersion::V2_0);
        assert_eq!(v("RekeyTimeout = 5"), AwgVersion::V3_0);
        assert_eq!(v("RandomTrailers = 1"), AwgVersion::V3_1);
    }

    #[test]
    fn a_plain_wireguard_config_is_said_to_be_one() {
        let r = check(
            "[Interface]\nPrivateKey = yNMDBJ4Vd3nZuJ2FZ1ChNTvHNQg1KgLpOaOtQC8LSXY=\nAddress = 10.0.0.2/32\n",
            &CheckOptions::default(),
        );
        assert!(codes(&r).contains(&"conf.not_obfuscated"));
        assert_eq!(r.version, None);
    }

    #[test]
    fn a_bare_parameter_block_is_not_held_to_a_tunnel() {
        let r = check(
            "Jc = 4\nJmin = 40\nJmax = 70\nS1 = 20\nS2 = 30",
            &CheckOptions::default(),
        );
        assert!(
            r.findings.iter().all(|f| f.level != Level::Error),
            "{:?}",
            r.findings
        );
        assert!(!codes(&r).contains(&"conf.missing_field"));
    }

    #[test]
    fn structure_problems_are_named() {
        let text = "[Interface]\nPrivateKey = short\nAddress = 10.0.0.2/32\nJc = 4\nJmin = 40\nJmax = 70\nBogus = 1\n\n[Peer]\nPublicKey = 0RSyG3nCXLBLGvNGqIzfhAqxV5s+RBgs1cq5AhCUcng=\nEndpoint = nowhere\n";
        let r = check(text, &CheckOptions::default());
        let c = codes(&r);
        assert!(c.contains(&"conf.bad_key"), "{c:?}");
        assert!(c.contains(&"conf.unknown_key"), "{c:?}");
        assert!(c.contains(&"conf.peer_bad_endpoint"), "{c:?}");
        assert_eq!(r.worst(), Some(Level::Error));
    }

    #[test]
    fn a_template_gets_one_note() {
        let text =
            "[Interface]\n# PrivateKey = \n# Address = \nJc = 4\nJmin = 40\nJmax = 70\n[Peer]\n";
        let r = check(text, &CheckOptions::default());
        assert!(codes(&r).contains(&"conf.template"));
        assert!(!codes(&r).contains(&"conf.missing_field"));
    }

    #[test]
    fn the_generator_rules_reach_a_pasted_file() {
        // Issue #14's ranges with the trailers on, and a <c> for a go client.
        let text = "Jc = 4\nJmin = 40\nJmax = 70\nS1 = 20\nS2 = 30\nS3 = 20\nS4 = 16\n\
                    H1 = 405138553-456138212\nH2 = 680931238-1038459501\n\
                    H3 = 1114423399-1432068193\nH4 = 3600000000-3600001000\n\
                    I1 = <b 0x01><c>\nRandomTrailers = 1\n";
        let r = check(text, &CheckOptions::default());
        assert_eq!(r.version, Some(AwgVersion::V3_1));
        let c = codes(&r);
        assert!(c.contains(&"h.width_loss"), "{c:?}");
        assert!(c.contains(&"client.tag_unsupported"), "{c:?}");
        assert!(!c.contains(&"version.awg3_missing"));
    }

    #[test]
    fn fields_the_file_never_wrote_are_not_reported() {
        // Only Jc: no Jmin/Jmax, so no "Jmin is not below Jmax" about zeros.
        let r = check("Jc = 4", &CheckOptions::default());
        assert!(r.findings.is_empty(), "{:?}", r.findings);
    }

    #[test]
    fn a_vpn_link_is_checked_as_the_config_inside_it() {
        let t = Tunnel::generate(&mut SeededRng::new(3), &GenOptions::default()).unwrap();
        let conf = client_conf(&net(), &t, &keys());
        let link = crate::vpn::conf_to_vpn(&conf).unwrap();
        let r = check(&link, &CheckOptions::default());
        assert_eq!(r.version, Some(AwgVersion::V3_0));
        assert!(
            r.findings.iter().all(|f| f.level != Level::Error),
            "{:?}",
            r.findings
        );
        assert!(codes(&check("vpn://AAAA", &CheckOptions::default())).contains(&"conf.bad_link"));
    }

    #[test]
    fn numbers_that_are_not_numbers_are_findings_not_panics() {
        let r = check(
            "Jc = four\nH1 = 1-x\nHeaderProtectionKey = nope",
            &CheckOptions::default(),
        );
        let c = codes(&r);
        assert!(c.contains(&"conf.not_a_number"));
        assert!(c.contains(&"conf.bad_hpk"));
    }
}
