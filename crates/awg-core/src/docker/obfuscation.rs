//! Do the two ends of a tunnel carry the same shared parameters.
//!
//! AmneziaWG obfuscation is symmetric. The junk packet counts, the magic
//! headers, the padding range and the 3.0 header key have to be byte-identical
//! on both sides; when they are not, nothing reports an error — the peers
//! simply never recognise each other's packets and the handshake times out.
//! That silence is why this comparison exists at all.
//!
//! The header-protection key is compared without ever being held: both sides
//! are reduced to a byte length, which distinguishes "set", "absent" and
//! "truncated" and is useless to anyone who reads it.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use std::collections::BTreeMap;

use super::health::UapiDevice;

/// The obfuscation keys in UAPI spelling. This is the set both ends of a tunnel
/// have to agree on.
pub const OBFUSCATION_UAPI_KEYS: [&str; 27] = [
    "jc",
    "jmin",
    "jmax",
    "s1",
    "s2",
    "s3",
    "s4",
    "h1",
    "h2",
    "h3",
    "h4",
    "i1",
    "i2",
    "i3",
    "i4",
    "i5",
    "itime",
    "j1",
    "j2",
    "j3",
    "header_protection_key",
    "content_padding_addition",
    "rekey_after_time",
    "rekey_timeout",
    "reject_after_time",
    "keepalive_timeout",
    "max_handshake_attempts",
];

/// `.conf` spelling paired with the UAPI spelling, for the same set.
pub const OBFUSCATION_CONF_KEYS: [(&str, &str); 27] = [
    ("Jc", "jc"),
    ("Jmin", "jmin"),
    ("Jmax", "jmax"),
    ("S1", "s1"),
    ("S2", "s2"),
    ("S3", "s3"),
    ("S4", "s4"),
    ("H1", "h1"),
    ("H2", "h2"),
    ("H3", "h3"),
    ("H4", "h4"),
    ("I1", "i1"),
    ("I2", "i2"),
    ("I3", "i3"),
    ("I4", "i4"),
    ("I5", "i5"),
    ("Itime", "itime"),
    ("J1", "j1"),
    ("J2", "j2"),
    ("J3", "j3"),
    ("HeaderProtectionKey", "header_protection_key"),
    ("ContentPaddingAddition", "content_padding_addition"),
    ("RekeyAfterTime", "rekey_after_time"),
    ("RekeyTimeout", "rekey_timeout"),
    ("RejectAfterTime", "reject_after_time"),
    ("KeepaliveTimeout", "keepalive_timeout"),
    ("MaxHandshakeAttempts", "max_handshake_attempts"),
];

/// One field the two ends do not agree on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObfuscationMismatch {
    /// UAPI spelling.
    pub field: String,
    pub server: String,
    pub client: String,
}

/// The result of putting a server's live obfuscation next to a client config.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObfuscationComparison {
    /// Fields present on both sides and equal.
    pub agreed: Vec<String>,
    pub mismatches: Vec<ObfuscationMismatch>,
    /// Set on the server and absent from the client config, and the reverse.
    pub server_only: Vec<String>,
    pub client_only: Vec<String>,
}

impl ObfuscationComparison {
    pub fn is_identical(&self) -> bool {
        self.mismatches.is_empty() && self.server_only.is_empty() && self.client_only.is_empty()
    }
}

/// The obfuscation block out of a live device.
pub fn obfuscation_from_uapi(dev: &UapiDevice) -> BTreeMap<String, String> {
    dev.obfuscation.clone()
}

/// The obfuscation block out of a `.conf`, normalised to UAPI names.
///
/// `HeaderProtectionKey` is base64 in a `.conf` and hex over UAPI; it is reduced
/// to its byte length here so the comparison can be made without the key itself
/// ever being held.
pub fn obfuscation_from_conf(conf: &str) -> BTreeMap<String, String> {
    let names: BTreeMap<&str, &str> = OBFUSCATION_CONF_KEYS.iter().copied().collect();
    let mut out = BTreeMap::new();
    let mut inside = false;
    for line in conf.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            inside = line.eq_ignore_ascii_case("[Interface]");
            continue;
        }
        if !inside || line.is_empty() {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        let Some(uapi) = names.get(k) else { continue };
        if *uapi == "header_protection_key" {
            let bytes = B64.decode(v).map(|b| b.len()).unwrap_or(0);
            out.insert((*uapi).to_string(), format!("<{bytes} bytes>"));
        } else {
            out.insert((*uapi).to_string(), v.to_string());
        }
    }
    out
}

/// Compare two obfuscation blocks, field by field including the ones only one
/// side carries.
pub fn compare_obfuscation(
    server: &BTreeMap<String, String>,
    client: &BTreeMap<String, String>,
) -> ObfuscationComparison {
    let mut c = ObfuscationComparison::default();
    for (field, s) in server {
        match client.get(field) {
            Some(v) if v == s => c.agreed.push(field.clone()),
            Some(v) => c.mismatches.push(ObfuscationMismatch {
                field: field.clone(),
                server: s.clone(),
                client: v.clone(),
            }),
            None => c.server_only.push(field.clone()),
        }
    }
    for field in client.keys() {
        if !server.contains_key(field) {
            c.client_only.push(field.clone());
        }
    }
    c
}

#[cfg(test)]
pub(crate) mod fixtures {
    /// A client `.conf` matching `health::fixtures::UAPI` exactly.
    pub(crate) const CLIENT_CONF: &str = "\
[Interface]
PrivateKey = yNMDBJ4Vd3nZuJ2FZ1ChNTvHNQg1KgLpOaOtQC8LSXY=
Address = 10.8.1.2/32
Jc = 5
Jmin = 41
Jmax = 113
S1 = 48
S2 = 39
S3 = 25
S4 = 32
H1 = 1188112031
H2 = 1651454815
H3 = 1275092325
H4 = 1064772620
HeaderProtectionKey = ABEiM0RVZneImaq7zN3u/wARIjNEVWZ3iJmqu8zd7v8=
ContentPaddingAddition = 4-32
RekeyAfterTime = 100-140

[Peer]
PublicKey = 7DHFY2VYRZ7Ag+K7C6X0i9FfHkw+q4H0dqIiRCyEXHM=
AllowedIPs = 0.0.0.0/0
";
}

#[cfg(test)]
mod tests {
    use super::fixtures::CLIENT_CONF;
    use super::*;
    use crate::docker::health::fixtures::UAPI;
    use crate::docker::health::parse_uapi_get;

    fn server() -> BTreeMap<String, String> {
        obfuscation_from_uapi(&parse_uapi_get(UAPI))
    }

    #[test]
    fn a_client_config_matching_the_live_device_compares_clean() {
        let c = compare_obfuscation(&server(), &obfuscation_from_conf(CLIENT_CONF));
        assert!(c.is_identical(), "{c:?}");
        assert!(c.agreed.contains(&"header_protection_key".to_string()));
        assert!(c.agreed.contains(&"jc".to_string()));
        assert_eq!(c.agreed.len(), 14, "every field the fixture carries");
    }

    #[test]
    fn one_wrong_junk_count_is_found_and_named() {
        let bad = CLIENT_CONF.replace("Jc = 5", "Jc = 6");
        let c = compare_obfuscation(&server(), &obfuscation_from_conf(&bad));
        assert!(!c.is_identical());
        assert_eq!(c.mismatches.len(), 1);
        assert_eq!(c.mismatches[0].field, "jc");
        assert_eq!(c.mismatches[0].server, "5");
        assert_eq!(c.mismatches[0].client, "6");
    }

    #[test]
    fn the_header_protection_key_is_compared_without_being_carried() {
        let s = server();
        let client = obfuscation_from_conf(CLIENT_CONF);
        assert_eq!(s["header_protection_key"], "<32 bytes>");
        assert_eq!(client["header_protection_key"], "<32 bytes>");
        // A truncated key is a different length, so it is still caught.
        let short = CLIENT_CONF.replace(
            "HeaderProtectionKey = ABEiM0RVZneImaq7zN3u/wARIjNEVWZ3iJmqu8zd7v8=",
            "HeaderProtectionKey = ABEiM0RVZneImaq7zN3u/w==",
        );
        let c = compare_obfuscation(&s, &obfuscation_from_conf(&short));
        assert_eq!(c.mismatches.len(), 1);
        assert_eq!(c.mismatches[0].field, "header_protection_key");
        assert_eq!(c.mismatches[0].client, "<16 bytes>");
    }

    #[test]
    fn a_field_present_on_one_side_only_is_reported_as_such() {
        let missing = CLIENT_CONF.replace("S4 = 32\n", "");
        let c = compare_obfuscation(&server(), &obfuscation_from_conf(&missing));
        assert!(!c.is_identical());
        assert!(c.mismatches.is_empty());
        assert_eq!(c.server_only, vec!["s4"]);

        let extra = CLIENT_CONF.replace("S4 = 32", "S4 = 32\nItime = 25");
        let c = compare_obfuscation(&server(), &obfuscation_from_conf(&extra));
        assert_eq!(c.client_only, vec!["itime"]);
    }

    #[test]
    fn only_the_interface_block_counts_and_comments_do_not() {
        // A `[Peer]` section has no obfuscation, and a commented-out value is
        // not a value.
        let conf = "[Interface]\nJc = 5\n# Jmin = 99\n\n[Peer]\nJmax = 7\n";
        let m = obfuscation_from_conf(conf);
        assert_eq!(m.get("jc").map(String::as_str), Some("5"));
        assert!(!m.contains_key("jmin"));
        assert!(!m.contains_key("jmax"), "a Peer block carries none");
    }
}
