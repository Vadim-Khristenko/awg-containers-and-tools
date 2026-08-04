//! `vpn://` links — the format the Amnezia client imports.
//!
//! Wire format, matching `Any-Tech-ARCHITECT/src/utils/mergekeys.ts`:
//!
//! ```text
//! vpn:// + base64url( 4-byte big-endian original length + zlib(JSON) )
//! ```
//!
//! Padding is stripped from the base64url on the way out and restored on the
//! way in, which is what the client and the web editor both do.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use serde_json::{Map, Value, json};
use std::io::{Read, Write};

use crate::{Error, Result};

/// Fields the client reads directly off the container in addition to `config`.
const MIRRORED: [&str; 8] = ["Jc", "Jmin", "Jmax", "I1", "I2", "I3", "I4", "I5"];

fn parse_conf(conf: &str) -> Vec<(String, String)> {
    conf.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty() && !l.starts_with('['))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

fn field<'a>(entries: &'a [(String, String)], key: &str) -> Option<&'a str> {
    entries
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// Wrap a `.conf` into the `VpnConfig` object the client expects.
pub fn build_vpn_config(conf: &str) -> Value {
    let entries = parse_conf(conf);

    // IPv6 endpoints look like "[::1]:51820", so only a trailing :port is cut.
    let endpoint = field(&entries, "Endpoint").unwrap_or_default();
    let host = match endpoint.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => h,
        _ => endpoint,
    };
    let host = if host.is_empty() { "amneziawg" } else { host };

    let dns: Vec<&str> = field(&entries, "DNS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    let mut awg = Map::new();
    awg.insert("config".into(), json!(conf));
    for f in MIRRORED {
        if let Some(v) = field(&entries, f) {
            awg.insert(f.into(), json!(v));
        }
    }

    // last_config is the JSON twin Amnezia stores alongside the text config.
    let mut flat = Map::new();
    for (k, v) in &entries {
        flat.insert(k.clone(), json!(v));
    }
    flat.insert("config".into(), json!(conf));
    awg.insert(
        "last_config".into(),
        json!(serde_json::to_string_pretty(&Value::Object(flat)).unwrap_or_default()),
    );

    json!({
        "containers": [{ "container": "amneziawg", "awg": Value::Object(awg) }],
        "defaultContainer": "amneziawg",
        "description": "AmneziaWG",
        "hostName": host,
        "dns1": dns.first().copied().unwrap_or(""),
        "dns2": dns.get(1).copied().unwrap_or(""),
        "nameOverriddenByUser": false,
    })
}

pub fn encode(config: &Value) -> Result<String> {
    let json = serde_json::to_vec(config).map_err(|e| Error::Key(e.to_string()))?;

    let mut z = ZlibEncoder::new(Vec::new(), Compression::best());
    z.write_all(&json).map_err(|e| Error::Key(e.to_string()))?;
    let compressed = z.finish().map_err(|e| Error::Key(e.to_string()))?;

    let mut payload = Vec::with_capacity(4 + compressed.len());
    payload.extend_from_slice(&(json.len() as u32).to_be_bytes());
    payload.extend_from_slice(&compressed);

    Ok(format!("vpn://{}", URL_SAFE_NO_PAD.encode(payload)))
}

/// Turn a `.conf` straight into a link.
pub fn conf_to_vpn(conf: &str) -> Result<String> {
    encode(&build_vpn_config(conf))
}

pub fn decode(link: &str) -> Result<Value> {
    let body = link.trim().strip_prefix("vpn://").unwrap_or(link.trim());
    let bytes = URL_SAFE_NO_PAD
        .decode(body.trim_end_matches('='))
        .map_err(|e| Error::Key(format!("not base64url: {e}")))?;
    if bytes.len() < 5 {
        return Err(Error::Key("link too short to hold a header".into()));
    }

    let declared = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let mut out = Vec::with_capacity(declared);
    ZlibDecoder::new(&bytes[4..])
        .read_to_end(&mut out)
        .map_err(|e| Error::Key(format!("zlib: {e}")))?;

    // The header is the client's sanity check; treat a mismatch as corruption
    // rather than trusting half a config.
    if out.len() != declared {
        return Err(Error::Key(format!(
            "length header says {declared}, payload is {}",
            out.len()
        )));
    }
    serde_json::from_slice(&out).map_err(|e| Error::Key(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONF: &str = "[Interface]\nAddress = 10.8.1.2/32\nDNS = 1.1.1.1, 8.8.8.8\nPrivateKey = aGVsbG8=\nJc = 5\nJmin = 509\nJmax = 627\nI1 = <b 0xc2000000><t>\n\n[Peer]\nPublicKey = d29ybGQ=\nEndpoint = 203.0.113.10:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n";

    #[test]
    fn round_trips_through_the_wire_format() {
        let link = conf_to_vpn(CONF).unwrap();
        assert!(link.starts_with("vpn://"));
        let back = decode(&link).unwrap();
        assert_eq!(back, build_vpn_config(CONF));
    }

    #[test]
    fn host_is_the_endpoint_without_its_port() {
        let v = build_vpn_config(CONF);
        assert_eq!(v["hostName"], "203.0.113.10");
        assert_eq!(v["dns1"], "1.1.1.1");
        assert_eq!(v["dns2"], "8.8.8.8");
    }

    #[test]
    fn ipv6_endpoints_keep_their_brackets() {
        let conf = "[Peer]\nEndpoint = [2001:db8::1]:51820\n";
        assert_eq!(build_vpn_config(conf)["hostName"], "[2001:db8::1]");
    }

    #[test]
    fn obfuscation_fields_are_mirrored_onto_the_container() {
        let v = build_vpn_config(CONF);
        let awg = &v["containers"][0]["awg"];
        assert_eq!(awg["Jc"], "5");
        assert_eq!(awg["I1"], "<b 0xc2000000><t>");
        // S/H values are not mirrored — the client reads them from `config`
        assert!(awg.get("S1").is_none());
    }

    #[test]
    fn a_corrupted_length_header_is_rejected() {
        let link = conf_to_vpn(CONF).unwrap();
        let mut bytes = URL_SAFE_NO_PAD.decode(&link[6..]).unwrap();
        bytes[3] ^= 0xff;
        let broken = format!("vpn://{}", URL_SAFE_NO_PAD.encode(bytes));
        assert!(decode(&broken).is_err());
    }
}
