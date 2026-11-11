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
//!
//! The JSON is the object the client builds itself when it imports a `.conf`
//! (`ImportController::extractWireGuardConfig` in amnezia-client 5.1): one
//! `amnezia-awg` container whose `awg.last_config` is a JSON string holding
//! the text config and its fields. A container name the client does not know
//! imports as "no protocol installed", so the names and keys below are the
//! client's, not ours.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use serde_json::{Map, Value, json};
use std::io::{Read, Write};

use crate::{Error, Result};

/// `ContainerUtils::containerToString(DockerContainer::Awg)`.
const CONTAINER: &str = "amnezia-awg";

/// `configKey::awgProtocolKeys()`: the keys the client copies out of a
/// `.conf` into `last_config`, as strings. The 3.x ones are in the list from
/// 5.0.0.2 on; the 4.8 releases do not have them.
const AWG_KEYS: [&str; 25] = [
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
        .filter(|v| !v.is_empty())
}

/// `Endpoint` split the way the client's `QUrl::fromUserInput` splits it: the
/// host without IPv6 brackets, and the port, 51820 when there is none.
fn endpoint(entries: &[(String, String)]) -> (String, u16) {
    let ep = field(entries, "Endpoint").unwrap_or_default();
    let (host, port) = match ep.rsplit_once(':') {
        Some((h, p))
            if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && !h.ends_with(':') =>
        {
            (h, p.parse().unwrap_or(51820))
        }
        _ => (ep, 51820),
    };
    (
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_string(),
        port,
    )
}

/// Wrap a `.conf` into the server object the client imports.
pub fn build_vpn_config(conf: &str) -> Value {
    let entries = parse_conf(conf);
    let (host, port) = endpoint(&entries);

    let mut last = Map::new();
    last.insert("config".into(), json!(conf));
    last.insert("hostName".into(), json!(host));
    last.insert("port".into(), json!(port));
    for (key, from) in [
        ("client_priv_key", "PrivateKey"),
        ("client_ip", "Address"),
        ("psk_key", "PresharedKey"),
        ("server_pub_key", "PublicKey"),
        ("persistent_keep_alive", "PersistentKeepalive"),
    ] {
        if let Some(v) = field(&entries, from) {
            last.insert(key.into(), json!(v));
        }
    }
    last.insert(
        "mtu".into(),
        json!(field(&entries, "MTU").unwrap_or("1280")),
    );
    let allowed: Vec<&str> = field(&entries, "AllowedIPs")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    last.insert("allowed_ips".into(), json!(allowed));
    for key in AWG_KEYS {
        if let Some(v) = field(&entries, key) {
            last.insert(key.into(), json!(v));
        }
    }

    let awg = json!({
        "last_config": serde_json::to_string_pretty(&Value::Object(last)).unwrap_or_default(),
        "isThirdPartyConfig": true,
        "port": port.to_string(),
        "transport_proto": "udp",
    });

    let mut top = Map::new();
    top.insert(
        "containers".into(),
        json!([{ "container": CONTAINER, "awg": awg }]),
    );
    top.insert("defaultContainer".into(), json!(CONTAINER));
    // The name the server gets in the client's list: with the host in it,
    // two imported servers are two names rather than the same one twice.
    top.insert(
        "description".into(),
        json!(if host.is_empty() {
            "AmneziaWG".to_string()
        } else {
            format!("AmneziaWG {host}")
        }),
    );
    top.insert("hostName".into(), json!(host));
    // The client sets these only when the config names two servers, and an
    // empty one would be a resolver it tries to use.
    let dns: Vec<&str> = field(&entries, "DNS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    for (key, v) in ["dns1", "dns2"].into_iter().zip(&dns) {
        top.insert(key.into(), json!(v));
    }
    Value::Object(top)
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

/// What `awg-peer` writes as the endpoint when the node was not told its own
/// public address.
pub(crate) const PLACEHOLDER_HOST: &str = "SERVER_PUBLIC_IP";

/// Turn a `.conf` straight into a link.
///
/// The client drops a config without an endpoint or without the three keys
/// of a tunnel, so a link that would import as nothing is refused here.
pub fn conf_to_vpn(conf: &str) -> Result<String> {
    let entries = parse_conf(conf);
    let missing: Vec<&str> = ["PrivateKey", "Address", "PublicKey", "Endpoint"]
        .into_iter()
        .filter(|k| field(&entries, k).is_none())
        .collect();
    if !missing.is_empty() || endpoint(&entries).0.is_empty() {
        return Err(Error::Key(format!(
            "the config has no {}: the Amnezia client would import nothing",
            if missing.is_empty() {
                "Endpoint host".to_string()
            } else {
                missing.join(", ")
            }
        )));
    }
    if endpoint(&entries).0 == PLACEHOLDER_HOST {
        return Err(Error::Key(format!(
            "the Endpoint is still {PLACEHOLDER_HOST}: set AWG_PUBLIC_HOST (or AWG_ENDPOINT) on the node, or fix the Endpoint line, and issue the config again"
        )));
    }
    encode(&build_vpn_config(conf))
}

/// The `.conf` inside a link: the AmneziaWG container's `config`, or the one
/// inside its `last_config` JSON, which is where links the app shares keep it.
pub fn conf_from_link(link: &str) -> Result<String> {
    let value = decode(link)?;
    let containers = value["containers"].as_array().cloned().unwrap_or_default();
    for c in &containers {
        let awg = &c["awg"];
        if let Some(conf) = awg["config"].as_str() {
            return Ok(conf.to_string());
        }
        if let Some(last) = awg["last_config"].as_str()
            && let Ok(inner) = serde_json::from_str::<Value>(last)
            && let Some(conf) = inner["config"].as_str()
        {
            return Ok(conf.to_string());
        }
    }
    Err(Error::Key(
        "no AmneziaWG container with a config in the link".into(),
    ))
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

    const CONF: &str = "[Interface]\nAddress = 10.8.1.2/32\nDNS = 1.1.1.1, 8.8.8.8\nPrivateKey = aGVsbG8=\nMTU = 1280\nJc = 5\nJmin = 509\nJmax = 627\nS1 = 35\nS2 = 64\nH1 = 1144-1199\nH4 = 9000\nI1 = <b 0xc2000000><t>\nHeaderProtectionKey = c2VjcmV0\nRandomTrailers = 1\n\n[Peer]\nPublicKey = d29ybGQ=\nPresharedKey = cHNr\nEndpoint = 203.0.113.10:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n";

    fn last_config(v: &Value) -> Value {
        serde_json::from_str(v["containers"][0]["awg"]["last_config"].as_str().unwrap()).unwrap()
    }

    #[test]
    fn round_trips_through_the_wire_format() {
        let link = conf_to_vpn(CONF).unwrap();
        assert!(link.starts_with("vpn://"));
        let back = decode(&link).unwrap();
        assert_eq!(back, build_vpn_config(CONF));
        assert_eq!(conf_from_link(&link).unwrap(), CONF);
    }

    #[test]
    fn the_container_is_one_the_client_knows() {
        let v = build_vpn_config(CONF);
        assert_eq!(v["defaultContainer"], "amnezia-awg");
        assert_eq!(v["containers"][0]["container"], "amnezia-awg");
        let awg = &v["containers"][0]["awg"];
        assert_eq!(awg["isThirdPartyConfig"], true);
        assert_eq!(awg["port"], "51820");
        assert_eq!(awg["transport_proto"], "udp");
    }

    #[test]
    fn last_config_carries_the_tunnel_as_the_client_reads_it() {
        let last = last_config(&build_vpn_config(CONF));
        assert_eq!(last["config"], CONF);
        assert_eq!(last["hostName"], "203.0.113.10");
        assert_eq!(last["port"], 51820);
        assert_eq!(last["client_priv_key"], "aGVsbG8=");
        assert_eq!(last["client_ip"], "10.8.1.2/32");
        assert_eq!(last["psk_key"], "cHNr");
        assert_eq!(last["server_pub_key"], "d29ybGQ=");
        assert_eq!(last["mtu"], "1280");
        assert_eq!(last["persistent_keep_alive"], "25");
        assert_eq!(last["allowed_ips"], json!(["0.0.0.0/0", "::/0"]));
    }

    #[test]
    fn every_obfuscation_key_travels_as_a_string() {
        let last = last_config(&build_vpn_config(CONF));
        for (k, v) in [
            ("Jc", "5"),
            ("S1", "35"),
            ("S2", "64"),
            ("H1", "1144-1199"),
            ("H4", "9000"),
            ("I1", "<b 0xc2000000><t>"),
            ("HeaderProtectionKey", "c2VjcmV0"),
            ("RandomTrailers", "1"),
        ] {
            assert_eq!(last[k], v, "{k}");
        }
        assert!(last.get("S3").is_none());
    }

    #[test]
    fn host_is_the_endpoint_without_its_port() {
        let v = build_vpn_config(CONF);
        assert_eq!(v["hostName"], "203.0.113.10");
        assert_eq!(v["dns1"], "1.1.1.1");
        assert_eq!(v["dns2"], "8.8.8.8");
    }

    #[test]
    fn ipv6_endpoints_lose_their_brackets_as_in_the_client() {
        let conf = "[Peer]\nEndpoint = [2001:db8::1]:443\n";
        let v = build_vpn_config(conf);
        assert_eq!(v["hostName"], "2001:db8::1");
        assert_eq!(last_config(&v)["port"], 443);
    }

    #[test]
    fn one_dns_server_leaves_dns2_out() {
        let v = build_vpn_config(&CONF.replace("1.1.1.1, 8.8.8.8", "172.29.172.254"));
        assert_eq!(v["dns1"], "172.29.172.254");
        assert!(v.get("dns2").is_none());
    }

    #[test]
    fn a_config_the_client_would_drop_gives_no_link() {
        assert!(conf_to_vpn(&CONF.replace("Endpoint = 203.0.113.10:51820\n", "")).is_err());
        assert!(conf_to_vpn(&CONF.replace("PrivateKey = aGVsbG8=\n", "")).is_err());
    }

    #[test]
    fn the_placeholder_endpoint_gives_no_link() {
        let conf = CONF.replace("203.0.113.10:51820", "SERVER_PUBLIC_IP:51820");
        let e = conf_to_vpn(&conf).unwrap_err().to_string();
        assert!(e.contains("AWG_PUBLIC_HOST"), "{e}");
    }

    #[test]
    fn the_server_is_named_after_its_host() {
        assert_eq!(
            build_vpn_config(CONF)["description"],
            "AmneziaWG 203.0.113.10"
        );
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
