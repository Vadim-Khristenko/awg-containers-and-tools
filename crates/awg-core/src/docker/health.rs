//! Is the interface up, does the UAPI socket answer, how many peers are there,
//! when did each last handshake, and how much has moved.
//!
//! Everything here comes out of one `docker exec` — a probe split across six
//! round trips would describe six slightly different moments, and a handshake
//! age computed against the caller's clock rather than the container's is wrong
//! by whatever the two disagree about.
//!
//! `awg show` cannot be used: `amneziawg-tools` does not know the 3.0 keys and
//! drops everything after `ContentPaddingAddition`. The container ships
//! `awg-uapi`, which speaks `get=1` to the daemon's socket directly, and that is
//! what this probe runs.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use std::collections::BTreeMap;

use super::host::{Host, safe_name};
use super::logs::redact;
use super::obfuscation::OBFUSCATION_UAPI_KEYS;
use crate::{Error, Result};

/// UAPI names that carry key material and must never be stored.
const UAPI_SECRETS: [&str; 3] = ["private_key", "preshared_key", "header_protection_key"];

/// One peer as the daemon reports it. No secret is carried: the preshared key is
/// reduced to whether there is one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UapiPeer {
    /// Base64, the spelling every other tool uses.
    pub public_key: String,
    pub has_preshared_key: bool,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    /// Unix seconds; `0` means the peer has never completed a handshake.
    pub last_handshake_secs: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub persistent_keepalive_interval: u32,
}

impl UapiPeer {
    pub fn ever_handshaked(&self) -> bool {
        self.last_handshake_secs > 0
    }

    /// Seconds since the last handshake, given the clock the device was read
    /// with. `None` when the peer has never handshaked.
    pub fn handshake_age(&self, now_secs: u64) -> Option<u64> {
        if self.last_handshake_secs == 0 {
            None
        } else {
            Some(now_secs.saturating_sub(self.last_handshake_secs))
        }
    }
}

/// A `get=1` dump, with the secrets left out on purpose.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UapiDevice {
    pub listen_port: Option<u32>,
    pub fwmark: Option<u32>,
    pub errno: Option<i64>,
    pub has_private_key: bool,
    pub has_header_protection_key: bool,
    /// The obfuscation block as the daemon has it, keyed by UAPI name. The
    /// header-protection key appears as `header_protection_key` with the value
    /// replaced by its length, never the key.
    pub obfuscation: BTreeMap<String, String>,
    pub peers: Vec<UapiPeer>,
}

fn hex_to_b64(hex: &str) -> Option<String> {
    let h = hex.trim();
    if !h.len().is_multiple_of(2) || h.is_empty() || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let bytes: Vec<u8> = (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap_or(0))
        .collect();
    Some(B64.encode(bytes))
}

/// Parse a `get=1` dump.
///
/// Values under [`UAPI_SECRETS`] are read only far enough to record that they
/// are set; they are never placed in the returned structure, so a caller that
/// prints a [`UapiDevice`] cannot print a key.
pub fn parse_uapi_get(text: &str) -> UapiDevice {
    let mut dev = UapiDevice::default();
    let mut current: Option<UapiPeer> = None;

    for line in text.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        match key {
            "public_key" => {
                if let Some(p) = current.take() {
                    dev.peers.push(p);
                }
                current = Some(UapiPeer {
                    public_key: hex_to_b64(value).unwrap_or_else(|| value.to_string()),
                    ..Default::default()
                });
            }
            "private_key" => dev.has_private_key = !value.chars().all(|c| c == '0'),
            "header_protection_key" => {
                dev.has_header_protection_key = !value.chars().all(|c| c == '0');
                // Length, not the key: enough to tell "set" from "absent" and to
                // catch a truncated one, and useless to anyone who reads it.
                dev.obfuscation.insert(
                    "header_protection_key".to_string(),
                    format!("<{} bytes>", value.len() / 2),
                );
            }
            "preshared_key" => {
                if let Some(p) = current.as_mut() {
                    p.has_preshared_key = !value.chars().all(|c| c == '0');
                }
            }
            "listen_port" => dev.listen_port = value.parse().ok(),
            "fwmark" => dev.fwmark = value.parse().ok(),
            "errno" => dev.errno = value.parse().ok(),
            "endpoint" => {
                if let Some(p) = current.as_mut() {
                    p.endpoint = Some(value.to_string());
                }
            }
            "allowed_ip" => {
                if let Some(p) = current.as_mut() {
                    p.allowed_ips.push(value.to_string());
                }
            }
            "last_handshake_time_sec" => {
                if let Some(p) = current.as_mut() {
                    p.last_handshake_secs = value.parse().unwrap_or(0);
                }
            }
            "rx_bytes" => {
                if let Some(p) = current.as_mut() {
                    p.rx_bytes = value.parse().unwrap_or(0);
                }
            }
            "tx_bytes" => {
                if let Some(p) = current.as_mut() {
                    p.tx_bytes = value.parse().unwrap_or(0);
                }
            }
            "persistent_keepalive_interval" => {
                if let Some(p) = current.as_mut() {
                    p.persistent_keepalive_interval = value.parse().unwrap_or(0);
                }
            }
            other => {
                // Device-level obfuscation only: a peer block carries none.
                if current.is_none()
                    && OBFUSCATION_UAPI_KEYS.contains(&other)
                    && !UAPI_SECRETS.contains(&other)
                {
                    dev.obfuscation.insert(other.to_string(), value.to_string());
                }
            }
        }
    }
    if let Some(p) = current.take() {
        dev.peers.push(p);
    }
    dev
}

/// UDP counters for the container's network namespace, out of `/proc/net/snmp`.
///
/// This is the only dependable answer to "has anything at all arrived here".
/// The DNAT packet counters look like they should answer it and do not: with
/// docker's userland proxying enabled — the default — traffic to a published
/// port is forwarded by `docker-proxy` and never traverses the DNAT rule, so
/// the rule's counter reads zero while packets are arriving. Verified against
/// docker 29.6.1.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpStats {
    pub in_datagrams: u64,
    /// Datagrams that arrived for a port nothing was listening on.
    pub no_ports: u64,
    pub in_errors: u64,
    pub out_datagrams: u64,
    pub rcvbuf_errors: u64,
}

/// Parse the two `Udp:` lines of `/proc/net/snmp` — one of names, one of values.
pub fn parse_udp_snmp(text: &str) -> Option<UdpStats> {
    let mut names: Vec<&str> = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("Udp:") else {
            continue;
        };
        let fields: Vec<&str> = rest.split_whitespace().collect();
        if fields.first().is_some_and(|f| f.parse::<u64>().is_ok()) {
            if names.is_empty() {
                return None;
            }
            let by_name: BTreeMap<&str, u64> = names
                .iter()
                .copied()
                .zip(fields.iter().filter_map(|v| v.parse::<u64>().ok()))
                .collect();
            let get = |k: &str| by_name.get(k).copied().unwrap_or(0);
            return Some(UdpStats {
                in_datagrams: get("InDatagrams"),
                no_ports: get("NoPorts"),
                in_errors: get("InErrors"),
                out_datagrams: get("OutDatagrams"),
                rcvbuf_errors: get("RcvbufErrors"),
            });
        }
        names = fields;
    }
    None
}

/// What a single health probe found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Health {
    pub container: String,
    pub interface: String,
    /// The container's own clock at the moment of the probe, so a handshake
    /// timestamp can be turned into an age without trusting the caller's clock.
    pub now_secs: Option<u64>,
    /// The `UP` flag on the tunnel device — a userspace WireGuard interface sits
    /// at `state UNKNOWN` forever, so the flag is the only signal.
    pub interface_up: bool,
    pub interface_output: String,
    pub addresses: Vec<String>,
    /// The UAPI socket answered a `get=1`.
    pub uapi_ok: bool,
    pub uapi_error: Option<String>,
    pub device: UapiDevice,
    /// `/dev/net/tun` is a character device inside the container.
    pub tun_present: Option<bool>,
    /// `/proc/sys/net/ipv4/ip_forward` as read inside the container.
    pub ip_forward: Option<bool>,
    /// UDP counters for the container's namespace — see [`UdpStats`].
    pub udp: Option<UdpStats>,
}

impl Health {
    pub fn peer_count(&self) -> usize {
        self.device.peers.len()
    }

    pub fn peers_ever_handshaked(&self) -> usize {
        self.device
            .peers
            .iter()
            .filter(|p| p.ever_handshaked())
            .count()
    }

    pub fn rx_bytes(&self) -> u64 {
        self.device.peers.iter().map(|p| p.rx_bytes).sum()
    }

    pub fn tx_bytes(&self) -> u64 {
        self.device.peers.iter().map(|p| p.tx_bytes).sum()
    }

    /// The freshest handshake across all peers, as an age in seconds.
    pub fn newest_handshake_age(&self) -> Option<u64> {
        let now = self.now_secs?;
        self.device
            .peers
            .iter()
            .filter_map(|p| p.handshake_age(now))
            .min()
    }
}

/// Marker the probe script prints between sections.
pub const PROBE_MARKER: &str = "@@awg-probe:";

/// One `docker exec` that answers every health question at once.
pub fn health_probe_command(container: &str, interface: &str) -> Result<String> {
    let c = safe_name(container)?;
    let i = safe_name(interface)?;
    Ok(format!(
        "docker exec {c} sh -c '\
         echo {PROBE_MARKER}epoch; date +%s; \
         echo {PROBE_MARKER}link; ip -o link show {i} 2>&1; \
         echo {PROBE_MARKER}addr; ip -o -4 addr show {i} 2>&1; \
         echo {PROBE_MARKER}tun; if [ -c /dev/net/tun ]; then echo present; else echo absent; fi; \
         echo {PROBE_MARKER}forward; cat /proc/sys/net/ipv4/ip_forward 2>/dev/null; \
         echo {PROBE_MARKER}udp; grep ^Udp: /proc/net/snmp 2>/dev/null; \
         echo {PROBE_MARKER}uapi; awg-uapi get 2>&1; \
         echo {PROBE_MARKER}end'"
    ))
}

/// Split probe output on [`PROBE_MARKER`].
pub fn parse_sections(output: &str) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let mut current = String::new();
    let mut body = String::new();
    for line in output.lines() {
        if let Some(name) = line.trim().strip_prefix(PROBE_MARKER) {
            if !current.is_empty() {
                out.insert(current.clone(), body.clone());
            }
            current = name.trim().to_string();
            body.clear();
            continue;
        }
        if !current.is_empty() {
            body.push_str(line);
            body.push('\n');
        }
    }
    if !current.is_empty() {
        out.insert(current, body);
    }
    out
}

/// Turn probe output into a [`Health`]. Pure, so the diagnosis logic can be
/// tested against captured output from a broken host.
pub fn parse_health(container: &str, interface: &str, probe_output: &str) -> Health {
    let s = parse_sections(probe_output);
    let get = |k: &str| {
        s.get(k)
            .map(String::as_str)
            .unwrap_or("")
            .trim()
            .to_string()
    };

    let uapi_text = get("uapi");
    // `awg-uapi` prints `no UAPI socket at ...` and exits when the daemon is not
    // listening; a real dump always has at least one `key=value`.
    let uapi_ok = uapi_text.lines().any(|l| l.contains('='));
    let link = get("link");

    Health {
        container: container.to_string(),
        interface: interface.to_string(),
        now_secs: get("epoch")
            .lines()
            .next()
            .and_then(|l| l.trim().parse().ok()),
        interface_up: crate::deploy::config::parse_interface_up(&link, interface),
        interface_output: link,
        addresses: get("addr")
            .lines()
            .filter_map(|l| {
                l.split_whitespace()
                    .skip_while(|t| *t != "inet")
                    .nth(1)
                    .map(str::to_string)
            })
            .collect(),
        uapi_ok,
        uapi_error: if uapi_ok {
            None
        } else {
            Some(redact(&uapi_text))
        },
        device: if uapi_ok {
            parse_uapi_get(&uapi_text)
        } else {
            UapiDevice::default()
        },
        tun_present: match get("tun").as_str() {
            "present" => Some(true),
            "absent" => Some(false),
            _ => None,
        },
        ip_forward: get("forward").lines().next().and_then(|l| match l.trim() {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        }),
        udp: parse_udp_snmp(&get("udp")),
    }
}

/// Interface, socket, peers, handshakes and counters, in one round trip.
pub fn health(host: &Host, container: &str, interface: &str) -> Result<Health> {
    let (out, err, _) = host.run_docker(&health_probe_command(container, interface)?)?;
    // The probe folds each section's stderr into stdout, but a failure to exec
    // at all lands in `err` and has to stay visible.
    let combined = if out.contains(PROBE_MARKER) {
        out
    } else {
        format!("{out}{err}")
    };
    if !combined.contains(PROBE_MARKER) {
        return Err(Error::Ssh(format!(
            "the health probe did not run inside {container}: {}",
            redact(combined.trim())
        )));
    }
    Ok(parse_health(container, interface, &combined))
}

#[cfg(test)]
pub(crate) mod fixtures {
    /// A `get=1` dump with two peers, one of which has never handshaked.
    pub(crate) const UAPI: &str = "\
private_key=4f3e2d1c0b9a8776554433221100ffeeddccbbaa99887766554433221100aabb
listen_port=51820
jc=5
jmin=41
jmax=113
s1=48
s2=39
s3=25
s4=32
h1=1188112031
h2=1651454815
h3=1275092325
h4=1064772620
header_protection_key=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
content_padding_addition=4-32
rekey_after_time=100-140
public_key=e83b5f4e5e8c1e63e7e0b4a02f5b7b8a4d16e7a5c3d2b1a0918273645564738a
preshared_key=1122334455667788990011223344556677889900112233445566778899001122
allowed_ip=10.8.1.2/32
last_handshake_time_sec=1770000000
last_handshake_time_nsec=123
rx_bytes=4096
tx_bytes=8192
persistent_keepalive_interval=25
public_key=aa3b5f4e5e8c1e63e7e0b4a02f5b7b8a4d16e7a5c3d2b1a0918273645564738a
allowed_ip=10.8.1.3/32
last_handshake_time_sec=0
rx_bytes=0
tx_bytes=0
errno=0
";

    /// The `ip -o link show` line a userspace WireGuard device really prints.
    pub(crate) const LINK_UP: &str = "5: awg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc fq_codel state UNKNOWN mode DEFAULT group default qlen 500\\    link/none";

    /// A healthy probe, one peer, handshaked 300 seconds before the clock reading.
    pub(crate) const PROBE: &str = "\
@@awg-probe:epoch
1770000300
@@awg-probe:link
5: awg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc fq_codel state UNKNOWN mode DEFAULT group default qlen 500\\    link/none
@@awg-probe:addr
5: awg0    inet 10.8.1.1/24 scope global awg0\\       valid_lft forever preferred_lft forever
@@awg-probe:tun
present
@@awg-probe:forward
1
@@awg-probe:udp
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors
Udp: 102 0 0 24 0 0 0 0 0
@@awg-probe:uapi
private_key=4f3e2d1c0b9a8776554433221100ffeeddccbbaa99887766554433221100aabb
listen_port=51820
jc=5
public_key=e83b5f4e5e8c1e63e7e0b4a02f5b7b8a4d16e7a5c3d2b1a0918273645564738a
allowed_ip=10.8.1.2/32
last_handshake_time_sec=1770000000
rx_bytes=4096
tx_bytes=8192
errno=0
@@awg-probe:end
";
}

#[cfg(test)]
mod tests {
    use super::fixtures::{PROBE, UAPI};
    use super::*;

    #[test]
    fn a_uapi_dump_yields_peers_without_carrying_a_single_secret() {
        let d = parse_uapi_get(UAPI);
        assert_eq!(d.listen_port, Some(51820));
        assert_eq!(d.errno, Some(0));
        assert!(d.has_private_key);
        assert!(d.has_header_protection_key);
        assert_eq!(d.peers.len(), 2);

        assert!(d.peers[0].has_preshared_key);
        assert!(d.peers[0].ever_handshaked());
        assert_eq!(d.peers[0].rx_bytes, 4096);
        assert_eq!(d.peers[0].tx_bytes, 8192);
        assert_eq!(d.peers[0].allowed_ips, vec!["10.8.1.2/32"]);
        assert_eq!(d.peers[0].handshake_age(1770000300), Some(300));
        assert_eq!(d.peers[0].persistent_keepalive_interval, 25);
        // Hex on the wire, base64 everywhere a human sees it.
        assert_eq!(
            d.peers[0].public_key,
            "6DtfTl6MHmPn4LSgL1t7ik0W56XD0rGgkYJzZFVkc4o="
        );

        assert!(!d.peers[1].has_preshared_key);
        assert!(!d.peers[1].ever_handshaked());
        assert_eq!(d.peers[1].handshake_age(1770000300), None);
    }

    #[test]
    fn no_secret_survives_the_parse() {
        let dump = format!("{:?}", parse_uapi_get(UAPI));
        for secret in [
            "4f3e2d1c0b9a8776554433221100ffee",
            "00112233445566778899aabbccddeeff",
            "1122334455667788990011223344556677889900112233445566778899001122",
        ] {
            assert!(!dump.contains(secret), "a secret reached the parsed device");
        }
        let d = parse_uapi_get(UAPI);
        assert_eq!(
            d.obfuscation
                .get("header_protection_key")
                .map(String::as_str),
            Some("<32 bytes>")
        );
        assert_eq!(d.obfuscation.get("jc").map(String::as_str), Some("5"));
        assert_eq!(d.obfuscation.get("s4").map(String::as_str), Some("32"));
    }

    #[test]
    fn an_all_zero_key_reads_as_absent_rather_than_as_set() {
        // The daemon answers with zeroes for a device that has no key, which is
        // not the same as a device carrying a key of zeroes.
        let text = format!("private_key={}\nlisten_port=1\n", "0".repeat(64));
        assert!(!parse_uapi_get(&text).has_private_key);
    }

    #[test]
    fn a_healthy_probe_reads_as_healthy() {
        let h = parse_health("awg-server", "awg0", PROBE);
        assert!(h.interface_up);
        assert!(h.uapi_ok);
        assert_eq!(h.uapi_error, None);
        assert_eq!(h.tun_present, Some(true));
        assert_eq!(h.ip_forward, Some(true));
        assert_eq!(h.now_secs, Some(1770000300));
        assert_eq!(h.addresses, vec!["10.8.1.1/24"]);
        assert_eq!(h.peer_count(), 1);
        assert_eq!(h.peers_ever_handshaked(), 1);
        assert_eq!(h.rx_bytes(), 4096);
        assert_eq!(h.tx_bytes(), 8192);
        assert_eq!(h.newest_handshake_age(), Some(300));
        assert_eq!(h.udp.unwrap().in_datagrams, 102);
        assert_eq!(h.udp.unwrap().out_datagrams, 24);
    }

    #[test]
    fn the_namespaces_udp_counters_are_read_by_name_and_not_by_position() {
        // Real output; the column set has grown over kernel versions, so the
        // names line is the only safe index.
        let s = parse_udp_snmp(
            "Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors\n\
             Udp: 102 3 1 24 0 0\n",
        )
        .unwrap();
        assert_eq!(s.in_datagrams, 102);
        assert_eq!(s.no_ports, 3);
        assert_eq!(s.in_errors, 1);
        assert_eq!(s.out_datagrams, 24);

        // A reordered header must not shift the values.
        let s = parse_udp_snmp("Udp: OutDatagrams InDatagrams\nUdp: 7 9\n").unwrap();
        assert_eq!(s.in_datagrams, 9);
        assert_eq!(s.out_datagrams, 7);

        assert!(parse_udp_snmp("").is_none());
        assert!(parse_udp_snmp("Tcp: InSegs\nTcp: 4\n").is_none());
        assert!(
            parse_udp_snmp("Udp: 1 2 3\n").is_none(),
            "values with no names"
        );
    }

    #[test]
    fn a_socket_that_does_not_answer_is_not_an_empty_device() {
        let probe = PROBE.replace(
            "private_key=4f3e2d1c0b9a8776554433221100ffeeddccbbaa99887766554433221100aabb",
            "no UAPI socket at /var/run/amneziawg/awg0.sock",
        );
        // Everything after that line still parses, so strip the rest too.
        let probe = probe
            .lines()
            .filter(|l| !l.contains('=') || l.starts_with("@@"))
            .collect::<Vec<_>>()
            .join("\n");
        let h = parse_health("awg-server", "awg0", &probe);
        assert!(!h.uapi_ok);
        assert!(
            h.uapi_error
                .as_deref()
                .is_some_and(|e| e.contains("no UAPI socket"))
        );
        assert_eq!(h.peer_count(), 0);
    }

    #[test]
    fn sections_are_split_on_the_marker_and_nothing_else() {
        let s = parse_sections(PROBE);
        assert_eq!(s["epoch"].trim(), "1770000300");
        assert_eq!(s["tun"].trim(), "present");
        assert!(s["uapi"].contains("listen_port=51820"));
        assert!(s.contains_key("end"));
        assert!(parse_sections("no markers here").is_empty());
    }

    #[test]
    fn the_probe_command_refuses_names_it_would_have_to_quote() {
        assert!(health_probe_command("ok", "awg0; id").is_err());
        assert!(health_probe_command("a b", "awg0").is_err());
        let c = health_probe_command("awg-server", "awg0").unwrap();
        assert!(c.starts_with("docker exec awg-server sh -c "));
        assert!(c.contains("awg-uapi get"));
        assert!(c.contains("/proc/sys/net/ipv4/ip_forward"));
    }
}
