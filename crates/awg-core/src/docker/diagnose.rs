//! What is wrong, on what evidence, and what to do about it.
//!
//! [`Evidence`] is the whole of what a verdict may be drawn from. Building it is
//! I/O ([`diagnose_container`]); reading it is not ([`diagnose`]), and that is
//! what keeps the verdicts testable against captured output from a host nobody
//! has to break twice.
//!
//! The individual rules live in [`super::faults`]. This module owns the shapes
//! they produce, the one piece of evidence that has nowhere else to live — the
//! DNAT packet counters — and the order the rules run in.

use super::discover::Container;
use super::health::Health;
use super::host::Host;
use super::inspect::Inspect;
use super::logs::redact;
use super::obfuscation::{
    ObfuscationComparison, compare_obfuscation, obfuscation_from_conf, obfuscation_from_uapi,
};
use super::{faults, tunnel};
use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FaultKind {
    ContainerNotRunning,
    NoTunDevice,
    MissingNetAdmin,
    IpForwardOff,
    PortNotPublished,
    InterfaceNeverConfigured,
    PeerNeverHandshaked,
    PeerStale,
    ObfuscationMismatch,
    /// A symptom with more than one cause the evidence cannot separate.
    Undetermined,
}

impl FaultKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FaultKind::ContainerNotRunning => "container-not-running",
            FaultKind::NoTunDevice => "no-tun-device",
            FaultKind::MissingNetAdmin => "missing-net-admin",
            FaultKind::IpForwardOff => "ip-forward-off",
            FaultKind::PortNotPublished => "port-not-published",
            FaultKind::InterfaceNeverConfigured => "interface-never-configured",
            FaultKind::PeerNeverHandshaked => "peer-never-handshaked",
            FaultKind::PeerStale => "peer-stale",
            FaultKind::ObfuscationMismatch => "obfuscation-mismatch",
            FaultKind::Undetermined => "undetermined",
        }
    }
}

/// How firmly the evidence supports the verdict.
///
/// `Confirmed` means something was observed that has no other explanation;
/// `Possible` means the symptom fits but so do the entries in
/// [`Finding::alternatives`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Possible,
    Likely,
    Confirmed,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Possible => "possible",
            Confidence::Likely => "likely",
            Confidence::Confirmed => "confirmed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: FaultKind,
    pub confidence: Confidence,
    /// What is wrong, in one sentence.
    pub what: String,
    /// What was observed. Every entry is something actually read off the host,
    /// quoted or summarised — never an inference.
    pub evidence: Vec<String>,
    /// The one thing to do next.
    pub next_step: String,
    /// Causes this evidence cannot rule out. Empty for a `Confirmed` finding.
    pub alternatives: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnosis {
    pub container: String,
    /// No findings *and* no blind spots.
    pub healthy: bool,
    pub findings: Vec<Finding>,
    /// Probes that could not be run, and why. An empty finding list next to a
    /// non-empty blind-spot list is not a clean bill of health.
    pub blind_spots: Vec<String>,
}

impl Diagnosis {
    pub fn worst(&self) -> Option<&Finding> {
        self.findings.iter().max_by_key(|f| f.confidence)
    }

    pub fn has(&self, kind: FaultKind) -> bool {
        self.findings.iter().any(|f| f.kind == kind)
    }
}

/// Packet counters for the DNAT rule that publishes a container port.
///
/// This is the only server-side observation that distinguishes "nothing is
/// arriving" from "packets arrive and the handshake still fails", which is
/// otherwise the hardest pair of causes in this module to tell apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortTraffic {
    pub port: u16,
    pub protocol: String,
    pub packets: u64,
    /// The rule the count came from, quoted so a verdict can show its working.
    pub rule: String,
}

/// Needs root; `-x` so the counts are exact rather than `1234K`.
pub fn port_traffic_command() -> String {
    "iptables -t nat -nvxL 2>&1".to_string()
}

/// Sum the DNAT counters for one published port.
pub fn parse_port_traffic(output: &str, port: u16, protocol: &str) -> Option<PortTraffic> {
    let want = format!("dpt:{port}");
    let mut packets = 0u64;
    let mut rule = String::new();
    let mut found = false;
    for line in output.lines() {
        if !line.contains("DNAT") || !line.contains(&want) {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 || !fields[3].eq_ignore_ascii_case(protocol) {
            continue;
        }
        let Ok(n) = fields[0].parse::<u64>() else {
            continue;
        };
        packets += n;
        if rule.is_empty() {
            rule = line.trim().to_string();
        }
        found = true;
    }
    if found {
        Some(PortTraffic {
            port,
            protocol: protocol.to_string(),
            packets,
            rule,
        })
    } else {
        None
    }
}

/// A handshake older than this is stale: the protocol renegotiates every two
/// minutes by default and `PersistentKeepalive` is normally 25 seconds, so five
/// minutes of silence is not a slow client.
pub const STALE_HANDSHAKE_SECS: u64 = 300;

/// Everything [`diagnose`] is allowed to reason from.
#[derive(Debug, Clone)]
pub struct Evidence {
    pub container: Container,
    pub inspect: Option<Inspect>,
    pub health: Option<Health>,
    /// Already redacted — see [`super::logs::logs`].
    pub logs: Option<String>,
    /// `net.ipv4.ip_forward` on the host itself.
    pub host_ip_forward: Option<bool>,
    pub port_traffic: Option<PortTraffic>,
    pub obfuscation: Option<ObfuscationComparison>,
    /// Filled in as probes fail; carried straight into the diagnosis.
    pub blind_spots: Vec<String>,
}

impl Evidence {
    pub fn new(container: Container) -> Self {
        Self {
            container,
            inspect: None,
            health: None,
            logs: None,
            host_ip_forward: None,
            port_traffic: None,
            obfuscation: None,
            blind_spots: Vec::new(),
        }
    }

    /// The `ListenPort` the mounted config declared, as the entrypoint recorded
    /// it in its `iface-up` event.
    ///
    /// This matters because a *client* node has no `ListenPort` and the daemon
    /// picks an ephemeral one anyway — so the port UAPI reports is not evidence
    /// of anything on its own. `Some(None)` means the config declared none;
    /// `None` means the log did not say.
    pub fn declared_listen_port(&self) -> Option<Option<u16>> {
        let line = self
            .logs
            .as_ref()?
            .lines()
            .rev()
            .find(|l| l.contains("event=iface-up"))?;
        let value = line
            .split_whitespace()
            .find_map(|t| t.strip_prefix("port="))?;
        Some(if value == "none" {
            None
        } else {
            value.parse().ok()
        })
    }

    /// Is this a server rather than a client node?
    ///
    /// A config that declared no `ListenPort` settles it outright. Otherwise a
    /// published UDP port or a listening daemon says so.
    pub fn is_server(&self) -> bool {
        if self.declared_listen_port() == Some(None) {
            return false;
        }
        self.health
            .as_ref()
            .and_then(|h| h.device.listen_port)
            .is_some()
            || self.container.udp_port().is_some()
    }
}

/// One fault rule: evidence in, at most one finding out, and whatever it could
/// not observe appended to the blind-spot list.
pub type Rule = fn(&Evidence, &mut Vec<String>) -> Option<Finding>;

/// Work out what is wrong, from evidence only.
pub fn diagnose(ev: &Evidence) -> Diagnosis {
    let mut findings = Vec::new();
    let mut blind = ev.blind_spots.clone();

    let rules: [Rule; 9] = [
        faults::container_state,
        faults::tun_device,
        faults::net_admin,
        faults::ip_forward,
        faults::published_port,
        tunnel::interface_configured,
        tunnel::peers_never_handshaked,
        tunnel::stale_peers,
        tunnel::obfuscation,
    ];
    for rule in rules {
        if let Some(f) = rule(ev, &mut blind) {
            findings.push(f);
        }
    }

    Diagnosis {
        container: ev.container.name.clone(),
        healthy: findings.is_empty() && blind.is_empty(),
        findings,
        blind_spots: blind,
    }
}

/// Collect everything and return a verdict.
///
/// `client_conf` is optional; without it the obfuscation blocks of the two ends
/// cannot be compared, and the diagnosis says so rather than guessing.
pub fn diagnose_container(
    host: &Host,
    container: &Container,
    client_conf: Option<&str>,
) -> Result<Diagnosis> {
    let mut ev = Evidence::new(container.clone());

    match super::inspect::inspect(host, &container.name) {
        Ok(i) => ev.inspect = Some(i),
        Err(e) => ev.blind_spots.push(format!("docker inspect failed: {e}")),
    }
    let interface = ev
        .inspect
        .as_ref()
        .map(Inspect::interface)
        .unwrap_or_else(|| "awg0".to_string());

    if container.state.is_running() {
        match super::health::health(host, &container.name, &interface) {
            Ok(h) => ev.health = Some(h),
            Err(e) => ev
                .blind_spots
                .push(format!("the in-container probe failed: {e}")),
        }
    }

    match super::logs::logs(host, &container.name, 200) {
        Ok(l) => ev.logs = Some(l),
        Err(e) => ev.blind_spots.push(format!("docker logs failed: {e}")),
    }

    if let Ok((out, _, 0)) = host.run("cat /proc/sys/net/ipv4/ip_forward 2>/dev/null") {
        ev.host_ip_forward = match out.trim() {
            "1" => Some(true),
            "0" => Some(false),
            _ => None,
        };
    }

    if let Some(port) = container.udp_port() {
        match host.run_root(&port_traffic_command()) {
            Ok((out, _, 0)) => ev.port_traffic = parse_port_traffic(&out, port, "udp"),
            _ => ev
                .blind_spots
                .push("could not read the nat table (needs root)".to_string()),
        }
    }

    if let (Some(conf), Some(h)) = (client_conf, ev.health.as_ref()) {
        ev.obfuscation = Some(compare_obfuscation(
            &obfuscation_from_uapi(&h.device),
            &obfuscation_from_conf(conf),
        ));
    }

    // The logs are already redacted; this is belt and braces at the one place a
    // verdict could otherwise quote something it should not.
    if let Some(l) = &ev.logs {
        ev.logs = Some(redact(l));
    }

    Ok(diagnose(&ev))
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use crate::docker::discover::{ContainerState, PublishedPort};
    use crate::docker::image::{Generation, parse_image_ref};
    use crate::versions::AwgVersion;

    /// `iptables -t nat -nvxL` on a host publishing one UDP and one TCP port.
    pub(crate) const NAT: &str = "\
Chain PREROUTING (policy ACCEPT 12 packets, 900 bytes)
    pkts      bytes target     prot opt in     out     source               destination
      12      900 DOCKER     0    --  *      *       0.0.0.0/0            0.0.0.0/0            ADDRTYPE match dst-type LOCAL

Chain DOCKER (2 references)
    pkts      bytes target     prot opt in     out     source               destination
       7      588 DNAT       udp  --  !br-9a *       0.0.0.0/0            0.0.0.0/0            udp dpt:51820 to:172.31.99.10:51820
       0        0 DNAT       tcp  --  !br-9a *       0.0.0.0/0            0.0.0.0/0            tcp dpt:80 to:172.31.99.20:80
";

    pub(crate) fn container(state: ContainerState, port: Option<u16>) -> Container {
        Container {
            id: "aa11".into(),
            name: "awg-server".into(),
            image: "vaiprog/amnezia-wg-3:latest".into(),
            image_ref: parse_image_ref("vaiprog/amnezia-wg-3:latest"),
            generation: Some(Generation::Awg(AwgVersion::V3_0)),
            state,
            status: "Up 5 minutes".into(),
            uptime: Some("5 minutes".into()),
            created_at: "2026-07-28 21:00:00 +0300 MSK".into(),
            ports: port
                .map(|p| {
                    vec![PublishedPort {
                        host_ip: Some("0.0.0.0".into()),
                        host_port: Some(p),
                        container_port: p,
                        protocol: "udp".into(),
                    }]
                })
                .unwrap_or_default(),
            ours: true,
        }
    }

    pub(crate) fn inspect(cap_add: &[&str], devices: &[&str], sysctl: Option<&str>) -> Inspect {
        Inspect {
            name: "awg-server".into(),
            running: true,
            cap_add: cap_add.iter().map(|s| (*s).to_string()).collect(),
            devices: devices.iter().map(|s| (*s).to_string()).collect(),
            sysctls: sysctl
                .map(|v| {
                    [("net.ipv4.ip_forward".to_string(), v.to_string())]
                        .into_iter()
                        .collect()
                })
                .unwrap_or_default(),
            env: [("AWG_IFACE".to_string(), "awg0".to_string())]
                .into_iter()
                .collect(),
            ..Default::default()
        }
    }

    /// A container with every privilege it needs, probed and found healthy.
    pub(crate) fn healthy() -> Evidence {
        use crate::docker::health::{fixtures::PROBE, parse_health};
        let mut ev = Evidence::new(container(ContainerState::Running, Some(51820)));
        ev.inspect = Some(inspect(
            &["NET_ADMIN"],
            &["/dev/net/tun:/dev/net/tun"],
            Some("1"),
        ));
        ev.health = Some(parse_health("awg-server", "awg0", PROBE));
        // Real tail of `docker logs` on a server that came up cleanly.
        ev.logs = Some(
            ">> configuration accepted by amneziawg-go (31 UAPI lines, errno=0)\n\
             2026-07-28T19:31:21Z iface=awg0 event=config-applied errno=0 uapi_lines=31 peers=1 port=51820\n\
             >> NAT enabled, egress via eth0 (and any other non-tunnel link)\n\
             >> awg0 is up\n\
             2026-07-28T19:31:21Z iface=awg0 event=iface-up addr=10.8.1.1/24 mtu=1280 port=51820 nat=1 full_tunnel=0\n"
                .to_string(),
        );
        ev.port_traffic = parse_port_traffic(NAT, 51820, "udp");
        ev.obfuscation = Some(ObfuscationComparison::default());
        ev
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{NAT, container, healthy};
    use super::*;
    use crate::docker::discover::ContainerState;

    #[test]
    fn dnat_counters_are_read_per_port_and_per_protocol() {
        let t = parse_port_traffic(NAT, 51820, "udp").unwrap();
        assert_eq!(t.packets, 7);
        assert_eq!(t.port, 51820);
        assert!(t.rule.contains("dpt:51820"));

        assert_eq!(parse_port_traffic(NAT, 80, "tcp").unwrap().packets, 0);
        // Right port, wrong protocol: the rule that carries a tunnel is the udp
        // one, and counting the tcp rule would answer a different question.
        assert!(parse_port_traffic(NAT, 51820, "tcp").is_none());
        assert!(parse_port_traffic(NAT, 9999, "udp").is_none());
        assert!(parse_port_traffic("", 51820, "udp").is_none());
    }

    #[test]
    fn a_healthy_deployment_produces_no_findings_at_all() {
        let d = diagnose(&healthy());
        assert!(d.findings.is_empty(), "{:#?}", d.findings);
        assert!(d.blind_spots.is_empty(), "{:?}", d.blind_spots);
        assert!(d.healthy);
        assert_eq!(d.worst(), None);
        assert_eq!(d.container, "awg-server");
    }

    #[test]
    fn a_host_that_could_not_be_probed_is_never_reported_as_healthy() {
        let ev = Evidence::new(container(ContainerState::Running, Some(51820)));
        let d = diagnose(&ev);
        assert!(d.findings.is_empty(), "nothing was observed to be wrong");
        assert!(!d.healthy, "and nothing was observed to be right either");
        assert!(!d.blind_spots.is_empty());
    }

    #[test]
    fn a_blind_spot_recorded_during_collection_survives_into_the_verdict() {
        let mut ev = healthy();
        ev.blind_spots.push("docker inspect failed: nope".into());
        let d = diagnose(&ev);
        assert!(!d.healthy);
        assert_eq!(d.blind_spots.len(), 1);
    }

    #[test]
    fn the_worst_finding_is_the_most_firmly_evidenced_one() {
        let mut ev = healthy();
        ev.container.state = ContainerState::Exited;
        let d = diagnose(&ev);
        assert_eq!(d.worst().map(|f| f.confidence), Some(Confidence::Confirmed));
        assert!(d.has(FaultKind::ContainerNotRunning));
        assert!(Confidence::Confirmed > Confidence::Likely);
        assert!(Confidence::Likely > Confidence::Possible);
    }
}
