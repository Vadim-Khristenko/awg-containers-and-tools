//! Faults in the tunnel rather than in the container.
//!
//! The container is running and has what it needs; the question here is whether
//! the protocol is actually working. Interface configured, peers handshaking,
//! and the two ends agreeing on the shared obfuscation block.
//!
//! [`peers_never_handshaked`] is the rule that matters most and the one that
//! most often refuses to answer. From the server side, "the client never sent
//! anything" and "the client sent something that was rejected" look identical
//! unless the DNAT packet counters can be read. So it does not choose between
//! them: it reports what it saw and lists what that cannot rule out.

use super::diagnose::{Confidence, Evidence, FaultKind, Finding, STALE_HANDSHAKE_SECS};
use super::faults::log_has;
use super::health::UapiPeer;

pub(super) fn interface_configured(ev: &Evidence, blind: &mut Vec<String>) -> Option<Finding> {
    if !ev.container.state.is_running() {
        return None;
    }
    let Some(h) = &ev.health else {
        blind.push(
            "the in-container probe did not run, so the interface, the UAPI socket and the peers \
             were not checked"
                .to_string(),
        );
        return None;
    };
    if h.interface_up && h.uapi_ok {
        return None;
    }

    let rejected = log_has(
        ev,
        &["daemon rejected the configuration", "config-rejected"],
    );
    let mut evidence = vec![format!(
        "`ip -o link show {}` inside the container: {}",
        h.interface,
        if h.interface_output.trim().is_empty() {
            "(no output)"
        } else {
            h.interface_output.trim()
        }
    )];
    if !h.uapi_ok {
        evidence.push(format!(
            "the UAPI socket did not answer: {}",
            h.uapi_error.clone().unwrap_or_default().trim()
        ));
    } else if !h.device.has_private_key {
        evidence.push(
            "the device answers but has no private key, so `set=1` never reached it".to_string(),
        );
    }
    if let Some(l) = &rejected {
        evidence.push(format!("container log: {l}"));
    }

    Some(Finding {
        kind: FaultKind::InterfaceNeverConfigured,
        confidence: Confidence::Confirmed,
        what: format!(
            "{} is up but {} was never brought into service",
            ev.container.name, h.interface
        ),
        evidence,
        next_step: if rejected.is_some() {
            "the daemon refused the config — read the errno in `docker logs` and check the \
             parameter that follows it"
                .to_string()
        } else {
            format!(
                "read `docker logs {}` from the start; the entrypoint prints `!!` on every fatal \
                 step",
                ev.container.name
            )
        },
        alternatives: Vec::new(),
    })
}

/// Has anything at all arrived in this container's network namespace?
///
/// `/proc/net/snmp` is the authority: it counts datagrams actually delivered in
/// the namespace. The DNAT packet counters look like they should answer the same
/// question and do not — with docker's userland proxying on, which is the
/// default, traffic to a published port is forwarded by `docker-proxy` and never
/// traverses the DNAT rule, so the rule's counter sits at zero while packets are
/// arriving. Verified against docker 29.6.1. They are therefore used as positive
/// corroboration only, never to conclude that nothing arrived.
fn traffic_arrived(ev: &Evidence) -> (Option<bool>, Vec<String>) {
    let mut evidence = Vec::new();
    let mut arrived = None;

    if let Some(t) = &ev.port_traffic
        && t.packets > 0
    {
        arrived = Some(true);
        evidence.push(format!(
            "{} packet(s) have hit the DNAT rule for UDP {}: {}",
            t.packets, t.port, t.rule
        ));
    }

    match ev.health.as_ref().and_then(|h| h.udp) {
        Some(u) if u.in_datagrams > 0 => {
            arrived = Some(true);
            evidence.push(format!(
                "/proc/net/snmp inside the container: {} UDP datagram(s) delivered in this \
                 namespace (NoPorts {}, InErrors {})",
                u.in_datagrams, u.no_ports, u.in_errors
            ));
        }
        Some(_) if arrived.is_none() => {
            arrived = Some(false);
            evidence.push(
                "/proc/net/snmp inside the container: no UDP datagram has ever been delivered in \
                 this namespace"
                    .to_string(),
            );
        }
        _ => {}
    }
    (arrived, evidence)
}

pub(super) fn peers_never_handshaked(ev: &Evidence, blind: &mut Vec<String>) -> Option<Finding> {
    let h = ev.health.as_ref()?;
    let never: Vec<&UapiPeer> = h
        .device
        .peers
        .iter()
        .filter(|p| !p.ever_handshaked())
        .collect();
    if never.is_empty() {
        return None;
    }

    let mut evidence = Vec::new();
    let (confidence, mut alternatives) = if h.peers_ever_handshaked() > 0 {
        // The counters are per-namespace, not per-peer. With another peer live
        // on the same device, everything that arrives is explained by that peer
        // and says nothing whatever about the silent one.
        evidence.push(format!(
            "{} other peer(s) on this device are handshaking, so no traffic counter here can be \
             attributed to the silent one",
            h.peers_ever_handshaked()
        ));
        (
            Confidence::Possible,
            vec![
                "the silent client has never tried to connect".to_string(),
                "a firewall between that client and this host drops the UDP port".to_string(),
                "that client's obfuscation block or its keys differ from the server's".to_string(),
            ],
        )
    } else {
        let (arrived, lines) = traffic_arrived(ev);
        evidence.extend(lines);
        match arrived {
            Some(true) => (
                Confidence::Confirmed,
                vec![
                    "the two ends disagree on the obfuscation block".to_string(),
                    "the client has the wrong server public key, or the preshared keys differ"
                        .to_string(),
                    "the arriving datagrams are something else entirely — a resolver on a side \
                     network, say — and no handshake has been attempted"
                        .to_string(),
                ],
            ),
            Some(false) => (
                Confidence::Likely,
                vec![
                    "the client has never tried to connect".to_string(),
                    "a firewall or NAT in front of this host drops the UDP port".to_string(),
                    "the client config carries the wrong Endpoint".to_string(),
                ],
            ),
            None => {
                blind.push(
                    "neither the namespace's UDP counters nor the DNAT counters could be read, so \
                     'nothing arrives' and 'arrives and is rejected' cannot be told apart"
                        .to_string(),
                );
                (
                    Confidence::Possible,
                    vec![
                        "nothing is arriving on the published port — blocked upstream, or the \
                         client never tried"
                            .to_string(),
                        "packets arrive and are rejected — an obfuscation or key mismatch"
                            .to_string(),
                    ],
                )
            }
        }
    };

    for p in &never {
        evidence.push(format!(
            "peer {} ({}) has last_handshake_time_sec=0, rx={} tx={}",
            p.public_key,
            p.allowed_ips.join(","),
            p.rx_bytes,
            p.tx_bytes
        ));
    }
    // A clean obfuscation comparison removes one of the remaining causes.
    if let Some(c) = &ev.obfuscation
        && c.is_identical()
    {
        alternatives.retain(|a| !a.contains("obfuscation"));
        evidence.push(
            "the client config supplied carries the same obfuscation block as the live device"
                .to_string(),
        );
    }

    Some(Finding {
        // More than one cause still standing is not a diagnosis, and saying so
        // is more useful than picking the likelier one.
        kind: if alternatives.len() > 1 {
            FaultKind::Undetermined
        } else {
            FaultKind::PeerNeverHandshaked
        },
        confidence,
        what: format!(
            "{} peer(s) are configured on the device and have never completed a handshake",
            never.len()
        ),
        evidence,
        next_step: "run this diagnosis again with the client's .conf so the obfuscation blocks \
                    can be compared, and check the endpoint from the client's network with \
                    `nc -u -z <host> <port>`"
            .to_string(),
        alternatives,
    })
}

pub(super) fn stale_peers(ev: &Evidence, _blind: &mut Vec<String>) -> Option<Finding> {
    let h = ev.health.as_ref()?;
    let now = h.now_secs?;
    let stale: Vec<String> = h
        .device
        .peers
        .iter()
        .filter_map(|p| {
            p.handshake_age(now)
                .filter(|a| *a > STALE_HANDSHAKE_SECS)
                .map(|a| format!("peer {} last handshook {a}s ago", p.public_key))
        })
        .collect();
    if stale.is_empty() {
        return None;
    }
    Some(Finding {
        kind: FaultKind::PeerStale,
        confidence: Confidence::Confirmed,
        what: format!(
            "{} peer(s) handshook once but not in the last {STALE_HANDSHAKE_SECS}s",
            stale.len()
        ),
        evidence: stale,
        next_step: "normal for a client that is simply offline; if it is meant to be connected, \
                    check its PersistentKeepalive and whether its NAT mapping expired"
            .to_string(),
        alternatives: vec!["the client is switched off or asleep".to_string()],
    })
}

pub(super) fn obfuscation(ev: &Evidence, blind: &mut Vec<String>) -> Option<Finding> {
    let Some(c) = &ev.obfuscation else {
        blind.push(
            "no client config was supplied, so the two ends' obfuscation blocks were not compared"
                .to_string(),
        );
        return None;
    };
    if !c.mismatches.is_empty() {
        return Some(Finding {
            kind: FaultKind::ObfuscationMismatch,
            confidence: Confidence::Confirmed,
            what: format!(
                "the client config and the live device disagree on {} obfuscation field(s); both \
                 ends must present identical parameters or the handshake never completes",
                c.mismatches.len()
            ),
            evidence: c
                .mismatches
                .iter()
                .map(|m| format!("{}: server {} vs client {}", m.field, m.server, m.client))
                .collect(),
            next_step: "reissue the client config from this server \
                        (`docker exec <container> awg-peer add <label>`), which copies the \
                        server's block verbatim"
                .to_string(),
            alternatives: Vec::new(),
        });
    }
    if !c.server_only.is_empty() || !c.client_only.is_empty() {
        return Some(Finding {
            kind: FaultKind::ObfuscationMismatch,
            confidence: Confidence::Likely,
            what: "an obfuscation field is set on one end and absent on the other".to_string(),
            evidence: vec![
                format!("only on the server: {:?}", c.server_only),
                format!("only in the client config: {:?}", c.client_only),
            ],
            next_step: "reissue the client config from this server so the two blocks match"
                .to_string(),
            alternatives: vec![
                "a field the running daemon does not echo back over UAPI, which is not the same \
                 as one it does not have"
                    .to_string(),
            ],
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::super::diagnose::PortTraffic;
    use super::super::diagnose::diagnose;
    use super::super::diagnose::fixtures::healthy;
    use super::super::discover::ContainerState;
    use super::super::health::fixtures::{LINK_UP, PROBE, UAPI};
    use super::super::health::{parse_health, parse_uapi_get};
    use super::super::obfuscation::fixtures::CLIENT_CONF;
    use super::super::obfuscation::{
        compare_obfuscation, obfuscation_from_conf, obfuscation_from_uapi,
    };
    use super::*;

    /// The device's only peer has never handshaked.
    fn dead_peer_probe() -> String {
        PROBE.replace(
            "last_handshake_time_sec=1770000000",
            "last_handshake_time_sec=0",
        )
    }

    /// ...and nothing has ever arrived in the namespace either.
    fn silent_probe() -> String {
        dead_peer_probe().replace("Udp: 102 0", "Udp: 0 0")
    }

    fn traffic(packets: u64) -> Option<PortTraffic> {
        Some(PortTraffic {
            port: 51820,
            protocol: "udp".into(),
            packets,
            rule: format!("{packets} 0 DNAT udp -- ... udp dpt:51820"),
        })
    }

    fn comparison(client: &str) -> super::super::obfuscation::ObfuscationComparison {
        compare_obfuscation(
            &obfuscation_from_uapi(&parse_uapi_get(UAPI)),
            &obfuscation_from_conf(client),
        )
    }

    #[test]
    fn nothing_ever_delivered_in_the_namespace_points_at_reachability() {
        let mut ev = healthy();
        ev.health = Some(parse_health("awg-server", "awg0", &silent_probe()));
        ev.port_traffic = traffic(0);
        ev.obfuscation = None;

        let f = peers_never_handshaked(&ev, &mut Vec::new()).unwrap();
        assert!(
            f.evidence
                .iter()
                .any(|e| e.contains("no UDP datagram has ever been delivered"))
        );
        assert!(
            f.evidence
                .iter()
                .any(|e| e.contains("last_handshake_time_sec=0"))
        );
        // Three causes remain open, and the verdict says so instead of picking.
        assert_eq!(f.kind, FaultKind::Undetermined);
        assert_eq!(f.confidence, Confidence::Likely);
        assert_eq!(f.alternatives.len(), 3);
    }

    #[test]
    fn a_zero_dnat_counter_is_never_read_as_nothing_arriving() {
        // docker-proxy forwards to a published port without the packets ever
        // traversing the DNAT rule, so a zero there means nothing at all. On its
        // own it must leave the question open rather than answer it.
        let mut ev = healthy();
        let no_udp = dead_peer_probe().replace("@@awg-probe:udp", "@@awg-probe:udp-unavailable");
        ev.health = Some(parse_health("awg-server", "awg0", &no_udp));
        ev.port_traffic = traffic(0);
        ev.obfuscation = None;

        let mut blind = Vec::new();
        let f = peers_never_handshaked(&ev, &mut blind).unwrap();
        assert_eq!(f.confidence, Confidence::Possible);
        assert!(!f.evidence.iter().any(|e| e.contains("DNAT")));
        assert!(blind.iter().any(|b| b.contains("cannot be told apart")));
    }

    #[test]
    fn datagrams_arriving_and_no_handshake_narrows_it_to_the_shared_secrets() {
        let mut ev = healthy();
        // 102 datagrams delivered, and still not one handshake.
        ev.health = Some(parse_health("awg-server", "awg0", &dead_peer_probe()));
        ev.port_traffic = None;
        ev.obfuscation = None;

        let f = peers_never_handshaked(&ev, &mut Vec::new()).unwrap();
        assert_eq!(f.confidence, Confidence::Confirmed);
        assert!(
            f.evidence
                .iter()
                .any(|e| e.contains("102 UDP datagram(s) delivered"))
        );
        assert_eq!(f.kind, FaultKind::Undetermined);
        assert_eq!(f.alternatives.len(), 3);
    }

    #[test]
    fn a_matching_client_config_removes_the_obfuscation_cause() {
        let mut ev = healthy();
        ev.health = Some(parse_health("awg-server", "awg0", &dead_peer_probe()));
        ev.port_traffic = traffic(42);
        ev.obfuscation = Some(comparison(CLIENT_CONF));

        let f = peers_never_handshaked(&ev, &mut Vec::new()).unwrap();
        assert!(f.evidence.iter().any(|e| e.contains("42 packet(s)")));
        assert_eq!(f.alternatives.len(), 2, "obfuscation is ruled out");
        assert!(!f.alternatives.iter().any(|a| a.contains("obfuscation")));
    }

    #[test]
    fn a_live_peer_alongside_a_silent_one_makes_the_counters_say_nothing() {
        // The counters are per-namespace. One peer working is a complete
        // explanation for everything that arrives, so it is not evidence about
        // the other — and claiming otherwise would be the whole failure mode
        // this module exists to avoid.
        let two_peers = PROBE.replace(
            "@@awg-probe:end",
            "public_key=aa3b5f4e5e8c1e63e7e0b4a02f5b7b8a4d16e7a5c3d2b1a0918273645564738a\n\
             allowed_ip=10.8.1.3/32\nlast_handshake_time_sec=0\nrx_bytes=0\ntx_bytes=0\n\
             @@awg-probe:end",
        );
        let mut ev = healthy();
        ev.health = Some(parse_health("awg-server", "awg0", &two_peers));
        ev.port_traffic = traffic(4000);
        ev.obfuscation = None;

        let f = peers_never_handshaked(&ev, &mut Vec::new()).unwrap();
        assert_eq!(f.confidence, Confidence::Possible);
        assert!(
            f.evidence
                .iter()
                .any(|e| e.contains("other peer(s) on this device are handshaking"))
        );
        assert!(!f.evidence.iter().any(|e| e.contains("4000 packet(s)")));
        assert_eq!(f.alternatives.len(), 3);
    }

    #[test]
    fn a_peer_that_stopped_handshaking_is_told_from_one_that_never_started() {
        let mut ev = healthy();
        // Same peer, one hour of silence rather than none at all.
        ev.health = Some(parse_health(
            "awg-server",
            "awg0",
            &PROBE.replace(
                "@@awg-probe:epoch\n1770000300",
                "@@awg-probe:epoch\n1770003700",
            ),
        ));
        let f = stale_peers(&ev, &mut Vec::new()).unwrap();
        assert_eq!(f.kind, FaultKind::PeerStale);
        assert!(f.evidence[0].contains("3700s ago"));
        assert!(peers_never_handshaked(&ev, &mut Vec::new()).is_none());
    }

    #[test]
    fn a_mismatched_obfuscation_block_is_reported_field_by_field() {
        let mut ev = healthy();
        ev.obfuscation = Some(comparison(&CLIENT_CONF.replace("S3 = 25", "S3 = 26")));
        let f = obfuscation(&ev, &mut Vec::new()).unwrap();
        assert_eq!(f.confidence, Confidence::Confirmed);
        assert!(f.evidence.iter().any(|e| e == "s3: server 25 vs client 26"));
        assert!(f.next_step.contains("awg-peer add"));
    }

    #[test]
    fn a_field_on_one_side_only_is_likely_rather_than_confirmed() {
        let mut ev = healthy();
        ev.obfuscation = Some(comparison(&CLIENT_CONF.replace("S4 = 32\n", "")));
        let f = obfuscation(&ev, &mut Vec::new()).unwrap();
        assert_eq!(f.confidence, Confidence::Likely);
        assert_eq!(f.alternatives.len(), 1, "the daemon may simply not echo it");
    }

    #[test]
    fn no_client_config_is_a_blind_spot_and_not_a_pass() {
        let mut ev = healthy();
        ev.obfuscation = None;
        let mut blind = Vec::new();
        assert!(obfuscation(&ev, &mut blind).is_none());
        assert!(blind[0].contains("not compared"));
    }

    #[test]
    fn a_container_that_is_up_with_no_interface_is_told_from_one_that_is_down() {
        let mut ev = healthy();
        ev.health = Some(parse_health(
            "awg-server",
            "awg0",
            &PROBE.replace(LINK_UP, "Device \"awg0\" does not exist."),
        ));
        ev.logs = Some(">> daemon rejected the configuration:\nerrno=-22\n".into());
        let d = diagnose(&ev);
        assert!(d.has(FaultKind::InterfaceNeverConfigured));
        assert!(!d.has(FaultKind::ContainerNotRunning));
        let f = d
            .findings
            .iter()
            .find(|f| f.kind == FaultKind::InterfaceNeverConfigured)
            .unwrap();
        assert!(f.next_step.contains("errno"));

        let mut ev = healthy();
        ev.container.state = ContainerState::Exited;
        ev.health = None;
        let d = diagnose(&ev);
        assert!(d.has(FaultKind::ContainerNotRunning));
        assert!(
            !d.has(FaultKind::InterfaceNeverConfigured),
            "a stopped container has no interface to have configured"
        );
    }
}
