//! Faults in how the container itself was started.
//!
//! These are the ones that stop the node before it ever gets to the protocol:
//! it is not running, it has no tun device, it was not given `NET_ADMIN`,
//! forwarding is off, the port is not published. The tunnel-side rules —
//! interfaces, peers, obfuscation — are in [`super::tunnel`].
//!
//! Every rule is a [`super::diagnose::Rule`]: evidence in, at most one
//! [`Finding`] out, and whatever it could not observe appended to the
//! blind-spot list. Keeping them separate is what makes "this evidence supports
//! this verdict" checkable one rule at a time.

use super::diagnose::{Confidence, Evidence, FaultKind, Finding};
use super::inspect::Inspect;

/// The first log line matching any of `needles`, case-insensitively.
pub(super) fn log_has(ev: &Evidence, needles: &[&str]) -> Option<String> {
    ev.logs.as_ref()?.lines().find_map(|l| {
        let lower = l.to_ascii_lowercase();
        needles
            .iter()
            .any(|n| lower.contains(n))
            .then(|| l.trim().to_string())
    })
}

pub(super) fn container_state(ev: &Evidence, _blind: &mut Vec<String>) -> Option<Finding> {
    if ev.container.state.is_running() {
        return None;
    }
    let mut evidence = vec![format!(
        "`docker ps` reports {} in state {} ({})",
        ev.container.name,
        ev.container.state.as_str(),
        ev.container.status
    )];
    if let Some(i) = &ev.inspect {
        evidence.push(format!(
            "exit code {}, restarted {} time(s), OOM-killed: {}",
            i.exit_code, i.restart_count, i.oom_killed
        ));
    }
    Some(Finding {
        kind: FaultKind::ContainerNotRunning,
        confidence: Confidence::Confirmed,
        what: format!("{} is not running", ev.container.name),
        evidence,
        next_step: format!(
            "read `docker logs {0}` for why it stopped, then `docker start {0}`",
            ev.container.name
        ),
        alternatives: Vec::new(),
    })
}

pub(super) fn tun_device(ev: &Evidence, _blind: &mut Vec<String>) -> Option<Finding> {
    let in_container = ev.health.as_ref().and_then(|h| h.tun_present);
    let in_config = ev.inspect.as_ref().map(Inspect::has_tun_device);
    if in_container != Some(false) && in_config != Some(false) {
        return None;
    }

    let mut evidence = Vec::new();
    if in_container == Some(false) {
        evidence.push(format!(
            "`test -c /dev/net/tun` inside {} says the device is not there",
            ev.container.name
        ));
    }
    if in_config == Some(false) {
        evidence.push(
            "`docker inspect` shows no `--device /dev/net/tun` and the container is not privileged"
                .to_string(),
        );
    }
    if let Some(l) = log_has(
        ev,
        &["/dev/net/tun", "failed to create tun", "cannot open tun"],
    ) {
        evidence.push(format!("container log: {l}"));
    }

    Some(Finding {
        kind: FaultKind::NoTunDevice,
        // The device being absent *inside* the container is the observation
        // with no other explanation; a missing `--device` flag alone could in
        // principle be made up for by a bind mount.
        confidence: if in_container == Some(false) {
            Confidence::Confirmed
        } else {
            Confidence::Likely
        },
        what: "the container has no /dev/net/tun, so amneziawg-go cannot create an interface"
            .to_string(),
        evidence,
        next_step: "recreate the container with `--device /dev/net/tun` (compose: \
                    `devices: [\"/dev/net/tun:/dev/net/tun\"]`); if the host has no tun module \
                    either, `modprobe tun` first"
            .to_string(),
        alternatives: Vec::new(),
    })
}

pub(super) fn net_admin(ev: &Evidence, _blind: &mut Vec<String>) -> Option<Finding> {
    let has = ev.inspect.as_ref().map(Inspect::has_net_admin);
    let refused = log_has(
        ev,
        &[
            "operation not permitted",
            "permission denied",
            "rtnetlink answers",
        ],
    );

    if has == Some(false) {
        let iface_down = ev.health.as_ref().is_some_and(|h| !h.interface_up);
        let mut evidence = vec![format!(
            "`docker inspect` HostConfig.CapAdd is {:?} — no NET_ADMIN, and Privileged is false",
            ev.inspect
                .as_ref()
                .map(|i| i.cap_add.clone())
                .unwrap_or_default()
        )];
        if let Some(l) = &refused {
            evidence.push(format!("container log: {l}"));
        }
        if iface_down {
            evidence.push(format!(
                "the {} interface is not up inside the container",
                ev.health
                    .as_ref()
                    .map(|h| h.interface.as_str())
                    .unwrap_or("")
            ));
        }
        return Some(Finding {
            kind: FaultKind::MissingNetAdmin,
            // A missing capability plus something that actually failed is
            // conclusive; a missing capability with everything working is not.
            confidence: if refused.is_some() || iface_down {
                Confidence::Confirmed
            } else {
                Confidence::Likely
            },
            what: "the container was started without NET_ADMIN, so it cannot bring an interface \
                   up, add addresses or write firewall rules"
                .to_string(),
            evidence,
            next_step: "recreate the container with `--cap-add NET_ADMIN` (compose: \
                        `cap_add: [NET_ADMIN]`). `--privileged` also works and is not needed."
                .to_string(),
            alternatives: Vec::new(),
        });
    }

    // No inspect to check, but something was refused a privileged operation.
    if has.is_none() && refused.is_some() {
        return Some(Finding {
            kind: FaultKind::MissingNetAdmin,
            confidence: Confidence::Possible,
            what: "something inside the container was refused a privileged network operation"
                .to_string(),
            evidence: vec![format!("container log: {}", refused.unwrap_or_default())],
            next_step:
                "run `docker inspect` on the container and check HostConfig.CapAdd for NET_ADMIN"
                    .to_string(),
            alternatives: vec![
                "a seccomp or AppArmor profile refusing the same call".to_string(),
                "a read-only /proc/sys, which is normal and is what --sysctl is for".to_string(),
            ],
        });
    }
    None
}

pub(super) fn ip_forward(ev: &Evidence, blind: &mut Vec<String>) -> Option<Finding> {
    if !ev.is_server() {
        return None;
    }
    match ev.health.as_ref().and_then(|h| h.ip_forward) {
        Some(true) => None,
        None => {
            if ev.health.is_some() {
                blind.push(
                    "could not read /proc/sys/net/ipv4/ip_forward inside the container".to_string(),
                );
            }
            None
        }
        Some(false) => {
            let mut evidence = vec![format!(
                "`cat /proc/sys/net/ipv4/ip_forward` inside {} reads 0",
                ev.container.name
            )];
            if let Some(i) = &ev.inspect
                && i.ip_forward_sysctl().is_none()
            {
                evidence.push(
                    "`docker inspect` HostConfig.Sysctls carries no net.ipv4.ip_forward"
                        .to_string(),
                );
            }
            if ev.host_ip_forward == Some(false) {
                evidence.push("the host's own net.ipv4.ip_forward is 0 as well".to_string());
            }
            Some(Finding {
                kind: FaultKind::IpForwardOff,
                confidence: Confidence::Confirmed,
                what: "IPv4 forwarding is off in the container's namespace, so tunnel traffic \
                       reaches the server and stops there"
                    .to_string(),
                evidence,
                next_step: "recreate the container with `--sysctl net.ipv4.ip_forward=1` \
                            (compose: `sysctls: {net.ipv4.ip_forward: \"1\"}`); /proc/sys is \
                            read-only inside an unprivileged container, so it cannot be set from \
                            within"
                    .to_string(),
                alternatives: Vec::new(),
            })
        }
    }
}

pub(super) fn published_port(ev: &Evidence, _blind: &mut Vec<String>) -> Option<Finding> {
    let port = ev.health.as_ref()?.device.listen_port?;
    if ev.container.udp_port().is_some() {
        return None;
    }
    // On the host network there is nothing to publish; the port is already the
    // host's.
    if ev
        .inspect
        .as_ref()
        .is_some_and(|i| i.network_mode.eq_ignore_ascii_case("host"))
    {
        return None;
    }

    // A client node declares no ListenPort and the daemon picks an ephemeral
    // one regardless, so the port UAPI reports is not by itself evidence that
    // anything was meant to be reachable.
    let mut evidence = vec![
        format!("UAPI `get=1` reports listen_port={port}"),
        format!(
            "`docker ps` port column: {:?}",
            ev.container
                .ports
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        ),
    ];
    let (confidence, alternatives) = match ev.declared_listen_port() {
        Some(None) => return None,
        Some(Some(declared)) => {
            evidence.push(format!(
                "the container log's iface-up event records port={declared}, so the mounted \
                 config asked for it"
            ));
            (Confidence::Confirmed, Vec::new())
        }
        None => (
            Confidence::Likely,
            vec![
                "this is a client node: with no ListenPort in its config the daemon picks an \
                 ephemeral port, which nothing is meant to publish"
                    .to_string(),
            ],
        ),
    };

    Some(Finding {
        kind: FaultKind::PortNotPublished,
        confidence,
        what: format!("the daemon listens on UDP {port} but nothing publishes it to the host"),
        evidence,
        next_step: format!(
            "recreate the container with `-p {port}:{port}/udp`, or put it on the host network"
        ),
        alternatives,
    })
}

#[cfg(test)]
mod tests {
    use super::super::diagnose::diagnose;
    use super::super::diagnose::fixtures::{healthy, inspect};
    use super::super::discover::ContainerState;
    use super::super::health::fixtures::{LINK_UP, PROBE};
    use super::super::health::parse_health;
    use super::*;

    #[test]
    fn a_stopped_container_is_reported_before_anything_it_might_also_be_missing() {
        let mut ev = healthy();
        ev.container.state = ContainerState::Exited;
        ev.container.status = "Exited (1) 3 minutes ago".into();
        let f = container_state(&ev, &mut Vec::new()).unwrap();
        assert_eq!(f.confidence, Confidence::Confirmed);
        assert!(f.evidence[0].contains("Exited (1)"));
        assert!(f.evidence[1].contains("restarted 0 time(s)"));
        assert!(f.next_step.contains("docker start awg-server"));
    }

    #[test]
    fn a_missing_tun_device_is_named_and_not_confused_with_a_missing_capability() {
        let mut ev = healthy();
        ev.inspect = Some(inspect(&["NET_ADMIN"], &[], Some("1")));
        ev.health = Some(parse_health(
            "awg-server",
            "awg0",
            &PROBE.replace("present", "absent"),
        ));
        ev.logs = Some("!! Failed to create TUN device: no such file or directory\n".into());

        let d = diagnose(&ev);
        assert!(d.has(FaultKind::NoTunDevice));
        assert!(!d.has(FaultKind::MissingNetAdmin));
        let f = d
            .findings
            .iter()
            .find(|f| f.kind == FaultKind::NoTunDevice)
            .unwrap();
        assert_eq!(f.confidence, Confidence::Confirmed);
        assert!(f.next_step.contains("--device /dev/net/tun"));
        assert!(
            f.evidence
                .iter()
                .any(|e| e.contains("test -c /dev/net/tun"))
        );
        assert!(
            f.evidence
                .iter()
                .any(|e| e.contains("Failed to create TUN"))
        );
    }

    #[test]
    fn a_device_missing_only_from_the_run_flags_is_likely_rather_than_confirmed() {
        let mut ev = healthy();
        // The flag is gone but the device is somehow still there — the two
        // observations disagree, so the verdict is not conclusive.
        ev.inspect = Some(inspect(&["NET_ADMIN"], &[], Some("1")));
        let f = tun_device(&ev, &mut Vec::new()).unwrap();
        assert_eq!(f.confidence, Confidence::Likely);
    }

    #[test]
    fn a_container_without_net_admin_is_named_from_the_capability_list_and_the_log() {
        let mut ev = healthy();
        ev.inspect = Some(inspect(&[], &["/dev/net/tun:/dev/net/tun"], Some("1")));
        ev.health = Some(parse_health(
            "awg-server",
            "awg0",
            &PROBE.replace(LINK_UP, "Device \"awg0\" does not exist."),
        ));
        ev.logs = Some("!! RTNETLINK answers: Operation not permitted\n".into());

        let d = diagnose(&ev);
        let f = d
            .findings
            .iter()
            .find(|f| f.kind == FaultKind::MissingNetAdmin)
            .unwrap();
        assert_eq!(f.confidence, Confidence::Confirmed);
        assert!(f.next_step.contains("--cap-add NET_ADMIN"));
        assert!(!d.has(FaultKind::NoTunDevice), "the device is present");
    }

    #[test]
    fn a_refusal_with_no_inspect_to_check_is_possible_and_lists_what_else_it_could_be() {
        let mut ev = healthy();
        ev.inspect = None;
        ev.logs = Some("!! RTNETLINK answers: Operation not permitted\n".into());
        let f = net_admin(&ev, &mut Vec::new()).unwrap();
        assert_eq!(f.confidence, Confidence::Possible);
        assert_eq!(f.alternatives.len(), 2);
    }

    #[test]
    fn a_privileged_container_is_not_reported_as_missing_a_capability() {
        let mut ev = healthy();
        let mut i = inspect(&[], &[], Some("1"));
        i.privileged = true;
        ev.inspect = Some(i);
        assert!(net_admin(&ev, &mut Vec::new()).is_none());
        assert!(tun_device(&ev, &mut Vec::new()).is_none());
    }

    #[test]
    fn forwarding_turned_off_is_read_from_proc_inside_the_container() {
        let mut ev = healthy();
        ev.inspect = Some(inspect(
            &["NET_ADMIN"],
            &["/dev/net/tun:/dev/net/tun"],
            None,
        ));
        ev.health = Some(parse_health(
            "awg-server",
            "awg0",
            &PROBE.replace("@@awg-probe:forward\n1", "@@awg-probe:forward\n0"),
        ));
        let f = ip_forward(&ev, &mut Vec::new()).unwrap();
        assert_eq!(f.confidence, Confidence::Confirmed);
        assert!(f.evidence.iter().any(|e| e.contains("reads 0")));
        assert!(f.evidence.iter().any(|e| e.contains("Sysctls carries no")));
        assert!(f.next_step.contains("--sysctl net.ipv4.ip_forward=1"));
    }

    /// The log a *client* node writes: no ListenPort in its config, so the
    /// entrypoint records `port=none` and the daemon takes an ephemeral one.
    fn client_logs() -> String {
        ">> awg0 is up\n\
         2026-07-28T19:31:21Z iface=awg0 event=iface-up addr=10.8.1.2/24 mtu=1280 port=none nat=0 full_tunnel=0\n"
            .to_string()
    }

    #[test]
    fn a_client_node_is_not_asked_about_forwarding() {
        let mut ev = healthy();
        ev.container.ports.clear();
        ev.logs = Some(client_logs());
        ev.health = Some(parse_health(
            "awg-client",
            "awg0",
            &PROBE
                .replace("listen_port=51820", "listen_port=50265")
                .replace("@@awg-probe:forward\n1", "@@awg-probe:forward\n0"),
        ));
        assert_eq!(ev.declared_listen_port(), Some(None));
        assert!(!ev.is_server());
        assert!(ip_forward(&ev, &mut Vec::new()).is_none());
    }

    #[test]
    fn a_clients_ephemeral_port_is_not_mistaken_for_an_unpublished_server_port() {
        // A client's daemon always ends up listening on *something*; that is not
        // a port anybody meant to publish, and saying so would be a false alarm
        // on every working client node.
        let mut ev = healthy();
        ev.container.ports.clear();
        ev.logs = Some(client_logs());
        ev.health = Some(parse_health(
            "awg-client",
            "awg0",
            &PROBE.replace("listen_port=51820", "listen_port=50265"),
        ));
        assert!(published_port(&ev, &mut Vec::new()).is_none());

        // With no log to read, the same shape is only *likely* a fault, and the
        // client-node reading is carried as the alternative.
        ev.logs = None;
        let f = published_port(&ev, &mut Vec::new()).unwrap();
        assert_eq!(f.confidence, Confidence::Likely);
        assert_eq!(f.alternatives.len(), 1);
        assert!(f.alternatives[0].contains("ephemeral"));
    }

    #[test]
    fn a_listening_daemon_with_no_published_port_is_a_confirmed_fault() {
        let mut ev = healthy();
        ev.container.ports.clear();
        let f = published_port(&ev, &mut Vec::new()).unwrap();
        assert_eq!(f.kind, FaultKind::PortNotPublished);
        assert_eq!(f.confidence, Confidence::Confirmed);
        assert!(f.evidence.iter().any(|e| e.contains("iface-up event")));
        assert!(f.next_step.contains("-p 51820:51820/udp"));

        // ...unless the container is on the host network, where there is
        // nothing to publish.
        let mut i = inspect(&["NET_ADMIN"], &["/dev/net/tun:/dev/net/tun"], Some("1"));
        i.network_mode = "host".into();
        ev.inspect = Some(i);
        assert!(published_port(&ev, &mut Vec::new()).is_none());
    }
}
