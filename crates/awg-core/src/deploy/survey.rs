//! Reading the shape of a target machine out of command output.
//!
//! Nothing here runs a command. Every function takes the *text something
//! printed* and returns a decision, because the parsing is the part that meets
//! a busybox `ip` or a Fedora route table and gets it wrong, and it is the only
//! part a test can reach without a server. [`survey_from_probes`] assembles the
//! whole picture from a bundle of captured outputs, so the SSH layer above is
//! left with nothing but transport.

use std::net::{IpAddr, Ipv4Addr};

use crate::platform::{Distro, Tool, detect};

/// Whether the login user can drive docker, and at what cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerAccess {
    /// `docker ...` works as the login user — root, or a member of the
    /// `docker` group.
    Direct,
    /// The binary is there and the daemon answers, but only through sudo.
    NeedsSudo,
    /// Installed and reachable by neither route: usually a daemon that is not
    /// running. Distinguished from [`Self::Absent`] because installing the
    /// package again will not fix it.
    Unusable,
    /// No `docker` binary at all.
    Absent,
}

impl DockerAccess {
    pub fn is_usable(self) -> bool {
        matches!(self, Self::Direct | Self::NeedsSudo)
    }

    pub fn needs_sudo(self) -> bool {
        self == Self::NeedsSudo
    }
}

/// Decide from the two probes: does the binary exist, and what did
/// `docker info` exit with as the login user and (optionally) under sudo.
///
/// The sudo probe is what separates "socket you may not read" from "daemon that
/// is down" — both fail identically for an unprivileged user.
pub fn docker_access(
    binary_present: bool,
    direct_code: i32,
    sudo_code: Option<i32>,
) -> DockerAccess {
    if !binary_present {
        return DockerAccess::Absent;
    }
    if direct_code == 0 {
        return DockerAccess::Direct;
    }
    match sudo_code {
        Some(0) => DockerAccess::NeedsSudo,
        Some(_) => DockerAccess::Unusable,
        // Nobody asked sudo. Assume the privileged path rather than declaring
        // the host broken on evidence we did not collect.
        None => DockerAccess::NeedsSudo,
    }
}

// ------------------------------------------------------------------ binaries

/// Probe several binaries in one round trip.
///
/// `command -v` rather than `which`: `which` is a separate package on Alpine and
/// missing from a minimal Debian, so the probe for missing tools would itself be
/// the missing tool.
pub fn tool_probe_command(tools: &[Tool]) -> String {
    let names: Vec<&str> = tools.iter().map(|t| t.binary()).collect();
    format!(
        "for b in {}; do printf '%s %s\\n' \"$b\" \"$(command -v \"$b\" 2>/dev/null || echo -)\"; done",
        names.join(" ")
    )
}

/// Which of `tools` the probe output says are not installed.
///
/// A tool the output never mentions counts as missing: a truncated reply must
/// not read as "everything is fine".
pub fn parse_tool_probe(output: &str, tools: &[Tool]) -> Vec<Tool> {
    tools
        .iter()
        .copied()
        .filter(|t| tool_path(output, t.binary()).is_none())
        .collect()
}

/// The resolved path of one binary in the probe output, if it has one.
pub fn tool_path<'a>(output: &'a str, binary: &str) -> Option<&'a str> {
    output.lines().find_map(|line| {
        let (name, path) = line.trim().split_once(char::is_whitespace)?;
        let path = path.trim();
        (name == binary && !path.is_empty() && path != "-").then_some(path)
    })
}

// -------------------------------------------------------------------- routes

/// One route as `ip route` prints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// `dev` — the egress interface, which is what NAT has to masquerade out of.
    pub interface: String,
    /// `via` — next hop. Absent on point-to-point links.
    pub gateway: Option<String>,
    /// `src` — the local address the kernel would use. On a machine with a
    /// public address directly attached this *is* the public IP; behind NAT it
    /// is an RFC1918 one, which is why [`is_global_ipv4`] exists.
    pub source: Option<String>,
    /// Missing metric means zero, which is how the kernel treats it.
    pub metric: Option<u32>,
}

/// `ip -4 route show default`, or `ip route get <addr>` — both print the same
/// `key value` tail, so one parser covers both.
pub fn parse_route(output: &str) -> Option<Route> {
    let mut best: Option<Route> = None;
    let mut best_is_default = false;

    for line in output.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        let Some(&first) = toks.first() else { continue };
        // Rejecting routes: they have no usable device and picking one would
        // send the tunnel's return traffic into a black hole.
        if matches!(first, "blackhole" | "unreachable" | "prohibit" | "throw") {
            continue;
        }
        // `ip route get` repeats itself on a "cache" continuation line.
        if first == "cache" {
            continue;
        }
        let Some(interface) = value_after(&toks, "dev") else {
            continue;
        };

        let route = Route {
            interface: interface.to_string(),
            gateway: value_after(&toks, "via").map(str::to_string),
            source: value_after(&toks, "src").map(str::to_string),
            metric: value_after(&toks, "metric").and_then(|m| m.parse().ok()),
        };
        let is_default = first == "default";

        let better = match &best {
            None => true,
            // An explicit default beats anything the kernel merely resolved.
            Some(_) if is_default && !best_is_default => true,
            Some(_) if !is_default && best_is_default => false,
            Some(b) => route.metric.unwrap_or(0) < b.metric.unwrap_or(0),
        };
        if better {
            best_is_default = is_default;
            best = Some(route);
        }
    }
    best
}

fn value_after<'a>(toks: &[&'a str], key: &str) -> Option<&'a str> {
    let i = toks.iter().position(|t| *t == key)?;
    toks.get(i + 1).copied().filter(|v| !v.is_empty())
}

// ---------------------------------------------------------------- forwarding

/// Accepts both shapes: `sysctl net.ipv4.ip_forward` prints `key = 1`,
/// `cat /proc/sys/net/ipv4/ip_forward` and `sysctl -n` print a bare `1`.
pub fn parse_ip_forward(output: &str) -> bool {
    output
        .lines()
        .map(|l| l.rsplit('=').next().unwrap_or("").trim())
        .any(|v| v == "1")
}

// ----------------------------------------------------------------- public IP

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicIpSource {
    /// Taken from the `src` of the default route — no third party involved.
    DefaultRoute,
    /// An external echo service was asked. Only reached when the caller opts in.
    ExternalEcho,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicIp {
    pub address: String,
    pub source: PublicIpSource,
    /// False means clients will not be able to reach this address from the
    /// outside — the deploy still proceeds, the caller warns.
    pub global: bool,
}

/// Is this an address the rest of the internet can route to?
///
/// `Ipv4Addr::is_global` is still unstable, so the exclusions are spelled out.
pub fn is_global_ipv4(addr: &str) -> bool {
    let Ok(ip) = addr.parse::<Ipv4Addr>() else {
        return false;
    };
    let o = ip.octets();
    // 100.64/10 is carrier-grade NAT: routable-looking, still unreachable from
    // outside the ISP, and std has no predicate for it.
    let cgnat = o[0] == 100 && (64..128).contains(&o[1]);
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_documentation()
        || cgnat)
}

/// What an IP echo service replied, if it replied with an address at all.
pub fn parse_echo_response(body: &str) -> Option<String> {
    let first = body.trim().lines().next()?.trim();
    first.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

/// Prefer the machine's own view of itself; only believe a third party when the
/// local address is one that cannot be reached from outside.
pub fn resolve_public_ip(route: Option<&Route>, echo: Option<&str>) -> Option<PublicIp> {
    let local = route.and_then(|r| r.source.clone());

    if let Some(addr) = &local
        && is_global_ipv4(addr)
    {
        return Some(PublicIp {
            address: addr.clone(),
            source: PublicIpSource::DefaultRoute,
            global: true,
        });
    }

    if let Some(addr) = echo.and_then(parse_echo_response) {
        let global = is_global_ipv4(&addr);
        return Some(PublicIp {
            address: addr,
            source: PublicIpSource::ExternalEcho,
            global,
        });
    }

    local.map(|address| PublicIp {
        address,
        source: PublicIpSource::DefaultRoute,
        global: false,
    })
}

// ---------------------------------------------------------------- privileges

/// `id -u`. Worth knowing before reaching for sudo: a minimal image logged into
/// as root often has no sudo at all, and wrapping a command in one that is not
/// installed turns "root already" into "command not found".
pub fn parse_uid(output: &str) -> Option<u32> {
    output.trim().lines().next()?.trim().parse().ok()
}

// -------------------------------------------------------------------- survey

/// Raw command output, exactly as captured. Keeping this a plain struct is what
/// lets the whole survey be exercised from recorded transcripts.
#[derive(Debug, Clone, Default)]
pub struct Probes {
    pub os_release: String,
    pub tool_probe: String,
    pub route: String,
    pub ip_forward: String,
    /// `id -u`.
    pub uid: String,
    /// `docker info` as the login user, and under sudo if it was tried.
    pub docker_direct_code: i32,
    pub docker_sudo_code: Option<i32>,
    /// Body of the external echo request, when the caller allowed one.
    pub echo: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Survey {
    pub distro: Distro,
    pub missing: Vec<Tool>,
    pub route: Option<Route>,
    pub public_ip: Option<PublicIp>,
    pub ip_forward: bool,
    pub docker: DockerAccess,
    /// Already root — so privileged commands must not be wrapped in a sudo that
    /// may not be installed.
    pub is_root: bool,
}

impl Survey {
    /// The interface NAT has to masquerade out of.
    pub fn egress_interface(&self) -> Option<&str> {
        self.route.as_ref().map(|r| r.interface.as_str())
    }

    /// The address to put in a client's `Endpoint`.
    pub fn endpoint_host(&self) -> Option<&str> {
        self.public_ip.as_ref().map(|p| p.address.as_str())
    }
}

/// Turn captured output into a survey. Pure — see the module note.
pub fn survey_from_probes(p: &Probes) -> Survey {
    let distro = detect(&p.os_release);
    let missing = parse_tool_probe(&p.tool_probe, &Tool::REQUIRED);
    let route = parse_route(&p.route);
    let docker = docker_access(
        tool_path(&p.tool_probe, Tool::Docker.binary()).is_some(),
        p.docker_direct_code,
        p.docker_sudo_code,
    );
    Survey {
        distro,
        missing,
        public_ip: resolve_public_ip(route.as_ref(), p.echo.as_deref()),
        route,
        ip_forward: parse_ip_forward(&p.ip_forward),
        docker,
        is_root: parse_uid(&p.uid) == Some(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::PackageManager;

    const UBUNTU: &str = r#"PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
ID_LIKE=debian
"#;

    #[test]
    fn os_release_survey_gives_the_distro_and_its_package_manager() {
        let s = survey_from_probes(&Probes {
            os_release: UBUNTU.into(),
            ..Default::default()
        });
        assert_eq!(s.distro.id, "ubuntu");
        assert_eq!(s.distro.version, "24.04");
        assert_eq!(s.distro.pm, PackageManager::Apt);
    }

    #[test]
    fn a_blank_os_release_does_not_pretend_to_know_the_distro() {
        let s = survey_from_probes(&Probes::default());
        assert_eq!(s.distro.pm, PackageManager::Unknown);
    }

    #[test]
    fn probe_command_asks_for_every_required_binary() {
        let cmd = tool_probe_command(&Tool::REQUIRED);
        for t in Tool::REQUIRED {
            assert!(cmd.contains(t.binary()), "{} not probed", t.binary());
        }
        assert!(cmd.contains("command -v"));
    }

    #[test]
    fn command_v_output_tells_present_from_missing() {
        let out = "docker /usr/bin/docker\niptables /usr/sbin/iptables\nip -\ncurl /usr/bin/curl\n";
        assert_eq!(parse_tool_probe(out, &Tool::REQUIRED), vec![Tool::Iproute2]);
        assert_eq!(tool_path(out, "docker"), Some("/usr/bin/docker"));
        assert_eq!(tool_path(out, "ip"), None);
    }

    #[test]
    fn a_tool_absent_from_the_output_entirely_counts_as_missing() {
        // A truncated reply must not read as "everything is installed".
        let out = "docker /usr/bin/docker\n";
        let missing = parse_tool_probe(out, &Tool::REQUIRED);
        assert_eq!(missing, vec![Tool::Iptables, Tool::Iproute2, Tool::Curl]);
    }

    #[test]
    fn default_route_yields_interface_gateway_and_source() {
        let out = "default via 192.168.1.1 dev enp3s0 proto dhcp src 192.168.1.50 metric 100\n";
        let r = parse_route(out).unwrap();
        assert_eq!(r.interface, "enp3s0");
        assert_eq!(r.gateway.as_deref(), Some("192.168.1.1"));
        assert_eq!(r.source.as_deref(), Some("192.168.1.50"));
        assert_eq!(r.metric, Some(100));
    }

    #[test]
    fn the_lowest_metric_default_route_wins() {
        let out = "\
default via 10.0.0.1 dev wlan0 proto dhcp src 10.0.0.9 metric 600
default via 10.0.2.2 dev eth0 proto dhcp src 10.0.2.15 metric 100
";
        assert_eq!(parse_route(out).unwrap().interface, "eth0");
    }

    #[test]
    fn a_route_without_metric_outranks_one_with_metric() {
        let out = "\
default via 172.31.1.1 dev ens5 proto dhcp metric 100
default via 172.31.1.1 dev ens6 proto static
";
        assert_eq!(parse_route(out).unwrap().interface, "ens6");
    }

    #[test]
    fn ip_route_get_output_parses_the_same_way() {
        // Real `ip route get 1.1.1.1` on a VPS with a directly attached public
        // address: no `via`, and the src is the public IP.
        let out = "1.1.1.1 dev eth0 src 203.0.113.10 uid 1000 \n    cache \n";
        let r = parse_route(out).unwrap();
        assert_eq!(r.interface, "eth0");
        assert_eq!(r.source.as_deref(), Some("203.0.113.10"));
        assert_eq!(r.gateway, None);
    }

    #[test]
    fn point_to_point_routes_have_no_gateway_but_still_have_a_device() {
        let out = "default dev venet0 scope link src 198.51.100.7\n";
        let r = parse_route(out).unwrap();
        assert_eq!(r.interface, "venet0");
        assert_eq!(r.gateway, None);
    }

    #[test]
    fn unroutable_entries_are_never_chosen_as_egress() {
        let out = "blackhole 10.0.0.0/8 dev lo\ndefault via 10.0.0.1 dev eth0\n";
        assert_eq!(parse_route(out).unwrap().interface, "eth0");
    }

    #[test]
    fn no_route_at_all_is_none_rather_than_a_guess() {
        assert_eq!(parse_route(""), None);
        assert_eq!(
            parse_route("Error: ipv4: FIB table does not exist.\n"),
            None
        );
    }

    #[test]
    fn ip_forward_reads_both_sysctl_shapes() {
        assert!(parse_ip_forward("net.ipv4.ip_forward = 1\n"));
        assert!(parse_ip_forward("1\n"));
        assert!(!parse_ip_forward("net.ipv4.ip_forward = 0\n"));
        assert!(!parse_ip_forward("0"));
        assert!(!parse_ip_forward(""));
        // A sysctl that does not exist must not read as "enabled".
        assert!(!parse_ip_forward(
            "sysctl: cannot stat /proc/sys/net/ipv4/ip_forward: No such file or directory\n"
        ));
    }

    #[test]
    fn private_and_cgnat_addresses_are_not_reachable_endpoints() {
        for bad in [
            "10.0.2.15",
            "192.168.1.50",
            "172.16.4.4",
            "127.0.0.1",
            "169.254.3.4",
            "100.64.1.1",
            "100.127.255.255",
            "0.0.0.0",
            "224.0.0.1",
            "203.0.113.10", // TEST-NET-3, documentation only
            "not-an-ip",
        ] {
            assert!(!is_global_ipv4(bad), "{bad} must not count as global");
        }
        for good in ["1.1.1.1", "95.85.30.7", "100.63.255.255", "100.128.0.1"] {
            assert!(is_global_ipv4(good), "{good} must count as global");
        }
    }

    #[test]
    fn the_route_source_is_preferred_over_any_echo_service() {
        let route = parse_route("default via 1.2.3.1 dev eth0 src 95.85.30.7\n").unwrap();
        let ip = resolve_public_ip(Some(&route), Some("8.8.8.8")).unwrap();
        assert_eq!(ip.address, "95.85.30.7");
        assert_eq!(ip.source, PublicIpSource::DefaultRoute);
        assert!(ip.global);
    }

    #[test]
    fn behind_nat_the_echo_service_is_used_when_one_was_allowed() {
        let route = parse_route("default via 192.168.1.1 dev eth0 src 192.168.1.50\n").unwrap();
        let ip = resolve_public_ip(Some(&route), Some("95.85.30.7\n")).unwrap();
        assert_eq!(ip.address, "95.85.30.7");
        assert_eq!(ip.source, PublicIpSource::ExternalEcho);
        assert!(ip.global);
    }

    #[test]
    fn behind_nat_without_an_echo_the_private_address_is_returned_and_flagged() {
        let route = parse_route("default via 192.168.1.1 dev eth0 src 192.168.1.50\n").unwrap();
        let ip = resolve_public_ip(Some(&route), None).unwrap();
        assert_eq!(ip.address, "192.168.1.50");
        assert!(
            !ip.global,
            "a private endpoint must be flagged, not silently shipped"
        );
    }

    #[test]
    fn junk_from_an_echo_service_is_not_taken_for_an_address() {
        assert_eq!(parse_echo_response("<html>error</html>"), None);
        assert_eq!(parse_echo_response(""), None);
        assert_eq!(
            parse_echo_response(" 95.85.30.7 \n"),
            Some("95.85.30.7".into())
        );
        assert_eq!(
            parse_echo_response("2001:db8::1\n"),
            Some("2001:db8::1".into())
        );
    }

    #[test]
    fn docker_access_separates_group_membership_from_a_dead_daemon() {
        assert_eq!(docker_access(false, 127, None), DockerAccess::Absent);
        assert_eq!(docker_access(true, 0, None), DockerAccess::Direct);
        assert_eq!(docker_access(true, 1, Some(0)), DockerAccess::NeedsSudo);
        assert_eq!(docker_access(true, 1, Some(1)), DockerAccess::Unusable);
        assert!(DockerAccess::NeedsSudo.needs_sudo());
        assert!(!DockerAccess::Direct.needs_sudo());
        assert!(!DockerAccess::Unusable.is_usable());
    }

    /// Captured verbatim from a real NixOS 26.05 machine, trailing spaces and
    /// the `cache` continuation line included — synthetic samples are exactly
    /// where a parser stops meeting reality.
    #[test]
    fn a_recorded_nixos_transcript_reads_the_way_the_machine_actually_is() {
        let s = survey_from_probes(&Probes {
            os_release: "ANSI_COLOR=\"0;38;2;126;186;228\"\nID=nixos\nID_LIKE=\"\"\n\
                         NAME=NixOS\nPRETTY_NAME=\"NixOS 26.05 (Yarara)\"\n\
                         VERSION=\"26.05 (Yarara)\"\nVERSION_ID=\"26.05\"\n"
                .into(),
            tool_probe: "docker /run/current-system/sw/bin/docker\n\
                         iptables /run/current-system/sw/bin/iptables\n\
                         ip /run/current-system/sw/bin/ip\n\
                         curl /run/current-system/sw/bin/curl\n"
                .into(),
            route: "default via 192.168.1.1 dev wlp3s0 proto dhcp src 192.168.1.50 metric 600 \n\
                    1.1.1.1 via 192.168.1.1 dev wlp3s0 src 192.168.1.50 uid 1000 \n    cache \n"
                .into(),
            ip_forward: "1\n".into(),
            uid: "1000\n".into(),
            docker_direct_code: 0,
            docker_sudo_code: None,
            echo: None,
        });

        assert_eq!(s.distro.pm, PackageManager::NixOS);
        assert_eq!(s.distro.version, "26.05");
        assert!(s.distro.is_declarative());
        assert!(s.missing.is_empty(), "nothing is missing on this machine");
        assert_eq!(s.egress_interface(), Some("wlp3s0"));
        assert!(s.ip_forward);
        assert!(!s.is_root);
        assert_eq!(s.docker, DockerAccess::Direct);
        // Behind a home router: usable as a target, but not as an endpoint.
        assert_eq!(s.endpoint_host(), Some("192.168.1.50"));
        assert!(!s.public_ip.unwrap().global);
    }

    #[test]
    fn root_is_recognised_so_sudo_is_not_reached_for() {
        assert_eq!(parse_uid("0\n"), Some(0));
        assert_eq!(parse_uid("1000"), Some(1000));
        assert_eq!(parse_uid("id: command not found\n"), None);
        assert_eq!(parse_uid(""), None);
        assert!(
            survey_from_probes(&Probes {
                uid: "0\n".into(),
                ..Default::default()
            })
            .is_root
        );
        // No answer means "not root": assuming root would skip a sudo that was
        // needed, and the failure would land halfway through a deploy.
        assert!(!survey_from_probes(&Probes::default()).is_root);
    }

    #[test]
    fn a_full_probe_bundle_becomes_a_complete_survey() {
        let s = survey_from_probes(&Probes {
            os_release: UBUNTU.into(),
            tool_probe:
                "docker /usr/bin/docker\niptables /usr/sbin/iptables\nip /usr/sbin/ip\ncurl -\n"
                    .into(),
            route: "default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.9 metric 100\n".into(),
            ip_forward: "net.ipv4.ip_forward = 0\n".into(),
            uid: "1000\n".into(),
            docker_direct_code: 1,
            docker_sudo_code: Some(0),
            echo: Some("95.85.30.7".into()),
        });
        assert_eq!(s.missing, vec![Tool::Curl]);
        assert_eq!(s.egress_interface(), Some("eth0"));
        assert_eq!(s.endpoint_host(), Some("95.85.30.7"));
        assert!(!s.ip_forward);
        assert!(!s.is_root);
        assert_eq!(s.docker, DockerAccess::NeedsSudo);
    }
}
