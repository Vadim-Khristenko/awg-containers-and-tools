//! Getting a target machine ready: packages, kernel forwarding, and the escape
//! hatch for machines that cannot have docker at all.
//!
//! As with [`super::survey`], the decisions are pure functions and the commands
//! are strings. Nothing here talks to a server.

use crate::platform::{Distro, Step, Tool, plan};
use crate::{Error, Result};

use super::write_file_command;

// ---------------------------------------------------------------- forwarding

/// Under `/etc/sysctl.d` rather than `sysctl -w`: a tunnel that stops routing
/// after the first reboot is the kind of failure nobody connects back to the
/// deploy that caused it.
pub const SYSCTL_PATH: &str = "/etc/sysctl.d/99-amneziawg-forward.conf";

pub const SYSCTL_FILE: &str = "\
# Installed by awg-tool.
# The AmneziaWG container routes client traffic out of this machine, which the
# kernel drops unless forwarding is on. This file is what makes it survive a
# reboot; `sysctl -w` alone does not.
net.ipv4.ip_forward = 1
";

/// Write the sysctl drop-in and apply it in the same breath, so the current
/// boot and every later one agree.
pub fn enable_forwarding_command() -> String {
    format!(
        "{} && sysctl -q -w net.ipv4.ip_forward=1",
        write_file_command(SYSCTL_PATH, SYSCTL_FILE, 0o644)
    )
}

// --------------------------------------------------------------- preparation

/// What to do about the tools this machine is missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Preparation {
    /// Nothing missing.
    Ready,
    Install {
        cmd: String,
        packages: Vec<String>,
    },
    /// The distro cannot be provisioned imperatively (NixOS), or nothing here
    /// knows how. Nothing is run — the hint is for a human.
    Manual {
        reason: String,
        hint: String,
    },
    /// No package manager can supply docker, so the tunnel is built from source
    /// and supervised by systemd instead of a container. `hint` is the manual
    /// route, kept because on NixOS it is still the better answer.
    SourceFallback {
        reason: String,
        hint: String,
        plan: Box<SourceBuildPlan>,
    },
}

impl Preparation {
    /// Whether applying this involves running anything on the target.
    pub fn is_actionable(&self) -> bool {
        matches!(self, Self::Install { .. })
    }
}

/// Apply [`crate::platform::plan`], then decide whether a machine it cannot
/// help is a dead end or a source build.
pub fn plan_preparation(
    distro: &Distro,
    missing: &[Tool],
    fallback: Option<&SourceBuildOptions>,
) -> Preparation {
    match plan(distro, missing) {
        Step::Ready => Preparation::Ready,
        Step::Install { cmd, packages } => Preparation::Install { cmd, packages },
        Step::Manual { reason, hint } => {
            // Only docker is worth a source build. A machine missing `ip` or
            // `iptables` has a bigger problem than the container runtime, and
            // guessing past that would deploy something that cannot route.
            let docker_missing = missing.contains(&Tool::Docker);
            let others: Vec<Tool> = missing
                .iter()
                .copied()
                .filter(|t| *t != Tool::Docker)
                .collect();
            match fallback {
                Some(opts) if docker_missing && others.is_empty() => Preparation::SourceFallback {
                    reason: format!("{reason}; building amneziawg-go from source instead"),
                    hint,
                    plan: Box::new(source_build_plan(opts)),
                },
                _ => Preparation::Manual { reason, hint },
            }
        }
    }
}

// -------------------------------------------------------------- source build

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceBuildOptions {
    /// Tag of `amneziawg-go`. Pinned, not `master`: 3.0 UAPI key names are read
    /// out of a specific tag's `device/uapi.go`.
    pub awg_go_version: String,
    /// Tag of `amneziawg-tools`, used for nothing but `genkey`/`pubkey` — it
    /// cannot parse a 3.0 config and is never asked to.
    pub awg_tools_version: String,
    pub prefix: String,
    pub interface: String,
    pub conf_dir: String,
    /// The interface NAT masquerades out of, from the survey.
    pub egress_interface: String,
    /// The tunnel subnet to masquerade, e.g. `10.8.1.0/24`.
    pub subnet: String,
    pub mtu: u16,
    pub server_address: String,
}

impl Default for SourceBuildOptions {
    fn default() -> Self {
        Self {
            awg_go_version: "v3.0.1".into(),
            awg_tools_version: "v1.0.20260618-2".into(),
            prefix: "/opt/amneziawg".into(),
            interface: "awg0".into(),
            conf_dir: "/etc/amnezia/awg3".into(),
            egress_interface: "eth0".into(),
            subnet: "10.8.1.0/24".into(),
            mtu: 1420,
            server_address: "10.8.1.1/24".into(),
        }
    }
}

/// A recipe, not a run. Every field is inspectable so the caller can show the
/// user exactly what would happen before anything does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceBuildPlan {
    pub awg_go_version: String,
    pub binary_path: String,
    pub tools_path: String,
    pub uapi_path: String,
    pub up_script_path: String,
    pub up_script: String,
    pub unit_name: String,
    pub unit_path: String,
    pub unit: String,
    /// Shell commands, in order.
    pub steps: Vec<String>,
    /// What the plan needs and cannot install for itself. A machine with no
    /// package manager cannot be handed a Go toolchain by this tool either.
    pub prerequisites: Vec<String>,
}

pub fn source_build_plan(o: &SourceBuildOptions) -> SourceBuildPlan {
    let prefix = o.prefix.trim_end_matches('/').to_string();
    let bin = format!("{prefix}/bin");
    let src = format!("{prefix}/src");
    let binary_path = format!("{bin}/amneziawg-go");
    let tools_path = format!("{bin}/awg");
    let conf_dir = o.conf_dir.trim_end_matches('/').to_string();
    let uapi_path = format!("{conf_dir}/{}.uapi", o.interface);
    let up_script_path = format!("{bin}/awg3-up.sh");
    let unit_name = format!("amneziawg-{}.service", o.interface);
    let unit_path = format!("/etc/systemd/system/{unit_name}");

    // amneziawg-go creates the device and then waits for its configuration over
    // UAPI, exactly as in the container: amneziawg-tools cannot write a 3.0
    // config, so the request is pre-rendered and fed to the socket here.
    let up_script = format!(
        r#"#!/bin/sh
# Installed by awg-tool. Configures {iface} after amneziawg-go has created it.
set -eu
SOCK=/var/run/wireguard/{iface}.sock
i=0
while [ ! -S "$SOCK" ]; do
    i=$((i+1))
    # `[ ... ] && exit` would be the last command of an && list and take the
    # whole script down under `set -e` on the *false* branch too.
    if [ "$i" -gt 50 ]; then echo "UAPI socket never appeared" >&2; exit 1; fi
    sleep 0.1
done
socat - "UNIX-CONNECT:$SOCK" < {uapi} > /tmp/{iface}.uapi.out
grep -q '^errno=0' /tmp/{iface}.uapi.out || {{ cat /tmp/{iface}.uapi.out >&2; exit 1; }}
ip address replace {addr} dev {iface}
ip link set mtu {mtu} up dev {iface}
iptables -C FORWARD -i {iface} -j ACCEPT 2>/dev/null || iptables -A FORWARD -i {iface} -j ACCEPT
iptables -t nat -C POSTROUTING -s {subnet} -o {egress} -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s {subnet} -o {egress} -j MASQUERADE
"#,
        iface = o.interface,
        uapi = uapi_path,
        addr = o.server_address,
        mtu = o.mtu,
        subnet = o.subnet,
        egress = o.egress_interface,
    );

    // WG_PROCESS_FOREGROUND is what keeps amneziawg-go attached to systemd; it
    // daemonises by default, and a forking daemon under Type=simple is a service
    // systemd thinks died the moment it started.
    let unit = format!(
        "[Unit]\n\
         Description=AmneziaWG 3.0 ({iface}, built from source)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         Environment=WG_PROCESS_FOREGROUND=1\n\
         ExecStart={binary} {iface}\n\
         ExecStartPost={up}\n\
         ExecStopPost=-/sbin/ip link del {iface}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        iface = o.interface,
        binary = binary_path,
        up = up_script_path,
    );

    let steps = vec![
        format!("install -d -m 0755 {bin} {src}"),
        format!("install -d -m 0700 {conf_dir}"),
        format!(
            "rm -rf {src}/amneziawg-go && git clone --depth 1 --branch {ver} \
             https://github.com/amnezia-vpn/amneziawg-go.git {src}/amneziawg-go",
            ver = o.awg_go_version
        ),
        format!("make -C {src}/amneziawg-go"),
        format!("install -m 0755 {src}/amneziawg-go/amneziawg-go {binary_path}"),
        format!(
            "rm -rf {src}/amneziawg-tools && git clone --depth 1 --branch {ver} \
             https://github.com/amnezia-vpn/amneziawg-tools.git {src}/amneziawg-tools",
            ver = o.awg_tools_version
        ),
        format!("make -C {src}/amneziawg-tools/src"),
        format!("install -m 0755 {src}/amneziawg-tools/src/wg {tools_path}"),
        write_file_command(&up_script_path, &up_script, 0o755),
        write_file_command(&unit_path, &unit, 0o644),
        "systemctl daemon-reload".to_string(),
        format!("systemctl enable --now {unit_name}"),
    ];

    SourceBuildPlan {
        awg_go_version: o.awg_go_version.clone(),
        binary_path,
        tools_path,
        uapi_path,
        up_script_path,
        up_script,
        unit_name,
        unit_path,
        unit,
        steps,
        prerequisites: vec![
            "a Go toolchain (1.24 or newer)".into(),
            "git, make and a C compiler".into(),
            "socat".into(),
            "systemd".into(),
            "iproute2 and iptables".into(),
        ],
    }
}

/// Not implemented, on purpose.
///
/// Running this plan means compiling Go on the target and installing a systemd
/// unit — a very different blast radius from `docker run`, and one that wants a
/// human looking at [`SourceBuildPlan::steps`] first. The plan is generated and
/// tested; executing it is a deliberate gap rather than a silent half-measure,
/// so this returns an error that says so instead of doing part of the job.
pub fn run_source_build(plan: &SourceBuildPlan) -> Result<()> {
    Err(Error::Config(format!(
        "source fallback not attempted: this build only generates the plan ({} steps, \
         installing {} and {}). Review the steps and run them yourself, or install docker.",
        plan.steps.len(),
        plan.binary_path,
        plan.unit_path
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::detect;

    fn distro(id: &str) -> Distro {
        detect(&format!(
            "ID={id}\nPRETTY_NAME=\"Test {id}\"\nVERSION_ID=\"1\"\n"
        ))
    }

    #[test]
    fn a_machine_with_every_tool_needs_no_preparation() {
        assert_eq!(
            plan_preparation(&distro("debian"), &[], None),
            Preparation::Ready
        );
    }

    #[test]
    fn a_debian_machine_gets_an_apt_command_naming_docker_io() {
        match plan_preparation(&distro("ubuntu"), &[Tool::Docker, Tool::Curl], None) {
            Preparation::Install { cmd, packages } => {
                assert!(cmd.contains("apt-get install"), "{cmd}");
                assert_eq!(packages, vec!["docker.io".to_string(), "curl".to_string()]);
            }
            other => panic!("expected an install step, got {other:?}"),
        }
    }

    #[test]
    fn nixos_surfaces_its_hint_and_runs_nothing() {
        let p = plan_preparation(&distro("nixos"), &[Tool::Docker], None);
        match &p {
            Preparation::Manual { reason, hint } => {
                assert!(reason.contains("declaratively"), "{reason}");
                assert!(hint.contains("virtualisation.docker.enable"));
            }
            other => panic!("NixOS must never be given a command, got {other:?}"),
        }
        assert!(!p.is_actionable());
    }

    #[test]
    fn an_unknown_distro_asks_for_help_rather_than_guessing_a_package_manager() {
        let p = plan_preparation(&distro("plan9"), &[Tool::Docker], None);
        assert!(matches!(p, Preparation::Manual { .. }), "got {p:?}");
        assert!(!p.is_actionable());
    }

    #[test]
    fn with_a_fallback_offered_a_dockerless_distro_gets_a_source_build() {
        let opts = SourceBuildOptions::default();
        let p = plan_preparation(&distro("nixos"), &[Tool::Docker], Some(&opts));
        // A fallback is a plan to show, never something applied on its own.
        assert!(!p.is_actionable());
        match p {
            Preparation::SourceFallback { reason, hint, plan } => {
                assert!(reason.contains("source"), "{reason}");
                // The declarative hint is still the better answer on NixOS, so
                // it must not be thrown away.
                assert!(hint.contains("virtualisation.docker.enable"));
                assert!(!plan.steps.is_empty());
            }
            other => panic!("expected a source fallback, got {other:?}"),
        }
    }

    #[test]
    fn the_fallback_is_refused_when_more_than_docker_is_missing() {
        // No `ip` means the tunnel could not be brought up even if it built.
        let opts = SourceBuildOptions::default();
        let p = plan_preparation(
            &distro("plan9"),
            &[Tool::Docker, Tool::Iproute2],
            Some(&opts),
        );
        assert!(matches!(p, Preparation::Manual { .. }), "got {p:?}");
    }

    #[test]
    fn a_distro_that_can_install_docker_is_never_diverted_to_a_source_build() {
        let opts = SourceBuildOptions::default();
        let p = plan_preparation(&distro("fedora"), &[Tool::Docker], Some(&opts));
        assert!(matches!(p, Preparation::Install { .. }), "got {p:?}");
    }

    #[test]
    fn the_source_plan_pins_versions_and_installs_a_unit() {
        let plan = source_build_plan(&SourceBuildOptions::default());
        let all = plan.steps.join("\n");
        assert!(
            all.contains("--branch v3.0.1"),
            "the go daemon tag must be pinned"
        );
        assert!(all.contains("amneziawg-go.git"));
        assert!(
            all.contains("amneziawg-tools.git"),
            "genkey has to come from somewhere"
        );
        assert!(all.contains("systemctl daemon-reload"));
        assert!(all.contains("systemctl enable --now amneziawg-awg0.service"));
        assert_eq!(plan.unit_path, "/etc/systemd/system/amneziawg-awg0.service");
        assert_eq!(plan.binary_path, "/opt/amneziawg/bin/amneziawg-go");
        // Clone before build before install, in that order.
        let clone = all.find("git clone").unwrap();
        let build = all.find("make -C").unwrap();
        let unit = all.find("daemon-reload").unwrap();
        assert!(clone < build && build < unit);
    }

    #[test]
    fn the_unit_keeps_the_daemon_in_the_foreground() {
        let plan = source_build_plan(&SourceBuildOptions::default());
        // Without this amneziawg-go forks and systemd declares the service dead.
        assert!(plan.unit.contains("Environment=WG_PROCESS_FOREGROUND=1"));
        assert!(
            plan.unit
                .contains("ExecStart=/opt/amneziawg/bin/amneziawg-go awg0")
        );
        assert!(
            plan.unit
                .contains("ExecStartPost=/opt/amneziawg/bin/awg3-up.sh")
        );
        assert!(plan.unit.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn the_up_script_configures_the_device_over_uapi_not_with_awg_quick() {
        let plan = source_build_plan(&SourceBuildOptions {
            egress_interface: "ens3".into(),
            ..Default::default()
        });
        assert!(plan.up_script.contains("UNIX-CONNECT:$SOCK"));
        assert!(
            plan.up_script.contains("errno=0"),
            "a rejected config must fail the unit"
        );
        assert!(plan.up_script.contains("-o ens3 -j MASQUERADE"));
        assert!(
            !plan.up_script.contains("awg-quick"),
            "the tools cannot parse a 3.0 config"
        );
        assert_eq!(plan.uapi_path, "/etc/amnezia/awg3/awg0.uapi");
    }

    #[test]
    fn running_the_source_build_reports_that_it_was_not_attempted() {
        let plan = source_build_plan(&SourceBuildOptions::default());
        let err = run_source_build(&plan).unwrap_err().to_string();
        assert!(err.contains("not attempted"), "{err}");
        assert!(err.contains("/opt/amneziawg/bin/amneziawg-go"));
    }

    #[test]
    fn forwarding_is_made_persistent_and_applied_at_once() {
        assert!(SYSCTL_FILE.contains("net.ipv4.ip_forward = 1"));
        assert!(
            SYSCTL_PATH.starts_with("/etc/sysctl.d/"),
            "a reboot must not undo this"
        );
        let cmd = enable_forwarding_command();
        assert!(cmd.contains(SYSCTL_PATH), "{cmd}");
        assert!(cmd.contains("sysctl -q -w net.ipv4.ip_forward=1"), "{cmd}");
    }
}
