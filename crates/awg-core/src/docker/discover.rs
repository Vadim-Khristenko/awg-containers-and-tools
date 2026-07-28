//! Which containers on this host are ours.
//!
//! `docker ps` in, a list of [`Container`] out. Ownership is decided by
//! [`super::image`] — the image reference, never the container name — with the
//! [`PROTOCOL_LABEL`] as the fallback for an image someone retagged.

use std::collections::BTreeMap;

use super::host::Host;
use super::image::{Generation, ImageRef, PROTOCOL_LABEL, parse_image_ref};
use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerState {
    Created,
    Restarting,
    Running,
    Removing,
    Paused,
    Exited,
    Dead,
    Unknown(String),
}

impl ContainerState {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "created" => ContainerState::Created,
            "restarting" => ContainerState::Restarting,
            "running" => ContainerState::Running,
            "removing" => ContainerState::Removing,
            "paused" => ContainerState::Paused,
            "exited" => ContainerState::Exited,
            "dead" => ContainerState::Dead,
            other => ContainerState::Unknown(other.to_string()),
        }
    }

    /// Older docker builds have no `{{.State}}`; the human status still says it.
    pub fn from_status(status: &str) -> Self {
        let s = status.trim();
        if s.starts_with("Up") && s.contains("Paused") {
            ContainerState::Paused
        } else if s.starts_with("Up") {
            ContainerState::Running
        } else if s.starts_with("Exited") {
            ContainerState::Exited
        } else if s.starts_with("Created") {
            ContainerState::Created
        } else if s.starts_with("Restarting") {
            ContainerState::Restarting
        } else if s.starts_with("Dead") {
            ContainerState::Dead
        } else {
            ContainerState::Unknown(s.to_string())
        }
    }

    pub fn is_running(&self) -> bool {
        matches!(self, ContainerState::Running)
    }

    pub fn as_str(&self) -> &str {
        match self {
            ContainerState::Created => "created",
            ContainerState::Restarting => "restarting",
            ContainerState::Running => "running",
            ContainerState::Removing => "removing",
            ContainerState::Paused => "paused",
            ContainerState::Exited => "exited",
            ContainerState::Dead => "dead",
            ContainerState::Unknown(s) => s,
        }
    }
}

/// One `->` entry out of `docker ps`'s port column, or one `PortBindings` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedPort {
    /// `None` when the port is merely exposed and not published.
    pub host_ip: Option<String>,
    pub host_port: Option<u16>,
    pub container_port: u16,
    pub protocol: String,
}

impl PublishedPort {
    pub fn is_published(&self) -> bool {
        self.host_port.is_some()
    }
}

impl std::fmt::Display for PublishedPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.host_ip, self.host_port) {
            (Some(ip), Some(p)) => write!(f, "{ip}:{p}->{}/{}", self.container_port, self.protocol),
            (None, Some(p)) => write!(f, "{p}->{}/{}", self.container_port, self.protocol),
            _ => write!(f, "{}/{}", self.container_port, self.protocol),
        }
    }
}

/// `0.0.0.0:51820->51820/udp, [::]:51820->51820/udp, 53/tcp`
pub fn parse_ports(column: &str) -> Vec<PublishedPort> {
    let mut out = Vec::new();
    for entry in column.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (host, container) = match entry.split_once("->") {
            Some((h, c)) => (Some(h.trim()), c.trim()),
            None => (None, entry),
        };
        let (port_text, protocol) = match container.rsplit_once('/') {
            Some((p, proto)) => (p, proto.to_ascii_lowercase()),
            None => (container, "tcp".to_string()),
        };
        let Ok(container_port) = port_text.trim().parse::<u16>() else {
            continue;
        };

        let (host_ip, host_port) = match host {
            // `[::]:51820` — the address is bracketed, the port follows.
            Some(h) if h.starts_with('[') => match h.rsplit_once("]:") {
                Some((ip, p)) => (
                    Some(ip.trim_start_matches('[').to_string()),
                    p.parse::<u16>().ok(),
                ),
                None => (None, None),
            },
            Some(h) => match h.rsplit_once(':') {
                Some((ip, p)) => (Some(ip.to_string()), p.parse::<u16>().ok()),
                None => (None, h.parse::<u16>().ok()),
            },
            None => (None, None),
        };

        out.push(PublishedPort {
            host_ip,
            host_port,
            container_port,
            protocol,
        });
    }
    out
}

/// A container on the target, as `docker ps` describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    pub id: String,
    pub name: String,
    /// The image reference verbatim, exactly as docker reported it.
    pub image: String,
    pub image_ref: Option<ImageRef>,
    /// From the image name, or from [`PROTOCOL_LABEL`] when the image was
    /// renamed. `None` when neither says.
    pub generation: Option<Generation>,
    pub state: ContainerState,
    /// `Up 4 minutes`, `Exited (1) 2 hours ago`.
    pub status: String,
    /// The `4 minutes` out of `Up 4 minutes`, when it is up.
    pub uptime: Option<String>,
    pub created_at: String,
    pub ports: Vec<PublishedPort>,
    /// This container belongs to this project.
    pub ours: bool,
}

impl Container {
    /// The UDP port the tunnel is published on, if any.
    pub fn udp_port(&self) -> Option<u16> {
        self.ports
            .iter()
            .find(|p| p.protocol == "udp" && p.host_port.is_some())
            .and_then(|p| p.host_port)
    }
}

/// The `--format` string [`parse_ps`] expects. Tab-separated rather than JSON
/// because the field set of `docker ps --format json` has changed between
/// releases and the tab layout has not.
pub const PS_FORMAT: &str =
    "{{.ID}}\\t{{.Image}}\\t{{.Names}}\\t{{.State}}\\t{{.Status}}\\t{{.CreatedAt}}\\t{{.Ports}}";

pub fn ps_command() -> String {
    format!("docker ps --all --no-trunc --format '{PS_FORMAT}'")
}

/// Container ids carrying [`PROTOCOL_LABEL`], asked for separately rather than
/// read out of `{{.Labels}}`: the OCI description label contains commas and the
/// `{{.Labels}}` column is comma-separated, so that column cannot be parsed
/// reliably.
pub fn ps_label_command() -> String {
    format!(
        "docker ps --all --no-trunc --filter 'label={PROTOCOL_LABEL}' \
         --format '{{{{.ID}}}}\\t{{{{.Label \"{PROTOCOL_LABEL}\"}}}}'"
    )
}

/// Parse the output of [`ps_command`].
pub fn parse_ps(output: &str) -> Vec<Container> {
    let mut out = Vec::new();
    for line in output.lines() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 7 {
            continue;
        }
        let image = f[1].trim().to_string();
        let image_ref = parse_image_ref(&image);
        let status = f[4].trim().to_string();
        let state = if f[3].trim().is_empty() {
            ContainerState::from_status(&status)
        } else {
            ContainerState::parse(f[3])
        };
        let uptime = status
            .strip_prefix("Up ")
            .map(|rest| rest.split('(').next().unwrap_or(rest).trim().to_string());

        out.push(Container {
            id: f[0].trim().to_string(),
            // A container can carry several names; docker joins them with a
            // comma and the first is the one every command accepts.
            name: f[2].split(',').next().unwrap_or("").trim().to_string(),
            image,
            generation: image_ref.as_ref().and_then(ImageRef::generation),
            ours: image_ref.as_ref().is_some_and(ImageRef::is_awg),
            image_ref,
            state,
            status,
            uptime,
            created_at: f[5].trim().to_string(),
            ports: parse_ports(f[6]),
        });
    }
    out
}

/// Parse the output of [`ps_label_command`] into `id -> label value`.
pub fn parse_label_ids(output: &str) -> BTreeMap<String, String> {
    output
        .lines()
        .filter_map(|l| l.trim().split_once('\t'))
        .map(|(id, v)| (id.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// Fold the label evidence into the container list: a container whose image no
/// longer names this project is still ours if it carries the label.
pub fn apply_label_evidence(containers: &mut [Container], labels: &BTreeMap<String, String>) {
    for c in containers {
        if let Some(value) = labels.get(&c.id) {
            c.ours = true;
            if c.generation.is_none() {
                c.generation = Generation::from_label(value);
            }
        }
    }
}

/// Every container on the host, ours or not.
pub fn list_containers(host: &Host) -> Result<Vec<Container>> {
    let (out, err, code) = host.run_docker(&ps_command())?;
    if code != 0 {
        return Err(Error::Ssh(format!(
            "`docker ps` failed (exit {code}): {}",
            err.trim()
        )));
    }
    let mut containers = parse_ps(&out);
    // Best effort: an old docker without `--filter label` is not a reason to
    // report nothing.
    if let Ok((lout, _, 0)) = host.run_docker(&ps_label_command()) {
        apply_label_evidence(&mut containers, &parse_label_ids(&lout));
    }
    Ok(containers)
}

/// The containers on this host that belong to this project.
pub fn find_awg_containers(host: &Host) -> Result<Vec<Container>> {
    Ok(list_containers(host)?
        .into_iter()
        .filter(|c| c.ours)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::versions::AwgVersion;

    #[test]
    fn the_port_column_survives_ipv6_and_unpublished_ports() {
        let p = parse_ports("0.0.0.0:51820->51820/udp, [::]:51820->51820/udp, 53/tcp");
        assert_eq!(p.len(), 3);
        assert_eq!(p[0].host_ip.as_deref(), Some("0.0.0.0"));
        assert_eq!(p[0].host_port, Some(51820));
        assert_eq!(p[0].protocol, "udp");
        assert_eq!(p[1].host_ip.as_deref(), Some("::"));
        assert_eq!(p[1].host_port, Some(51820));
        // Exposed but not published — not reachable from outside.
        assert_eq!(p[2].host_port, None);
        assert!(!p[2].is_published());
        assert_eq!(p[0].to_string(), "0.0.0.0:51820->51820/udp");
        assert!(parse_ports("").is_empty());
    }

    const PS: &str = "\
9f2c\tvaiprog/amnezia-wg-3:latest\tawg-server\trunning\tUp 4 minutes\t2026-07-28 21:00:00 +0300 MSK\t0.0.0.0:51820->51820/udp
7a1b\tvaiprog/amnezia-wg-dns:latest\tawg-dns\trunning\tUp 4 minutes\t2026-07-28 21:00:00 +0300 MSK\t
3c4d\tnginx:latest\tweb\trunning\tUp 2 hours\t2026-07-28 19:00:00 +0300 MSK\t0.0.0.0:80->80/tcp
5e6f\tvaiprog/amnezia-wg-2:latest\tsomeones-own-name\texited\tExited (1) 3 minutes ago\t2026-07-28 20:00:00 +0300 MSK\t";

    #[test]
    fn detection_matches_on_the_image_and_not_on_the_name() {
        let c = parse_ps(PS);
        assert_eq!(c.len(), 4);
        assert_eq!(
            c.iter().filter(|c| c.ours).count(),
            3,
            "nginx must not be picked up"
        );
        // A container nobody named after this project is still ours.
        let renamed = c.iter().find(|c| c.name == "someones-own-name").unwrap();
        assert!(renamed.ours);
        assert_eq!(renamed.generation, Some(Generation::Awg(AwgVersion::V2_0)));
        assert_eq!(renamed.state, ContainerState::Exited);

        let srv = &c[0];
        assert_eq!(srv.name, "awg-server");
        assert_eq!(srv.uptime.as_deref(), Some("4 minutes"));
        assert_eq!(srv.udp_port(), Some(51820));
        assert_eq!(srv.generation, Some(Generation::Awg(AwgVersion::V3_0)));
        assert_eq!(c[1].generation, Some(Generation::Dns));
        assert_eq!(c[1].udp_port(), None);
    }

    #[test]
    fn a_renamed_image_is_still_ours_if_it_carries_the_label() {
        let ps = "aa11\tmy-private-reg.example/vpn:1\tvpn\trunning\tUp 1 minute\t2026-07-28 21:00:00 +0300 MSK\t";
        let mut c = parse_ps(ps);
        assert!(!c[0].ours, "nothing in the reference says this is ours");
        apply_label_evidence(&mut c, &parse_label_ids("aa11\t3.0\n"));
        assert!(c[0].ours);
        assert_eq!(c[0].generation, Some(Generation::Awg(AwgVersion::V3_0)));
    }

    #[test]
    fn state_falls_back_to_the_human_status_when_docker_does_not_report_it() {
        let ps = "aa\tvaiprog/amnezia-wg-3:latest\tx\t\tUp 3 seconds\t2026\t";
        assert_eq!(parse_ps(ps)[0].state, ContainerState::Running);
        let ps = "aa\tvaiprog/amnezia-wg-3:latest\tx\t\tExited (0) 1 hour ago\t2026\t";
        assert_eq!(parse_ps(ps)[0].state, ContainerState::Exited);
        let ps = "aa\tvaiprog/amnezia-wg-3:latest\tx\t\tUp 3 seconds (Paused)\t2026\t";
        assert_eq!(parse_ps(ps)[0].state, ContainerState::Paused);
    }

    #[test]
    fn a_line_that_is_not_a_container_is_skipped_rather_than_half_parsed() {
        assert!(parse_ps("").is_empty());
        assert!(parse_ps("CONTAINER ID   IMAGE").is_empty());
        assert!(parse_ps("\n\n").is_empty());
    }

    #[test]
    fn the_ps_command_asks_for_stopped_containers_and_full_ids() {
        let c = ps_command();
        // A stopped node is the interesting case, and a truncated id cannot be
        // matched against the label filter's output.
        assert!(c.contains("--all"));
        assert!(c.contains("--no-trunc"));
        assert!(ps_label_command().contains(PROTOCOL_LABEL));
    }
}
