//! What privileges, devices, sysctls and ports one container was given, and
//! which image bytes it is running.
//!
//! This is the half of the evidence that comes from outside the container. It
//! answers "was it allowed to" where [`super::health`] answers "did it".

use std::collections::BTreeMap;

use super::discover::PublishedPort;
use super::host::{Host, safe_image, safe_name};
use super::image::parse_image_ref;
use super::logs::redact;
use crate::update::LocalImage;
use crate::{Error, Result};

/// The parts of `docker inspect` a diagnosis reasons about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inspect {
    pub id: String,
    pub name: String,
    pub image: String,
    pub image_id: String,
    pub state: String,
    pub running: bool,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub exit_code: i64,
    pub restart_count: i64,
    pub oom_killed: bool,
    pub privileged: bool,
    pub cap_add: Vec<String>,
    pub cap_drop: Vec<String>,
    /// `PathOnHost:PathInContainer` for each `--device`.
    pub devices: Vec<String>,
    pub sysctls: BTreeMap<String, String>,
    pub port_bindings: Vec<PublishedPort>,
    pub network_mode: String,
    /// Environment, with any secret-looking value already redacted.
    pub env: BTreeMap<String, String>,
    pub labels: BTreeMap<String, String>,
}

/// Capability names as one spelling.
///
/// Docker reports what it was given, and that is not one thing: the CLI takes
/// `--cap-add NET_ADMIN`, docker 29 stores `CAP_NET_ADMIN`, and compose files
/// in the wild use both. Comparing the raw string against `NET_ADMIN` reports a
/// correctly privileged container as unprivileged — which is exactly what this
/// module did until a real `docker inspect` was put in front of it.
fn normalised_capability(entry: &str) -> String {
    let e = entry.trim().to_ascii_uppercase();
    e.strip_prefix("CAP_").unwrap_or(&e).to_string()
}

impl Inspect {
    /// `--cap-add NET_ADMIN`, or `--privileged`, which implies it.
    pub fn has_net_admin(&self) -> bool {
        self.privileged
            || self.cap_add.iter().any(|c| {
                let n = normalised_capability(c);
                n == "NET_ADMIN" || n == "ALL"
            })
    }

    pub fn has_tun_device(&self) -> bool {
        self.privileged || self.devices.iter().any(|d| d.contains("/dev/net/tun"))
    }

    /// What the container was *started* with, which is not the same as what
    /// `/proc/sys` reads inside it — see [`super::health::Health::ip_forward`].
    pub fn ip_forward_sysctl(&self) -> Option<bool> {
        self.sysctls
            .get("net.ipv4.ip_forward")
            .map(|v| v.trim() == "1")
    }

    /// The interface name the entrypoint will have used.
    pub fn interface(&self) -> String {
        self.env
            .get("AWG_IFACE")
            .cloned()
            .unwrap_or_else(|| "awg0".to_string())
    }
}

pub fn inspect_command(container: &str) -> Result<String> {
    Ok(format!("docker inspect {}", safe_name(container)?))
}

fn string_list(v: Option<&serde_json::Value>) -> Vec<String> {
    v.and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn port_bindings(host: Option<&serde_json::Value>) -> Vec<PublishedPort> {
    let mut out = Vec::new();
    let Some(obj) = host
        .and_then(|h| h.get("PortBindings"))
        .and_then(serde_json::Value::as_object)
    else {
        return out;
    };
    for (spec, binds) in obj {
        let (port_text, protocol) = match spec.rsplit_once('/') {
            Some((p, proto)) => (p, proto.to_ascii_lowercase()),
            None => (spec.as_str(), "tcp".to_string()),
        };
        let Ok(container_port) = port_text.parse::<u16>() else {
            continue;
        };
        let list = binds.as_array().cloned().unwrap_or_default();
        if list.is_empty() {
            out.push(PublishedPort {
                host_ip: None,
                host_port: None,
                container_port,
                protocol: protocol.clone(),
            });
        }
        for b in list {
            out.push(PublishedPort {
                host_ip: b
                    .get("HostIp")
                    .and_then(|x| x.as_str())
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
                host_port: b
                    .get("HostPort")
                    .and_then(|x| x.as_str())
                    .and_then(|s| s.parse().ok()),
                container_port,
                protocol: protocol.clone(),
            });
        }
    }
    out
}

/// Parse `docker inspect`, which always returns an array.
pub fn parse_inspect(json: &str) -> Result<Inspect> {
    let v: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| Error::Config(format!("docker inspect did not return JSON: {e}")))?;
    let c = v
        .get(0)
        .ok_or_else(|| Error::Config("docker inspect returned an empty array".into()))?;

    let host = c.get("HostConfig");
    let state = c.get("State");
    let config = c.get("Config");

    let devices = host
        .and_then(|h| h.get("Devices"))
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .map(|d| {
                    format!(
                        "{}:{}",
                        d.get("PathOnHost").and_then(|x| x.as_str()).unwrap_or(""),
                        d.get("PathInContainer")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    let mut sysctls = BTreeMap::new();
    if let Some(obj) = host
        .and_then(|h| h.get("Sysctls"))
        .and_then(serde_json::Value::as_object)
    {
        for (k, v) in obj {
            sysctls.insert(k.clone(), v.as_str().unwrap_or("").to_string());
        }
    }

    // Environment holds AWG_ENDPOINT and friends; none of it is meant to be
    // secret, but it is not this module's job to be the one that finds out.
    let mut env = BTreeMap::new();
    for entry in string_list(config.and_then(|c| c.get("Env"))) {
        if let Some((k, v)) = entry.split_once('=') {
            env.insert(k.to_string(), redact(v));
        }
    }

    let mut labels = BTreeMap::new();
    if let Some(obj) = config
        .and_then(|c| c.get("Labels"))
        .and_then(serde_json::Value::as_object)
    {
        for (k, v) in obj {
            labels.insert(k.clone(), v.as_str().unwrap_or("").to_string());
        }
    }

    let text = |v: Option<&serde_json::Value>, key: &str| -> String {
        v.and_then(|v| v.get(key))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string()
    };

    Ok(Inspect {
        id: text(Some(c), "Id"),
        name: text(Some(c), "Name").trim_start_matches('/').to_string(),
        image: text(config, "Image"),
        image_id: text(Some(c), "Image"),
        state: text(state, "Status"),
        running: state
            .and_then(|s| s.get("Running"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        started_at: state
            .and_then(|s| s.get("StartedAt"))
            .and_then(|x| x.as_str())
            .map(str::to_string),
        finished_at: state
            .and_then(|s| s.get("FinishedAt"))
            .and_then(|x| x.as_str())
            .map(str::to_string),
        exit_code: state
            .and_then(|s| s.get("ExitCode"))
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0),
        restart_count: c
            .get("RestartCount")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0),
        oom_killed: state
            .and_then(|s| s.get("OOMKilled"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        privileged: host
            .and_then(|h| h.get("Privileged"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        cap_add: string_list(host.and_then(|h| h.get("CapAdd"))),
        cap_drop: string_list(host.and_then(|h| h.get("CapDrop"))),
        devices,
        sysctls,
        port_bindings: port_bindings(host),
        network_mode: text(host, "NetworkMode"),
        env,
        labels,
    })
}

pub fn inspect(host: &Host, container: &str) -> Result<Inspect> {
    let (out, err, code) = host.run_docker(&inspect_command(container)?)?;
    if code != 0 {
        return Err(Error::Ssh(format!(
            "`docker inspect {container}` failed (exit {code}): {}",
            err.trim()
        )));
    }
    parse_inspect(&out)
}

/// `docker image inspect`, for the digest the host is actually running.
pub fn image_inspect_command(reference: &str) -> Result<String> {
    Ok(format!("docker image inspect {}", safe_image(reference)?))
}

/// Turn `docker image inspect` into the shape [`crate::update`] compares.
pub fn parse_image_inspect(json: &str, reference: &str) -> Result<LocalImage> {
    let v: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| Error::Config(format!("docker image inspect did not return JSON: {e}")))?;
    let img = v
        .get(0)
        .ok_or_else(|| Error::Config("docker image inspect returned an empty array".into()))?;
    let r = parse_image_ref(reference)
        .ok_or_else(|| Error::Config(format!("cannot parse the image reference {reference}")))?;

    Ok(LocalImage {
        reference: reference.to_string(),
        hub_repository: r.hub_repository(),
        tag: r.tag.clone(),
        repo_digests: string_list(img.get("RepoDigests")),
        created: img
            .get("Created")
            .and_then(|x| x.as_str())
            .map(str::to_string),
        // The image's own build stamp, which for a locally built image is the
        // only honest answer to "how old is this".
        label_created: img
            .get("Config")
            .and_then(|c| c.get("Labels"))
            .and_then(|l| l.get("org.opencontainers.image.created"))
            .and_then(|x| x.as_str())
            .map(str::to_string),
    })
}

pub fn local_image(host: &Host, reference: &str) -> Result<LocalImage> {
    let (out, err, code) = host.run_docker(&image_inspect_command(reference)?)?;
    if code != 0 {
        return Err(Error::Ssh(format!(
            "`docker image inspect {reference}` failed (exit {code}): {}",
            err.trim()
        )));
    }
    parse_image_inspect(&out, reference)
}

#[cfg(test)]
mod tests {
    use super::super::image::PROTOCOL_LABEL;
    use super::*;

    pub(crate) const INSPECT: &str = r#"[{
      "Id": "9f2c",
      "Name": "/awg-server",
      "Image": "sha256:d478",
      "RestartCount": 2,
      "State": {"Status":"running","Running":true,"StartedAt":"2026-07-28T18:00:00Z","FinishedAt":"0001-01-01T00:00:00Z","ExitCode":0,"OOMKilled":false},
      "Config": {
        "Image": "vaiprog/amnezia-wg-3:latest",
        "Env": ["AWG_IFACE=awg0","PATH=/usr/bin","AWG_CLIENT_DNS=172.29.172.254"],
        "Labels": {"space.vai-rice.awg.protocol":"3.0"}
      },
      "HostConfig": {
        "Privileged": false,
        "CapAdd": ["NET_ADMIN"],
        "CapDrop": null,
        "NetworkMode": "bridge",
        "Devices": [{"PathOnHost":"/dev/net/tun","PathInContainer":"/dev/net/tun","CgroupPermissions":"rwm"}],
        "Sysctls": {"net.ipv4.ip_forward":"1"},
        "PortBindings": {"51820/udp":[{"HostIp":"","HostPort":"51820"}]}
      }
    }]"#;

    #[test]
    fn inspect_yields_exactly_the_privileges_a_diagnosis_reasons_about() {
        let i = parse_inspect(INSPECT).unwrap();
        assert_eq!(i.name, "awg-server");
        assert!(i.running);
        assert_eq!(i.restart_count, 2);
        assert!(i.has_net_admin());
        assert!(i.has_tun_device());
        assert_eq!(i.ip_forward_sysctl(), Some(true));
        assert_eq!(i.interface(), "awg0");
        assert_eq!(i.port_bindings.len(), 1);
        assert_eq!(i.port_bindings[0].host_port, Some(51820));
        assert_eq!(i.port_bindings[0].protocol, "udp");
        assert_eq!(i.labels[PROTOCOL_LABEL], "3.0");
        assert_eq!(i.env["AWG_CLIENT_DNS"], "172.29.172.254");
        assert_eq!(i.network_mode, "bridge");
        assert_eq!(i.image, "vaiprog/amnezia-wg-3:latest");
    }

    #[test]
    fn a_container_stripped_of_its_privileges_reads_as_stripped() {
        let stripped = INSPECT
            .replace("\"CapAdd\": [\"NET_ADMIN\"],", "\"CapAdd\": null,")
            .replace(
                "\"Devices\": [{\"PathOnHost\":\"/dev/net/tun\",\"PathInContainer\":\"/dev/net/tun\",\"CgroupPermissions\":\"rwm\"}],",
                "\"Devices\": [],",
            );
        let i = parse_inspect(&stripped).unwrap();
        assert!(!i.has_net_admin());
        assert!(!i.has_tun_device());
        assert_eq!(i.ip_forward_sysctl(), Some(true));
    }

    #[test]
    fn a_capability_is_recognised_whichever_way_docker_spelled_it() {
        // docker 29 stores what the CLI was given as `CAP_NET_ADMIN`; older
        // daemons and compose files say `NET_ADMIN`. Both are the same grant,
        // and reading only one spelling calls a working container broken.
        for spelling in ["NET_ADMIN", "CAP_NET_ADMIN", "cap_net_admin", "net_admin"] {
            let i = parse_inspect(&INSPECT.replace("\"NET_ADMIN\"", &format!("\"{spelling}\"")))
                .unwrap();
            assert!(i.has_net_admin(), "{spelling} was not recognised");
        }
        for other in ["CAP_SYS_ADMIN", "NET_RAW", ""] {
            let i =
                parse_inspect(&INSPECT.replace("\"NET_ADMIN\"", &format!("\"{other}\""))).unwrap();
            assert!(!i.has_net_admin(), "{other} was mistaken for NET_ADMIN");
        }
        // `ALL` covers it, however it is spelled.
        let i = parse_inspect(&INSPECT.replace("\"NET_ADMIN\"", "\"CAP_ALL\"")).unwrap();
        assert!(i.has_net_admin());
    }

    #[test]
    fn a_privileged_container_counts_as_having_everything() {
        let i = parse_inspect(&INSPECT.replace("\"Privileged\": false", "\"Privileged\": true"))
            .unwrap();
        assert!(i.has_net_admin());
        assert!(i.has_tun_device());
    }

    #[test]
    fn a_secret_in_the_environment_does_not_survive_the_inspect() {
        let key = "yNMDBJ4Vd3nZuJ2FZ1ChNTvHNQg1KgLpOaOtQC8LSXY=";
        let with_secret = INSPECT.replace(
            "\"PATH=/usr/bin\"",
            &format!("\"AWG_PRIVATE_KEY={key}\", \"PATH=/usr/bin\""),
        );
        let i = parse_inspect(&with_secret).unwrap();
        assert!(!format!("{i:?}").contains(key), "a key reached Inspect");
    }

    #[test]
    fn malformed_output_is_an_error_rather_than_an_empty_verdict() {
        assert!(parse_inspect("not json").is_err());
        assert!(parse_inspect("[]").is_err());
        assert!(parse_image_inspect("[]", "x/y:z").is_err());
    }

    const IMAGE: &str = r#"[{
      "Id": "sha256:d478",
      "RepoTags": ["vaiprog/amnezia-wg-3:latest"],
      "RepoDigests": ["vaiprog/amnezia-wg-3@sha256:d4782548"],
      "Created": "2026-07-28T20:42:46.902542441+03:00",
      "Config": {"Labels": {"org.opencontainers.image.created":"2026-07-28T17:37:23Z"}}
    }]"#;

    #[test]
    fn an_image_inspect_carries_the_digest_and_both_dates() {
        let l = parse_image_inspect(IMAGE, "vaiprog/amnezia-wg-3:latest").unwrap();
        assert_eq!(l.hub_repository.as_deref(), Some("vaiprog/amnezia-wg-3"));
        assert_eq!(l.tag, "latest");
        assert_eq!(l.digest(), Some("sha256:d4782548"));
        assert_eq!(l.label_created.as_deref(), Some("2026-07-28T17:37:23Z"));
        assert!(l.created.unwrap().starts_with("2026-07-28T20:42:46"));
    }

    #[test]
    fn shell_metacharacters_never_reach_a_command() {
        assert!(inspect_command("awg; rm -rf /").is_err());
        assert!(image_inspect_command("a`b`").is_err());
        assert_eq!(
            inspect_command("awg-server").unwrap(),
            "docker inspect awg-server"
        );
        assert_eq!(
            image_inspect_command("vaiprog/amnezia-wg-3:latest").unwrap(),
            "docker image inspect vaiprog/amnezia-wg-3:latest"
        );
    }
}
