//! Peers on a running node, through the `awg-peer` tool the node image ships.
//!
//! The node already knows how to issue a client: it generates the key inside
//! the container, prints the config once and keeps only what the server needs
//! after a restart. So this module does not reimplement that, it runs it, on
//! this machine or over SSH, and reads back what it printed. Everything that
//! reaches the shell is checked against a narrow character set first, the
//! same one `awg-peer` enforces on its side.

use super::host::{Host, safe_name};
use crate::{Error, Result};

/// One row of `awg-peer list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRow {
    pub label: String,
    pub public_key: String,
    pub allowed_ips: String,
    /// RFC 3339, or `never`.
    pub last_handshake: String,
}

/// A label `awg-peer` accepts: `A-Z a-z 0-9 . _ -`.
pub fn peer_label(label: &str) -> Result<&str> {
    let l = label.trim();
    if l.is_empty()
        || !l
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(Error::Config(format!(
            "{l:?} is not a usable peer label: A-Z a-z 0-9 . _ - only"
        )));
    }
    Ok(l)
}

/// An address for the new peer: an IPv4 or IPv6 literal, nothing a shell
/// could read as anything else.
fn peer_address(ip: &str) -> Result<&str> {
    let ip = ip.trim();
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Err(Error::Config(format!("{ip:?} is not an IP address")));
    }
    Ok(ip)
}

/// A label or a base64 public key, as `awg-peer rm` takes either.
fn peer_ref(who: &str) -> Result<&str> {
    let w = who.trim();
    if w.is_empty()
        || !w
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '/' | '='))
    {
        return Err(Error::Config(format!(
            "{w:?} is neither a peer label nor a public key"
        )));
    }
    Ok(w)
}

pub fn add_command(container: &str, label: &str, ip: Option<&str>) -> Result<String> {
    let mut cmd = format!(
        "docker exec {} awg-peer add {}",
        safe_name(container)?,
        peer_label(label)?
    );
    if let Some(ip) = ip {
        cmd.push(' ');
        cmd.push_str(peer_address(ip)?);
    }
    Ok(cmd)
}

pub fn list_command(container: &str) -> Result<String> {
    Ok(format!(
        "docker exec {} awg-peer list",
        safe_name(container)?
    ))
}

pub fn remove_command(container: &str, who: &str) -> Result<String> {
    Ok(format!(
        "docker exec {} awg-peer rm {}",
        safe_name(container)?,
        peer_ref(who)?
    ))
}

fn run(host: &Host<'_>, cmd: &str, what: &str) -> Result<String> {
    let (out, err, code) = host.run_docker(cmd)?;
    if code != 0 {
        let reason = err
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("no output")
            .trim_start_matches("!! ");
        return Err(Error::Config(format!("{what}: {reason}")));
    }
    Ok(out)
}

/// Issue a new peer and return the client config the node printed.
///
/// The config holds the client's private key, generated inside the container
/// and printed exactly once: the caller is the only place it now exists.
pub fn add(host: &Host<'_>, container: &str, label: &str, ip: Option<&str>) -> Result<String> {
    let out = run(host, &add_command(container, label, ip)?, "adding the peer")?;
    if !out.contains("[Interface]") {
        return Err(Error::Config(
            "the node answered without a client config".into(),
        ));
    }
    Ok(out)
}

pub fn list(host: &Host<'_>, container: &str) -> Result<Vec<PeerRow>> {
    Ok(parse_list(&run(
        host,
        &list_command(container)?,
        "listing peers",
    )?))
}

pub fn remove(host: &Host<'_>, container: &str, who: &str) -> Result<String> {
    run(host, &remove_command(container, who)?, "removing the peer").map(|s| s.trim().to_string())
}

/// `awg-peer list`: a header row, then label, key, allowed IPs, handshake.
pub fn parse_list(text: &str) -> Vec<PeerRow> {
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with("LABEL"))
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            Some(PeerRow {
                label: f.next()?.to_string(),
                public_key: f.next()?.to_string(),
                allowed_ips: f.next()?.to_string(),
                last_handshake: f.next().unwrap_or("never").to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_carry_only_what_the_node_tool_accepts() {
        assert_eq!(
            add_command("awg-server", "laptop", None).unwrap(),
            "docker exec awg-server awg-peer add laptop"
        );
        assert_eq!(
            add_command("awg-server", "phone.1", Some("10.8.1.9")).unwrap(),
            "docker exec awg-server awg-peer add phone.1 10.8.1.9"
        );
        for bad in ["a b", "x;rm -rf /", "$(id)", "", "lap`top`"] {
            assert!(add_command("awg-server", bad, None).is_err(), "{bad:?}");
        }
        assert!(add_command("awg-server", "ok", Some("10.0.0.1; reboot")).is_err());
        assert!(add_command("awg server", "ok", None).is_err());
        assert_eq!(
            remove_command("awg-server", "7DHFY2VYRZ7Ag+K7C6X0i9FfHkw+q4H0dqIiRCyEXHM=").unwrap(),
            "docker exec awg-server awg-peer rm 7DHFY2VYRZ7Ag+K7C6X0i9FfHkw+q4H0dqIiRCyEXHM="
        );
        assert!(remove_command("awg-server", "x && y").is_err());
    }

    #[test]
    fn the_list_reads_back_as_rows() {
        let text = "LABEL            PUBLIC_KEY                                   ALLOWED_IPS            LAST_HANDSHAKE\n\
                    laptop           7DHFY2VYRZ7Ag+K7C6X0i9FfHkw+q4H0dqIiRCyEXHM= 10.8.1.2/32            2026-10-08T10:00:00Z\n\
                    (unlabelled)     0RSyG3nCXLBLGvNGqIzfhAqxV5s+RBgs1cq5AhCUcng= 10.8.1.3/32            never\n";
        let rows = parse_list(text);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].label, "laptop");
        assert_eq!(rows[0].allowed_ips, "10.8.1.2/32");
        assert_eq!(rows[1].last_handshake, "never");
    }
}
