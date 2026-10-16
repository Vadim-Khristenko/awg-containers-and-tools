//! The tunnel's resolver, from outside it.
//!
//! The resolver container rebuilds its config whenever a watched file changes
//! (see `containers/entrypoint-dns.sh`), so everything here is a read of what
//! it generated or a write to the two lists it keeps on its own volume, both
//! through the `awg-dns-list` script the image ships, so no command here needs
//! quoting in any shell: cmd on Windows, a local sh and an SSH session run
//! them alike. Names are checked before anything is run.

use std::collections::BTreeMap;

use super::host::{Host, safe_name};
use crate::{Error, Result};

/// Which managed list a name goes on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum List {
    Block,
    Allow,
}

impl List {
    fn word(self) -> &'static str {
        match self {
            List::Block => "block",
            List::Allow => "allow",
        }
    }
}

/// What the resolver is doing, read off its generated config and statistics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsStatus {
    /// `recursive` or `forward`.
    pub mode: String,
    pub blocked: u64,
    pub allowed: u64,
    /// Names in the managed lists, as `awg-tool dns` wrote them.
    pub managed_block: Vec<String>,
    pub managed_allow: Vec<String>,
    /// `unbound-control stats_noreset`, refreshed every minute.
    pub stats: BTreeMap<String, String>,
    /// Forwarded zones, `zone server...` each.
    pub zones: Vec<String>,
    /// The chain's counters, `chain.N.answered` and the like.
    pub chain: BTreeMap<String, String>,
}

/// One resolver in the chain, as its counters tell it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChainHop {
    pub addr: String,
    pub answered: u64,
    /// Passed over, for any reason, timeouts included.
    pub passed: u64,
    pub timeouts: u64,
}

impl DnsStatus {
    /// The chain in order, empty when there is none.
    pub fn chain_hops(&self) -> Vec<ChainHop> {
        let n: usize = self
            .chain
            .get("chain.upstreams")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let num =
            |k: String| -> u64 { self.chain.get(&k).and_then(|v| v.parse().ok()).unwrap_or(0) };
        (0..n.min(64))
            .map(|i| {
                let passed = [
                    "timeout", "servfail", "refused", "nxdomain", "sinkhole", "invalid",
                ]
                .iter()
                .map(|r| num(format!("chain.{i}.{r}")))
                .sum();
                ChainHop {
                    // The inner resolver goes by the name chain.conf gives it.
                    addr: match self.chain.get(&format!("chain.{i}.addr")) {
                        Some(a) if a == "127.0.0.1:5301" => "default".to_string(),
                        Some(a) => a.clone(),
                        None => String::new(),
                    },
                    answered: num(format!("chain.{i}.answered")),
                    passed,
                    timeouts: num(format!("chain.{i}.timeout")),
                }
            })
            .collect()
    }

    pub fn stat(&self, key: &str) -> Option<u64> {
        self.stats
            .get(key)
            .and_then(|v| v.split('.').next()?.parse().ok())
    }
}

/// A name to block, allow or look up: letters, digits, `-`, `_` and dots,
/// at least one dot. Lowercased, without a trailing dot.
pub fn dns_name(name: &str) -> Result<String> {
    let n = name.trim().trim_end_matches('.').to_ascii_lowercase();
    let ok = n.contains('.')
        && n.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        });
    if !ok || n.len() > 253 {
        return Err(Error::Config(format!("{name:?} is not a domain name")));
    }
    Ok(n)
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

pub fn status_command(container: &str) -> Result<String> {
    Ok(format!(
        "docker exec {} awg-dns-list status",
        safe_name(container)?
    ))
}

pub fn parse_status(text: &str) -> DnsStatus {
    let mut s = DnsStatus::default();
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("mode=") {
            s.mode = v.to_string();
        } else if let Some(v) = line.strip_prefix("blocked=") {
            s.blocked = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("allowed=") {
            s.allowed = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("block:") {
            if !v.trim().is_empty() {
                s.managed_block.push(v.trim().to_string());
            }
        } else if let Some(v) = line.strip_prefix("allow:") {
            if !v.trim().is_empty() {
                s.managed_allow.push(v.trim().to_string());
            }
        } else if let Some(v) = line.strip_prefix("zone:") {
            if !v.trim().is_empty() {
                s.zones.push(v.trim().to_string());
            }
        } else if let Some(v) = line.strip_prefix("chain:")
            && let Some((k, val)) = v.split_once('=')
        {
            s.chain.insert(k.to_string(), val.to_string());
        } else if let Some(v) = line.strip_prefix("stat:")
            && let Some((k, val)) = v.split_once('=')
        {
            s.stats.insert(k.to_string(), val.to_string());
        }
    }
    s
}

pub fn status(host: &Host<'_>, container: &str) -> Result<DnsStatus> {
    Ok(parse_status(&run(
        host,
        &status_command(container)?,
        "reading the resolver",
    )?))
}

/// Put a name on a managed list, or take it off. Idempotent either way.
pub fn edit_command(container: &str, list: List, name: &str, add: bool) -> Result<String> {
    Ok(format!(
        "docker exec {} awg-dns-list {} {} {}",
        safe_name(container)?,
        if add { "add" } else { "rm" },
        list.word(),
        dns_name(name)?
    ))
}

pub fn edit(host: &Host<'_>, container: &str, list: List, name: &str, add: bool) -> Result<String> {
    run(
        host,
        &edit_command(container, list, name, add)?,
        "changing the list",
    )
    .map(|s| s.trim().to_string())
}

/// What the resolver answers for a name, asked from inside its container.
pub fn query_command(container: &str, name: &str) -> Result<String> {
    Ok(format!(
        "docker exec {} awg-dns-list query {}",
        safe_name(container)?,
        dns_name(name)?
    ))
}

/// The answer lines of a busybox nslookup: addresses after the server block,
/// names it was aliased to, or the reason there is none.
pub fn parse_answer(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut past_server = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with("Server:") {
            continue;
        }
        if let Some(a) = line.strip_prefix("Address:") {
            if past_server {
                out.push(a.trim().to_string());
            }
            past_server = true;
        } else if line.contains("canonical name")
            || line.contains("NXDOMAIN")
            || line.contains("timed out")
        {
            out.push(line.to_string());
        }
    }
    out
}

pub fn query(host: &Host<'_>, container: &str, name: &str) -> Result<Vec<String>> {
    Ok(parse_answer(&run(
        host,
        &query_command(container, name)?,
        "asking the resolver",
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_domain_names_reach_the_shell() {
        assert_eq!(dns_name("Ads.Example.COM.").unwrap(), "ads.example.com");
        for bad in [
            "example",
            "a b.com",
            "x;reboot.com",
            "$(id).com",
            "",
            "..",
            "a..b",
            "x'.com",
        ] {
            assert!(dns_name(bad).is_err(), "{bad:?}");
        }
        // No quoting anywhere, so the same command works through cmd on
        // Windows, a local sh and an SSH session alike.
        assert_eq!(
            edit_command("awg-dns", List::Allow, "WWW.example.com", true).unwrap(),
            "docker exec awg-dns awg-dns-list add allow www.example.com"
        );
        assert_eq!(
            edit_command("awg-dns", List::Block, "x.com", false).unwrap(),
            "docker exec awg-dns awg-dns-list rm block x.com"
        );
        assert!(edit_command("awg dns", List::Block, "x.com", true).is_err());
    }

    #[test]
    fn the_chain_and_the_zones_read_back() {
        let s = parse_status(
            "mode=recursive\nzone:geek. 185.121.177.177\nchain:chain.upstreams=2\n\
             chain:chain.0.addr=127.0.0.1:5301\nchain:chain.0.answered=90\nchain:chain.0.nxdomain=7\n\
             chain:chain.0.timeout=1\nchain:chain.1.addr=185.121.177.177:53\nchain:chain.1.answered=7\n",
        );
        assert_eq!(s.zones, ["geek. 185.121.177.177"]);
        let hops = s.chain_hops();
        assert_eq!(hops.len(), 2);
        assert_eq!(
            (hops[0].answered, hops[0].passed, hops[0].timeouts),
            (90, 8, 1)
        );
        assert_eq!(hops[0].addr, "default");
        assert_eq!(hops[1].addr, "185.121.177.177:53");
        assert!(parse_status("mode=forward\n").chain_hops().is_empty());
    }

    #[test]
    fn the_status_reads_back() {
        let s = parse_status(
            "mode=forward\nblocked=3\nallowed=1\nblock:example.com\nallow:www.example.com\n\
             stat:total.num.queries=42\nstat:total.num.cachehits=40\n",
        );
        assert_eq!(s.mode, "forward");
        assert_eq!((s.blocked, s.allowed), (3, 1));
        assert_eq!(s.managed_block, ["example.com"]);
        assert_eq!(s.managed_allow, ["www.example.com"]);
        assert_eq!(s.stat("total.num.queries"), Some(42));
    }

    #[test]
    fn an_answer_skips_the_server_lines() {
        let text = "Server:\t\t127.0.0.1\nAddress:\t127.0.0.1:53\n\nNon-authoritative answer:\n\
                    Name:\twww.example.com\nAddress: 104.20.23.154\n";
        assert_eq!(parse_answer(text), ["104.20.23.154"]);
        let nx = "Server:\t\t127.0.0.1\nAddress:\t127.0.0.1:53\n\n** server can't find x.com: NXDOMAIN\n";
        assert_eq!(parse_answer(nx).len(), 1);
    }
}
