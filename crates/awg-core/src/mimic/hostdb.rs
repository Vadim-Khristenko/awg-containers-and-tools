//! The hosts a mimicry packet may name, with facts attached.
//!
//! The pools used to be flat lists of strings, picked once and never
//! re-checked, so a host that dropped HTTP/3 stayed in the QUIC pool and SIP
//! packets named hosts that speak no SIP. Here a host is a record of what
//! Architect's probe established about it, and a pool is a query: what the
//! profile needs of the host (its [`Role`]) and where the client is (its
//! [`Region`]), since a name is only plausible if a client there would contact
//! it.
//!
//! The data is `hosts.tsv`, written by `scripts/hosts-from-architect.ts` from
//! Architect's `src/shared/domains.ts`; the rules below are that file's
//! `meetsRole`, `findDomains` and `pickHost`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use crate::rng::Rng;

const DATA: &str = include_str!("hosts.tsv");

/// Where a host is plausible traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Region {
    Ru,
    Global,
    Eu,
    Uk,
    By,
    Cn,
}

impl Region {
    pub const ALL: [Region; 6] = [
        Region::Ru,
        Region::Global,
        Region::Eu,
        Region::Uk,
        Region::By,
        Region::Cn,
    ];

    pub fn id(&self) -> &'static str {
        match self {
            Region::Ru => "ru",
            Region::Global => "global",
            Region::Eu => "eu",
            Region::Uk => "uk",
            Region::By => "by",
            Region::Cn => "cn",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().to_ascii_lowercase();
        Region::ALL.into_iter().find(|r| r.id() == s)
    }

    fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// What a profile needs of the host it names. The requirements are the
/// protocols' own: a QUIC packet aimed at a host with no HTTP/3 is a packet
/// nobody could have sent, and an unknown SIP host named in a SIP packet is
/// the imitation that falls apart under inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// HTTP/3 answered.
    Quic,
    /// TLS 1.3 answered, which is what the imitated ClientHello offers.
    Tls,
    /// A DTLS service: WebRTC and VPN endpoints, not web servers.
    Dtls,
    /// A SIP service, normally on 5060.
    Sip,
    /// A STUN or TURN service, normally on 3478.
    Stun,
    /// A name to ask about: it has to answer the query type being asked.
    Dns,
}

impl Role {
    pub const ALL: [Role; 6] = [
        Role::Quic,
        Role::Tls,
        Role::Dtls,
        Role::Sip,
        Role::Stun,
        Role::Dns,
    ];

    pub fn id(&self) -> &'static str {
        match self {
            Role::Quic => "quic",
            Role::Tls => "tls",
            Role::Dtls => "dtls",
            Role::Sip => "sip",
            Role::Stun => "stun",
            Role::Dns => "dns",
        }
    }
}

/// The DNS question types the probe records answers for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsType {
    A,
    Aaaa,
    Mx,
    Txt,
    Ns,
    Soa,
    Cname,
    Srv,
    Https,
    Caa,
}

impl DnsType {
    const ALL: [DnsType; 10] = [
        DnsType::A,
        DnsType::Aaaa,
        DnsType::Mx,
        DnsType::Txt,
        DnsType::Ns,
        DnsType::Soa,
        DnsType::Cname,
        DnsType::Srv,
        DnsType::Https,
        DnsType::Caa,
    ];

    fn name(self) -> &'static str {
        match self {
            DnsType::A => "A",
            DnsType::Aaaa => "AAAA",
            DnsType::Mx => "MX",
            DnsType::Txt => "TXT",
            DnsType::Ns => "NS",
            DnsType::Soa => "SOA",
            DnsType::Cname => "CNAME",
            DnsType::Srv => "SRV",
            DnsType::Https => "HTTPS",
            DnsType::Caa => "CAA",
        }
    }

    fn bit(self) -> u16 {
        1 << self as u16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Fact {
    Yes,
    No,
    Unknown,
}

impl Fact {
    fn from_char(c: char) -> Self {
        match c {
            'y' => Fact::Yes,
            'n' => Fact::No,
            _ => Fact::Unknown,
        }
    }

    fn ok(self, allow_unknown: bool) -> bool {
        self == Fact::Yes || (allow_unknown && self == Fact::Unknown)
    }
}

/// One host and what is known about it.
#[derive(Debug, Clone)]
pub struct HostRecord {
    pub host: &'static str,
    regions: u8,
    tls13: Fact,
    h3: Fact,
    dtls: Fact,
    sip: Fact,
    stun: Fact,
    /// Query types the name answers; 0 when nobody asked.
    dns_answers: u16,
    whitelisted_in: u8,
}

impl HostRecord {
    pub fn in_region(&self, region: Region) -> bool {
        self.regions & region.bit() != 0
    }

    pub fn whitelisted_in(&self, region: Region) -> bool {
        self.whitelisted_in & region.bit() != 0
    }

    /// Whether the host meets what `role` needs.
    pub fn meets(&self, role: Role, allow_unknown: bool, dns_type: Option<DnsType>) -> bool {
        match role {
            Role::Quic => self.h3.ok(allow_unknown),
            Role::Tls => self.tls13.ok(allow_unknown),
            Role::Dtls => self.dtls.ok(allow_unknown),
            Role::Sip => self.sip.ok(allow_unknown),
            Role::Stun => self.stun.ok(allow_unknown),
            // A query for MX on a name that has never had one is a question
            // no resolver is asked twice.
            Role::Dns => match (self.dns_answers, dns_type) {
                (0, _) => allow_unknown,
                (answers, Some(t)) => answers & t.bit() != 0,
                (_, None) => true,
            },
        }
    }
}

fn regions_mask(field: &str) -> u8 {
    field
        .split(',')
        .filter_map(Region::parse)
        .fold(0, |m, r| m | r.bit())
}

fn types_mask(field: &str) -> u16 {
    field
        .split(',')
        .filter_map(|t| DnsType::ALL.into_iter().find(|x| x.name() == t))
        .fold(0, |m, t| m | t.bit())
}

/// Every record, parsed once.
pub fn records() -> &'static [HostRecord] {
    static RECORDS: OnceLock<Vec<HostRecord>> = OnceLock::new();
    RECORDS.get_or_init(|| {
        DATA.lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter_map(|line| {
                let f: Vec<&'static str> = line.split('\t').collect();
                let facts: Vec<Fact> = f.get(2)?.chars().map(Fact::from_char).collect();
                if facts.len() != 8 {
                    return None;
                }
                Some(HostRecord {
                    host: f[0],
                    regions: regions_mask(f[1]),
                    tls13: facts[0],
                    h3: facts[2],
                    dtls: facts[4],
                    sip: facts[5],
                    stun: facts[6],
                    dns_answers: types_mask(f.get(4)?),
                    whitelisted_in: regions_mask(f.get(6)?),
                })
            })
            .collect()
    })
}

/// What a profile asks of the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HostQuery {
    pub role: Role,
    /// `None` means any region.
    pub region: Option<Region>,
    pub dns_type: Option<DnsType>,
    /// Only names on this region's whitelist: what is still moving when the
    /// network is degraded, which is when this tool gets used.
    pub whitelisted_in: Option<Region>,
    /// Accept hosts whose facts were never established.
    pub allow_unknown: bool,
}

impl HostQuery {
    pub fn new(role: Role) -> Self {
        Self {
            role,
            region: None,
            dns_type: None,
            whitelisted_in: None,
            allow_unknown: false,
        }
    }
}

/// A query's answer, shared between everyone who asked it.
pub type Hosts = Arc<[&'static str]>;

/// Every host matching a query, in database order.
///
/// The table is fixed at build time, so the same query always has the same
/// answer and there is nothing to invalidate. Cached because the callers are
/// not one-off: the generator asks once per packet.
pub fn hosts_for(q: &HostQuery) -> Hosts {
    static ANSWERS: OnceLock<Mutex<HashMap<HostQuery, Hosts>>> = OnceLock::new();
    let answers = ANSWERS.get_or_init(Default::default);
    if let Some(found) = answers.lock().ok().and_then(|m| m.get(q).cloned()) {
        return found;
    }
    let found: Hosts = records()
        .iter()
        .filter(|r| q.region.is_none_or(|g| r.in_region(g)))
        .filter(|r| q.whitelisted_in.is_none_or(|g| r.whitelisted_in(g)))
        .filter(|r| r.meets(q.role, q.allow_unknown, q.dns_type))
        .map(|r| r.host)
        .collect();
    if let Ok(mut m) = answers.lock() {
        m.insert(*q, found.clone());
    }
    found
}

/// One host matching a query.
///
/// Widens rather than returning nothing, because a profile with no host to
/// name cannot build its packet at all: first hosts whose facts are unknown,
/// then any region and no whitelist.
pub fn pick(rng: &mut impl Rng, q: &HostQuery) -> &'static str {
    let tries = [
        *q,
        HostQuery {
            allow_unknown: true,
            ..*q
        },
        HostQuery {
            region: None,
            whitelisted_in: None,
            allow_unknown: true,
            ..*q
        },
    ];
    for t in tries {
        let found = hosts_for(&t);
        if !found.is_empty() {
            return found[rng.range(0, found.len() as u32 - 1) as usize];
        }
    }
    records().first().map_or("example.com", |r| r.host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::SeededRng;

    #[test]
    fn the_whole_table_parses() {
        let all = records();
        let lines = DATA
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .count();
        assert_eq!(all.len(), lines, "a line was dropped");
        assert!(all.len() > 2000);
        assert!(all.iter().all(|r| r.regions != 0), "a host with no region");
    }

    #[test]
    fn every_role_has_verified_hosts_in_every_region_that_matters() {
        for role in Role::ALL {
            assert!(
                !hosts_for(&HostQuery::new(role)).is_empty(),
                "{}",
                role.id()
            );
        }
        for region in [Region::Ru, Region::Global] {
            for role in [Role::Quic, Role::Tls, Role::Dns] {
                let q = HostQuery {
                    region: Some(region),
                    ..HostQuery::new(role)
                };
                assert!(
                    !hosts_for(&q).is_empty(),
                    "{} in {}",
                    role.id(),
                    region.id()
                );
            }
        }
    }

    #[test]
    fn a_picked_host_meets_its_role() {
        let mut rng = SeededRng::new(1);
        for role in Role::ALL {
            for _ in 0..50 {
                let host = pick(&mut rng, &HostQuery::new(role));
                let rec = records().iter().find(|r| r.host == host).unwrap();
                assert!(rec.meets(role, false, None), "{host} for {}", role.id());
            }
        }
    }

    #[test]
    fn a_dns_name_answers_the_type_it_is_asked_about() {
        let mut rng = SeededRng::new(2);
        for t in [DnsType::A, DnsType::Aaaa] {
            let q = HostQuery {
                dns_type: Some(t),
                ..HostQuery::new(Role::Dns)
            };
            for _ in 0..50 {
                let host = pick(&mut rng, &q);
                let rec = records().iter().find(|r| r.host == host).unwrap();
                assert!(
                    rec.dns_answers & t.bit() != 0,
                    "{host} does not answer {}",
                    t.name()
                );
            }
        }
    }

    #[test]
    fn a_region_and_a_whitelist_narrow_the_pool() {
        let ru = HostQuery {
            region: Some(Region::Ru),
            whitelisted_in: Some(Region::Ru),
            ..HostQuery::new(Role::Tls)
        };
        let found = hosts_for(&ru);
        assert!(!found.is_empty());
        for &host in found.iter() {
            let rec = records().iter().find(|r| r.host == host).unwrap();
            assert!(rec.in_region(Region::Ru) && rec.whitelisted_in(Region::Ru));
        }
    }

    #[test]
    fn an_empty_query_widens_instead_of_failing() {
        // Nothing in the table is whitelisted in China for STUN; the pick
        // still returns a STUN-capable name rather than nothing.
        let q = HostQuery {
            region: Some(Region::Cn),
            whitelisted_in: Some(Region::Cn),
            ..HostQuery::new(Role::Stun)
        };
        let host = pick(&mut SeededRng::new(3), &q);
        let rec = records().iter().find(|r| r.host == host).unwrap();
        assert!(rec.meets(Role::Stun, true, None));
    }
}
