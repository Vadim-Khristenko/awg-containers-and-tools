//! awg-dns-chain: ask a list of DNS upstreams in order, and move on when one
//! cannot answer.
//!
//! It sits behind the resolver's unbound, which keeps doing what it does (the
//! .vpn zone, the block and allow lists, the cache) and forwards everything
//! else here. Each query goes to the first upstream; the answer is passed back
//! unless it is one this chain was told not to accept:
//!
//! | the upstream answers      | reason       | on by default |
//! |---------------------------|--------------|---------------|
//! | nothing, in time          | `timeout`    | always        |
//! | SERVFAIL                  | `servfail`   | yes           |
//! | REFUSED                   | `refused`    | yes           |
//! | NXDOMAIN                  | `nxdomain`   | yes           |
//! | only sinkhole addresses   | `sinkhole`   | yes           |
//!
//! and then the next upstream is asked. A name that one resolver does not know
//! (a TLD outside the ICANN root, say) or blocks with 0.0.0.0 is looked up
//! further down the list. When every upstream fell through, the first answer
//! that came back at all is the one returned, so a name that does not exist
//! anywhere still reads as NXDOMAIN rather than as a failure.
//!
//! A silent upstream is not waited out before the next is asked: after the
//! hedge delay (400 ms by default) the next one is asked alongside it. The
//! order still decides for twice that long: an earlier upstream that answers
//! within it wins over a quicker later one. Past it, an acceptable answer
//! from further down is taken rather than waiting out a resolver that is
//! down.
//!
//! An answer is used only when it came from the address it was asked of, with
//! the query's id and the query's own question; anything else is ignored as
//! if it never arrived.
//!
//! Counts, never names, go to the stats file: how many queries, and per
//! upstream how many it answered and why it was passed over.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const RCODE_SERVFAIL: u8 = 2;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_REFUSED: u8 = 5;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_OPT: u16 = 41;

/// Why an answer was passed over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Timeout,
    Servfail,
    Refused,
    Nxdomain,
    Sinkhole,
    /// Not an answer to this query at all.
    Invalid,
}

impl Reason {
    const ALL: [Reason; 6] = [
        Reason::Timeout,
        Reason::Servfail,
        Reason::Refused,
        Reason::Nxdomain,
        Reason::Sinkhole,
        Reason::Invalid,
    ];

    fn name(self) -> &'static str {
        match self {
            Reason::Timeout => "timeout",
            Reason::Servfail => "servfail",
            Reason::Refused => "refused",
            Reason::Nxdomain => "nxdomain",
            Reason::Sinkhole => "sinkhole",
            Reason::Invalid => "invalid",
        }
    }

    fn index(self) -> usize {
        Reason::ALL.iter().position(|r| *r == self).unwrap_or(0)
    }

    fn parse(s: &str) -> Option<Reason> {
        Reason::ALL.into_iter().find(|r| r.name() == s)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Next(Reason),
}

/// An address or a CIDR range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Net {
    addr: IpAddr,
    prefix: u8,
}

impl Net {
    pub fn parse(s: &str) -> Option<Net> {
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p.parse::<u8>().ok()?)),
            None => (s, None),
        };
        let addr: IpAddr = a.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = p.unwrap_or(max);
        (prefix <= max).then_some(Net { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let bits = |ip: IpAddr| -> u128 {
            match ip {
                IpAddr::V4(v) => u32::from(v) as u128,
                IpAddr::V6(v) => u128::from(v),
            }
        };
        if self.addr.is_ipv4() != ip.is_ipv4() {
            return false;
        }
        let width = if ip.is_ipv4() { 32 } else { 128 };
        if self.prefix == 0 {
            return true;
        }
        let shift = width - self.prefix as u32;
        (bits(self.addr) >> shift) == (bits(ip) >> shift)
    }
}

/// What a resolver answers when it blocks a name instead of saying it does
/// not exist.
pub fn default_sinkholes() -> Vec<Net> {
    ["0.0.0.0/32", "127.0.0.0/8", "::/128", "::1/128"]
        .iter()
        .filter_map(|s| Net::parse(s))
        .collect()
}

#[derive(Debug, Clone)]
pub struct Policy {
    /// Reasons that move on to the next upstream. A timeout always does.
    pub fall_on: Vec<Reason>,
    pub sinkholes: Vec<Net>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            fall_on: Reason::ALL.to_vec(),
            sinkholes: default_sinkholes(),
        }
    }
}

fn u16_at(m: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*m.get(at)?, *m.get(at + 1)?]))
}

/// Past one name at `at`, compressed or not.
fn skip_name(m: &[u8], mut at: usize) -> Option<usize> {
    for _ in 0..128 {
        let len = *m.get(at)?;
        if len & 0xc0 == 0xc0 {
            return Some(at + 2);
        }
        if len & 0xc0 != 0 {
            return None;
        }
        at += 1;
        if len == 0 {
            return Some(at);
        }
        at += len as usize;
    }
    None
}

/// The end of the question section: one question, as every query has.
pub fn question_end(m: &[u8]) -> Option<usize> {
    if m.len() < 12 || u16_at(m, 4)? != 1 {
        return None;
    }
    let end = skip_name(m, 12)? + 4;
    (end <= m.len()).then_some(end)
}

/// The UDP payload size a query says its sender takes, from its OPT record.
pub fn edns_size(q: &[u8]) -> Option<usize> {
    let mut at = question_end(q)?;
    let records = u16_at(q, 6)? as usize + u16_at(q, 8)? as usize + u16_at(q, 10)? as usize;
    for _ in 0..records {
        at = skip_name(q, at)?;
        let rtype = u16_at(q, at)?;
        let class = u16_at(q, at + 2)?;
        let rdlen = u16_at(q, at + 8)? as usize;
        if rtype == TYPE_OPT {
            return Some(class as usize);
        }
        at += 10 + rdlen;
    }
    None
}

/// Is `resp` an answer to `query`, and is it one to pass back?
pub fn judge(query: &[u8], resp: &[u8], policy: &Policy) -> Verdict {
    let Some(qend) = question_end(query) else {
        return Verdict::Next(Reason::Invalid);
    };
    let valid = resp.len() >= qend
        && resp[..2] == query[..2]
        && resp[2] & 0x80 != 0
        && u16_at(resp, 4) == Some(1)
        && resp[12..qend].eq_ignore_ascii_case(&query[12..qend]);
    if !valid {
        return Verdict::Next(Reason::Invalid);
    }
    let falls = |r: Reason| policy.fall_on.contains(&r);
    match resp[3] & 0x0f {
        RCODE_SERVFAIL if falls(Reason::Servfail) => return Verdict::Next(Reason::Servfail),
        RCODE_REFUSED if falls(Reason::Refused) => return Verdict::Next(Reason::Refused),
        RCODE_NXDOMAIN if falls(Reason::Nxdomain) => return Verdict::Next(Reason::Nxdomain),
        0 => {}
        _ => return Verdict::Accept,
    }
    if !falls(Reason::Sinkhole) {
        return Verdict::Accept;
    }
    // Every address in the answer a sinkhole: the name is blocked there, not
    // answered. One real address among them and the answer stands.
    let answers = u16_at(resp, 6).unwrap_or(0);
    let (mut addrs, mut sunk) = (0, 0);
    let mut at = qend;
    for _ in 0..answers {
        let Some(after) = skip_name(resp, at) else {
            break;
        };
        let (Some(rtype), Some(rdlen)) = (u16_at(resp, after), u16_at(resp, after + 8)) else {
            break;
        };
        let data = after + 10;
        let Some(rdata) = resp.get(data..data + rdlen as usize) else {
            break;
        };
        let ip = match (rtype, rdata.len()) {
            (TYPE_A, 4) => Some(IpAddr::V4(Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            ))),
            (TYPE_AAAA, 16) => {
                let b: [u8; 16] = rdata.try_into().unwrap_or([0; 16]);
                Some(IpAddr::V6(Ipv6Addr::from(b)))
            }
            _ => None,
        };
        if let Some(ip) = ip {
            addrs += 1;
            if policy.sinkholes.iter().any(|n| n.contains(ip)) {
                sunk += 1;
            }
        }
        at = data + rdlen as usize;
    }
    if addrs > 0 && sunk == addrs {
        Verdict::Next(Reason::Sinkhole)
    } else {
        Verdict::Accept
    }
}

/// SERVFAIL for `query`, when nobody answered at all.
pub fn servfail(query: &[u8]) -> Vec<u8> {
    let end = question_end(query).unwrap_or(query.len().min(12));
    let mut r = query[..end.max(12).min(query.len())].to_vec();
    r.resize(r.len().max(12), 0);
    r[2] = 0x80 | (query.get(2).copied().unwrap_or(0) & 0x01);
    r[3] = 0x80 | RCODE_SERVFAIL;
    r[6..12].fill(0);
    r
}

/// The header and question alone with TC set: "ask again over TCP".
pub fn truncated(resp: &[u8]) -> Vec<u8> {
    let end = question_end(resp).unwrap_or(12.min(resp.len()));
    let mut r = resp[..end].to_vec();
    if r.len() >= 12 {
        r[2] |= 0x02;
        r[6..12].fill(0);
    }
    r
}

fn ask_udp(up: SocketAddr, query: &[u8], timeout: Duration) -> Option<Vec<u8>> {
    let bind: SocketAddr = if up.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let sock = UdpSocket::bind(bind).ok()?;
    // Connected: the kernel drops datagrams from anybody else.
    sock.connect(up).ok()?;
    sock.send(query).ok()?;
    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; 65535];
    loop {
        let left = deadline.checked_duration_since(Instant::now())?;
        sock.set_read_timeout(Some(left.max(Duration::from_millis(1))))
            .ok()?;
        let n = sock.recv(&mut buf).ok()?;
        // A late answer to an earlier try has another id: keep waiting.
        if n >= 2 && buf[..2] == query[..2] {
            return Some(buf[..n].to_vec());
        }
    }
}

fn ask_tcp(up: SocketAddr, query: &[u8], timeout: Duration) -> Option<Vec<u8>> {
    let mut s = TcpStream::connect_timeout(&up, timeout).ok()?;
    s.set_read_timeout(Some(timeout)).ok()?;
    s.set_write_timeout(Some(timeout)).ok()?;
    let mut msg = (query.len() as u16).to_be_bytes().to_vec();
    msg.extend_from_slice(query);
    s.write_all(&msg).ok()?;
    let mut len = [0u8; 2];
    s.read_exact(&mut len).ok()?;
    let mut resp = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut resp).ok()?;
    Some(resp)
}

/// Counters, by upstream and by reason.
pub struct Stats {
    queries: AtomicU64,
    exhausted: AtomicU64,
    answered: Vec<AtomicU64>,
    passed: Vec<[AtomicU64; 6]>,
}

impl Stats {
    pub fn new(upstreams: usize) -> Stats {
        Stats {
            queries: AtomicU64::new(0),
            exhausted: AtomicU64::new(0),
            answered: (0..upstreams).map(|_| AtomicU64::new(0)).collect(),
            passed: (0..upstreams).map(|_| Default::default()).collect(),
        }
    }

    pub fn render(&self, upstreams: &[SocketAddr]) -> String {
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let mut s = format!(
            "chain.upstreams={}\nchain.queries={}\nchain.exhausted={}\n",
            upstreams.len(),
            get(&self.queries),
            get(&self.exhausted)
        );
        for (i, up) in upstreams.iter().enumerate() {
            s += &format!(
                "chain.{i}.addr={up}\nchain.{i}.answered={}\n",
                get(&self.answered[i])
            );
            for r in Reason::ALL {
                s += &format!(
                    "chain.{i}.{}={}\n",
                    r.name(),
                    get(&self.passed[i][r.index()])
                );
            }
        }
        s
    }
}

pub struct Chain {
    pub upstreams: Vec<SocketAddr>,
    pub timeout: Duration,
    /// How long an upstream gets before the next is asked alongside it.
    /// Zero asks strictly one after another.
    pub hedge: Duration,
    pub policy: Policy,
    pub stats: Stats,
}

/// One upstream's try: over UDP, and over TCP when the answer was cut short.
fn attempt(up: SocketAddr, query: &[u8], timeout: Duration) -> Option<Vec<u8>> {
    match ask_udp(up, query, timeout) {
        Some(r) if r.len() > 2 && r[2] & 0x02 != 0 => ask_tcp(up, query, timeout).or(Some(r)),
        other => other,
    }
}

/// What became of one upstream's try.
enum Outcome {
    Accepted(Vec<u8>),
    /// Passed over; the answer is kept when there was one worth returning
    /// should nothing better come.
    Fell(Option<Vec<u8>>),
}

impl Chain {
    pub fn new(upstreams: Vec<SocketAddr>, timeout: Duration, policy: Policy) -> Chain {
        let stats = Stats::new(upstreams.len());
        Chain {
            upstreams,
            timeout,
            hedge: Duration::from_millis(400),
            policy,
            stats,
        }
    }

    fn launch(&self, i: usize, query: &[u8], tx: &mpsc::Sender<(usize, Option<Vec<u8>>)>) {
        let (up, q, tx, timeout) = (self.upstreams[i], query.to_vec(), tx.clone(), self.timeout);
        std::thread::spawn(move || {
            let _ = tx.send((i, attempt(up, &q, timeout)));
        });
    }

    fn judge_one(&self, i: usize, query: &[u8], resp: Option<Vec<u8>>) -> Outcome {
        let Some(resp) = resp else {
            self.stats.passed[i][Reason::Timeout.index()].fetch_add(1, Ordering::Relaxed);
            return Outcome::Fell(None);
        };
        match judge(query, &resp, &self.policy) {
            Verdict::Accept => {
                self.stats.answered[i].fetch_add(1, Ordering::Relaxed);
                Outcome::Accepted(resp)
            }
            Verdict::Next(reason) => {
                self.stats.passed[i][reason.index()].fetch_add(1, Ordering::Relaxed);
                Outcome::Fell((reason != Reason::Invalid).then_some(resp))
            }
        }
    }

    /// The answer to pass back for `query`.
    pub fn resolve(&self, query: &[u8]) -> Vec<u8> {
        self.stats.queries.fetch_add(1, Ordering::Relaxed);
        let n = self.upstreams.len();
        let (tx, rx) = mpsc::channel();
        let mut outcomes: Vec<Option<Outcome>> = (0..n).map(|_| None).collect();
        let mut started_at: Vec<Option<Instant>> = vec![None; n];
        let mut started = 0;
        let mut next_hedge = Instant::now();
        let patience = self.hedge * 2;
        loop {
            // The earliest upstream not yet passed over decides: its answer if
            // it has one, otherwise wait for it, unless it has been silent for
            // longer than its priority lasts, in which case the ones after it
            // are looked at too.
            let now = Instant::now();
            let stale = |i: usize| {
                !self.hedge.is_zero()
                    && started_at[i].is_some_and(|t| now.saturating_duration_since(t) >= patience)
            };
            let mut head = 0;
            let mut waiting = None;
            while head < n {
                match &outcomes[head] {
                    Some(Outcome::Accepted(r)) => return r.clone(),
                    Some(Outcome::Fell(_)) => head += 1,
                    None if stale(head) => {
                        waiting.get_or_insert(head);
                        head += 1;
                    }
                    None => break,
                }
            }
            // Everything after a silent one fell through too: it is still the
            // only hope, so it is waited for after all.
            if head == n
                && let Some(w) = waiting
            {
                head = w;
            }
            if head == n {
                self.stats.exhausted.fetch_add(1, Ordering::Relaxed);
                // Nothing acceptable anywhere: the first answer in list order,
                // so a name that exists nowhere still reads as NXDOMAIN.
                return outcomes
                    .into_iter()
                    .find_map(|o| match o {
                        Some(Outcome::Fell(Some(r))) => Some(r),
                        _ => None,
                    })
                    .unwrap_or_else(|| servfail(query));
            }
            if started <= head || (!self.hedge.is_zero() && started < n && now >= next_hedge) {
                self.launch(started, query, &tx);
                started_at[started] = Some(now);
                started += 1;
                next_hedge = now + self.hedge;
            }
            // Wake for the next hedge, or when the head's priority runs out.
            let mut wake = now + self.timeout * 2;
            if !self.hedge.is_zero() {
                if started < n {
                    wake = wake.min(next_hedge);
                }
                if let Some(t) = started_at.get(head).copied().flatten() {
                    let until = t + patience;
                    if until > now {
                        wake = wake.min(until);
                    }
                }
            }
            let wait = wake.saturating_duration_since(Instant::now());
            match rx.recv_timeout(wait.max(Duration::from_millis(1))) {
                Ok((i, resp)) => outcomes[i] = Some(self.judge_one(i, query, resp)),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // Every try has its own deadline; past twice that, the
                    // ones still out are counted as silent.
                    let late = self.timeout * 2;
                    for (i, o) in outcomes.iter_mut().enumerate().take(started) {
                        if o.is_none() && started_at[i].is_some_and(|t| t.elapsed() >= late) {
                            *o = Some(self.judge_one(i, query, None));
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {}
            }
        }
    }
}

/// `1.2.3.4`, `1.2.3.4:5353`, unbound's `1.2.3.4@5353`, `[::1]:53`, `::1`.
pub fn parse_upstream(s: &str) -> Option<SocketAddr> {
    let s = s.trim();
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Some(a);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 53));
    }
    let (ip, port) = s.rsplit_once('@')?;
    Some(SocketAddr::new(ip.parse().ok()?, port.parse().ok()?))
}

struct Args {
    listen: SocketAddr,
    upstreams: Vec<SocketAddr>,
    timeout: Duration,
    hedge: Duration,
    policy: Policy,
    stats: Option<PathBuf>,
    max_inflight: usize,
}

fn usage() -> ! {
    eprintln!(
        "usage: awg-dns-chain --upstream ADDR [--upstream ADDR ...] [--listen 127.0.0.1:5300]\n\
         \x20      [--timeout-ms 1500] [--hedge-ms 400] [--sinkhole IP|CIDR ...] [--keep REASON ...]\n\
         \x20      [--stats FILE] [--max-inflight 256]\n\
         REASON: servfail refused nxdomain sinkhole (answers to accept instead of moving on)"
    );
    std::process::exit(2)
}

fn parse_args(raw: &[String]) -> Result<Args, String> {
    let mut a = Args {
        listen: "127.0.0.1:5300".parse().unwrap_or_else(|_| usage()),
        upstreams: Vec::new(),
        timeout: Duration::from_millis(1500),
        hedge: Duration::from_millis(400),
        policy: Policy::default(),
        stats: None,
        max_inflight: 256,
    };
    let mut it = raw.iter();
    while let Some(flag) = it.next() {
        let mut value = || {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{flag} wants a value"))
        };
        match flag.as_str() {
            "--listen" => a.listen = value()?.parse().map_err(|_| "--listen wants ip:port")?,
            "--upstream" => {
                let v = value()?;
                a.upstreams
                    .push(parse_upstream(&v).ok_or(format!("not an upstream: {v}"))?);
            }
            "--timeout-ms" => {
                let ms: u64 = value()?
                    .parse()
                    .map_err(|_| "--timeout-ms wants a number")?;
                a.timeout = Duration::from_millis(ms.clamp(100, 10_000));
            }
            "--hedge-ms" => {
                let ms: u64 = value()?.parse().map_err(|_| "--hedge-ms wants a number")?;
                a.hedge = Duration::from_millis(ms.min(10_000));
            }
            "--sinkhole" => {
                let v = value()?;
                a.policy
                    .sinkholes
                    .push(Net::parse(&v).ok_or(format!("not an address: {v}"))?);
            }
            "--keep" => {
                let v = value()?;
                let r = Reason::parse(&v)
                    .filter(|r| !matches!(r, Reason::Timeout | Reason::Invalid))
                    .ok_or(format!("not a reason to keep: {v}"))?;
                a.policy.fall_on.retain(|x| *x != r);
            }
            "--stats" => a.stats = Some(PathBuf::from(value()?)),
            "--max-inflight" => {
                a.max_inflight = value()?
                    .parse()
                    .map_err(|_| "--max-inflight wants a number")?;
            }
            "-h" | "--help" => usage(),
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if a.upstreams.is_empty() {
        return Err("no --upstream given".into());
    }
    Ok(a)
}

fn serve_udp(sock: UdpSocket, chain: Arc<Chain>, max_inflight: usize) {
    let inflight = Arc::new(AtomicUsize::new(0));
    let mut buf = vec![0u8; 65535];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf) else {
            continue;
        };
        // Past the limit a query is dropped, and the client's own retry is
        // what asks again: the resolver in front retries on its own.
        if n < 12 || inflight.load(Ordering::Relaxed) >= max_inflight {
            continue;
        }
        let Ok(reply) = sock.try_clone() else {
            continue;
        };
        let query = buf[..n].to_vec();
        let (chain, inflight) = (chain.clone(), inflight.clone());
        inflight.fetch_add(1, Ordering::Relaxed);
        std::thread::spawn(move || {
            let mut resp = chain.resolve(&query);
            let limit = edns_size(&query).unwrap_or(512).max(512);
            if resp.len() > limit {
                resp = truncated(&resp);
            }
            let _ = reply.send_to(&resp, from);
            inflight.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

fn serve_tcp(listener: TcpListener, chain: Arc<Chain>) {
    for conn in listener.incoming() {
        let Ok(mut s) = conn else { continue };
        let chain = chain.clone();
        std::thread::spawn(move || {
            let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
            loop {
                let mut len = [0u8; 2];
                if s.read_exact(&mut len).is_err() {
                    return;
                }
                let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                if q.len() < 12 || s.read_exact(&mut q).is_err() {
                    return;
                }
                let resp = chain.resolve(&q);
                let mut out = (resp.len() as u16).to_be_bytes().to_vec();
                out.extend_from_slice(&resp);
                if s.write_all(&out).is_err() {
                    return;
                }
            }
        });
    }
}

fn write_stats(path: &PathBuf, chain: &Chain) {
    let tmp = path.with_extension("new");
    if std::fs::write(&tmp, chain.stats.render(&chain.upstreams)).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let args = parse_args(&raw).unwrap_or_else(|e| {
        eprintln!("awg-dns-chain: {e}");
        usage()
    });
    let mut chain = Chain::new(args.upstreams.clone(), args.timeout, args.policy.clone());
    chain.hedge = args.hedge;
    let chain = Arc::new(chain);
    let udp = UdpSocket::bind(args.listen).unwrap_or_else(|e| {
        eprintln!("awg-dns-chain: udp {}: {e}", args.listen);
        std::process::exit(1)
    });
    let tcp = TcpListener::bind(args.listen).unwrap_or_else(|e| {
        eprintln!("awg-dns-chain: tcp {}: {e}", args.listen);
        std::process::exit(1)
    });
    let names: Vec<String> = args.upstreams.iter().map(|u| u.to_string()).collect();
    eprintln!(
        "awg-dns-chain: on {}, asking in order: {}",
        args.listen,
        names.join(", ")
    );
    {
        let chain = chain.clone();
        std::thread::spawn(move || serve_tcp(tcp, chain));
    }
    if let Some(path) = args.stats.clone() {
        let chain = chain.clone();
        std::thread::spawn(move || {
            loop {
                write_stats(&path, &chain);
                std::thread::sleep(Duration::from_secs(15));
            }
        });
    }
    serve_udp(udp, chain, args.max_inflight);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(id: u16, name: &str, qtype: u16, edns: Option<u16>) -> Vec<u8> {
        let mut q = id.to_be_bytes().to_vec();
        q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, u8::from(edns.is_some())]);
        for l in name.trim_end_matches('.').split('.') {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        if let Some(size) = edns {
            q.extend_from_slice(&[0, 0, 41]);
            q.extend_from_slice(&size.to_be_bytes());
            q.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        }
        q
    }

    /// The query echoed back with `rcode` and these A/AAAA answers.
    fn answer(q: &[u8], rcode: u8, addrs: &[IpAddr]) -> Vec<u8> {
        let end = question_end(q).unwrap();
        let mut r = q[..end].to_vec();
        r[2] = 0x81;
        r[3] = 0x80 | rcode;
        r[6..12].fill(0);
        r[7] = addrs.len() as u8;
        for a in addrs {
            r.extend_from_slice(&[0xc0, 0x0c]);
            match a {
                IpAddr::V4(v) => {
                    r.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                    r.extend_from_slice(&v.octets());
                }
                IpAddr::V6(v) => {
                    r.extend_from_slice(&[0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
                    r.extend_from_slice(&v.octets());
                }
            }
        }
        r
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn what_falls_through_and_what_stands() {
        let p = Policy::default();
        let q = query(9, "site.geek", TYPE_A, None);
        assert_eq!(
            judge(&q, &answer(&q, 0, &[ip("93.184.215.14")]), &p),
            Verdict::Accept
        );
        assert_eq!(
            judge(&q, &answer(&q, 3, &[]), &p),
            Verdict::Next(Reason::Nxdomain)
        );
        assert_eq!(
            judge(&q, &answer(&q, 2, &[]), &p),
            Verdict::Next(Reason::Servfail)
        );
        assert_eq!(
            judge(&q, &answer(&q, 5, &[]), &p),
            Verdict::Next(Reason::Refused)
        );
        assert_eq!(
            judge(&q, &answer(&q, 0, &[ip("0.0.0.0")]), &p),
            Verdict::Next(Reason::Sinkhole)
        );
        assert_eq!(
            judge(&q, &answer(&q, 0, &[ip("127.0.0.1")]), &p),
            Verdict::Next(Reason::Sinkhole)
        );
        assert_eq!(
            judge(&q, &answer(&q, 0, &[ip("::")]), &p),
            Verdict::Next(Reason::Sinkhole)
        );
        assert_eq!(
            judge(&q, &answer(&q, 0, &[ip("127.0.0.1"), ip("1.1.1.1")]), &p),
            Verdict::Accept,
            "one real address among them"
        );
        assert_eq!(
            judge(&q, &answer(&q, 0, &[]), &p),
            Verdict::Accept,
            "no data is an answer"
        );
    }

    #[test]
    fn an_answer_to_something_else_is_not_an_answer() {
        let p = Policy::default();
        let q = query(9, "site.geek", TYPE_A, None);
        let other = query(10, "site.geek", TYPE_A, None);
        assert_eq!(
            judge(&q, &answer(&other, 0, &[ip("1.1.1.1")]), &p),
            Verdict::Next(Reason::Invalid)
        );
        let elsewhere = query(9, "evil.geek", TYPE_A, None);
        assert_eq!(
            judge(&q, &answer(&elsewhere, 0, &[ip("1.1.1.1")]), &p),
            Verdict::Next(Reason::Invalid)
        );
        assert_eq!(
            judge(&q, &q, &p),
            Verdict::Next(Reason::Invalid),
            "a query is not a response"
        );
        let upper = query(9, "SITE.geek", TYPE_A, None);
        assert_eq!(
            judge(&q, &answer(&upper, 0, &[ip("1.1.1.1")]), &p),
            Verdict::Accept,
            "case is not identity"
        );
    }

    #[test]
    fn kept_reasons_stand() {
        let mut p = Policy::default();
        p.fall_on.retain(|r| *r != Reason::Nxdomain);
        let q = query(1, "nope.example", TYPE_A, None);
        assert_eq!(judge(&q, &answer(&q, 3, &[]), &p), Verdict::Accept);
    }

    #[test]
    fn networks_and_upstreams_parse() {
        let n = Net::parse("127.0.0.0/8").unwrap();
        assert!(
            n.contains(ip("127.9.9.9")) && !n.contains(ip("128.0.0.1")) && !n.contains(ip("::1"))
        );
        assert!(Net::parse("10.0.0.0/33").is_none());
        assert_eq!(
            parse_upstream("1.2.3.4"),
            Some("1.2.3.4:53".parse().unwrap())
        );
        assert_eq!(
            parse_upstream("1.2.3.4@5301"),
            Some("1.2.3.4:5301".parse().unwrap())
        );
        assert_eq!(
            parse_upstream("[::1]:53"),
            Some("[::1]:53".parse().unwrap())
        );
        assert_eq!(
            parse_upstream("2001:db8::1"),
            Some("[2001:db8::1]:53".parse().unwrap())
        );
        assert_eq!(parse_upstream("dns.example"), None);
    }

    #[test]
    fn edns_size_and_truncation() {
        let q = query(1, "a.example", TYPE_A, Some(1232));
        assert_eq!(edns_size(&q), Some(1232));
        assert_eq!(edns_size(&query(1, "a.example", TYPE_A, None)), None);
        let r = answer(&q, 0, &[ip("1.1.1.1")]);
        let t = truncated(&r);
        assert_eq!(t[2] & 0x02, 0x02);
        assert_eq!(&t[6..12], &[0; 6]);
        let sf = servfail(&q);
        assert_eq!(sf[3] & 0x0f, RCODE_SERVFAIL);
        assert_eq!(&sf[..2], &q[..2]);
        assert_eq!(question_end(&sf), Some(sf.len()));
    }

    /// A fake upstream: answers every query with what `reply` makes of it.
    fn upstream(reply: fn(&[u8]) -> Option<Vec<u8>>) -> SocketAddr {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = s.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = s.recv_from(&mut buf) {
                if let Some(r) = reply(&buf[..n]) {
                    let _ = s.send_to(&r, from);
                }
            }
        });
        addr
    }

    #[test]
    fn the_chain_walks_past_every_kind_of_non_answer() {
        let silent = upstream(|_| None);
        let nx = upstream(|q| Some(answer(q, 3, &[])));
        let blocked = upstream(|q| Some(answer(q, 0, &["0.0.0.0".parse().unwrap()])));
        let liar = upstream(|q| {
            let mut other = q.to_vec();
            other[0] ^= 0xff;
            Some(answer(&other, 0, &["6.6.6.6".parse().unwrap()]))
        });
        let real = upstream(|q| Some(answer(q, 0, &["185.121.177.177".parse().unwrap()])));
        let chain = Chain::new(
            vec![silent, nx, blocked, liar, real],
            Duration::from_millis(300),
            Policy::default(),
        );
        let q = query(77, "opennic.geek", TYPE_A, None);
        let r = chain.resolve(&q);
        assert_eq!(judge(&q, &r, &Policy::default()), Verdict::Accept);
        assert_eq!(&r[r.len() - 4..], &[185, 121, 177, 177]);
        let stats = chain.stats.render(&chain.upstreams);
        for line in [
            "chain.0.timeout=1",
            "chain.1.nxdomain=1",
            "chain.2.sinkhole=1",
            "chain.4.answered=1",
        ] {
            assert!(stats.contains(line), "{line} missing from\n{stats}");
        }
        assert!(
            stats.contains("chain.3.timeout=1"),
            "a forged answer is waited past\n{stats}"
        );
    }

    #[test]
    fn a_silent_upstream_costs_the_hedge_and_the_order_still_decides() {
        let silent = upstream(|_| None);
        let real = upstream(|q| Some(answer(q, 0, &["192.0.2.1".parse().unwrap()])));
        let chain = Chain::new(
            vec![silent, real],
            Duration::from_millis(1500),
            Policy::default(),
        );
        let q = query(3, "slow.example", TYPE_A, None);
        let t0 = Instant::now();
        let r = chain.resolve(&q);
        assert_eq!(&r[r.len() - 4..], &[192, 0, 2, 1]);
        assert!(
            t0.elapsed() < Duration::from_millis(1200),
            "waited {:?}",
            t0.elapsed()
        );

        // The first is slow but right, the second quick: the first's answer.
        let slow = upstream(|q| {
            std::thread::sleep(Duration::from_millis(700));
            Some(answer(q, 0, &["192.0.2.10".parse().unwrap()]))
        });
        let quick = upstream(|q| Some(answer(q, 0, &["192.0.2.20".parse().unwrap()])));
        let chain = Chain::new(
            vec![slow, quick],
            Duration::from_millis(1500),
            Policy::default(),
        );
        let r = chain.resolve(&query(4, "order.example", TYPE_A, None));
        assert_eq!(&r[r.len() - 4..], &[192, 0, 2, 10]);
    }

    #[test]
    fn a_name_nobody_knows_comes_back_as_the_first_answer() {
        let nx = upstream(|q| Some(answer(q, 3, &[])));
        let nx2 = upstream(|q| Some(answer(q, 3, &[])));
        let chain = Chain::new(vec![nx, nx2], Duration::from_millis(300), Policy::default());
        let q = query(5, "nowhere.example", TYPE_A, None);
        let r = chain.resolve(&q);
        assert_eq!(r[3] & 0x0f, RCODE_NXDOMAIN);
        assert!(
            chain
                .stats
                .render(&chain.upstreams)
                .contains("chain.exhausted=1")
        );

        let dead = Chain::new(
            vec![upstream(|_| None)],
            Duration::from_millis(200),
            Policy::default(),
        );
        assert_eq!(
            dead.resolve(&q)[3] & 0x0f,
            RCODE_SERVFAIL,
            "nobody answered at all"
        );
    }
}
