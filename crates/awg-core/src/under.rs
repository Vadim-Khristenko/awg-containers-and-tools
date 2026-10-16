//! "Am I under the VPN?" asked from the client machine itself.
//!
//! The same question the amiunder.vpn page and the node's `awg-under` answer,
//! from wherever `awg-tool` runs, with nothing but the standard library: a
//! hand-built DNS query to the tunnel's resolver, the system resolver asked the
//! same name, and a plain HTTP request for the page's whoami. `.vpn` is not a
//! real top-level domain, so only the tunnel's resolver can answer it, and its
//! address is reachable only through the tunnel: each answer is evidence on
//! its own, and together they say where this machine's queries and traffic go.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// What the checks found. `None` means the check got no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnderReport {
    pub name: String,
    pub resolver: Ipv4Addr,
    /// What the tunnel resolver answers for the name.
    pub tunnel_answer: Option<Ipv4Addr>,
    /// What this machine's own resolver answers for it.
    pub system_answer: Option<IpAddr>,
    /// The address the page saw this machine as.
    pub seen: Option<String>,
}

impl UnderReport {
    /// The verdict: the page answered, which only happens through the tunnel.
    pub fn under(&self) -> bool {
        self.seen.is_some()
    }

    /// Whether this machine's own DNS goes to the tunnel: it knows a name only
    /// the tunnel resolver answers.
    pub fn system_dns_in_tunnel(&self) -> bool {
        self.system_answer.is_some()
    }
}

/// An A query for `name`, RFC 1035 §4.1, recursion desired.
pub fn a_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0x00, 0x01, 0x00, 0x01]);
    q
}

/// The first A record in a response to query `id`, or `None` for anything
/// else: another id, an error code, no answers, or a malformed packet.
pub fn first_a(resp: &[u8], id: u16) -> Option<Ipv4Addr> {
    if resp.len() < 12 || u16::from_be_bytes([resp[0], resp[1]]) != id {
        return None;
    }
    // QR set, RCODE 0.
    if resp[2] & 0x80 == 0 || resp[3] & 0x0f != 0 {
        return None;
    }
    let qd = u16::from_be_bytes([resp[4], resp[5]]);
    let an = u16::from_be_bytes([resp[6], resp[7]]);
    let mut at = 12;
    let skip_name = |at: &mut usize| -> Option<()> {
        loop {
            let len = *resp.get(*at)?;
            if len & 0xc0 == 0xc0 {
                *at += 2;
                return Some(());
            }
            *at += 1;
            if len == 0 {
                return Some(());
            }
            *at += len as usize;
        }
    };
    for _ in 0..qd {
        skip_name(&mut at)?;
        at += 4;
    }
    for _ in 0..an {
        skip_name(&mut at)?;
        let rtype = u16::from_be_bytes([*resp.get(at)?, *resp.get(at + 1)?]);
        let rdlen = u16::from_be_bytes([*resp.get(at + 8)?, *resp.get(at + 9)?]) as usize;
        at += 10;
        if rtype == 1 && rdlen == 4 {
            let r = resp.get(at..at + 4)?;
            return Some(Ipv4Addr::new(r[0], r[1], r[2], r[3]));
        }
        at += rdlen;
    }
    None
}

/// Ask `resolver` for the A record of `name` over UDP.
pub fn ask(resolver: SocketAddr, name: &str, timeout: Duration) -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    sock.set_read_timeout(Some(timeout)).ok()?;
    let id = (std::process::id() as u16) ^ 0x5a17;
    sock.send_to(&a_query(id, name), resolver).ok()?;
    let mut buf = [0u8; 1500];
    let (n, from) = sock.recv_from(&mut buf).ok()?;
    if from != resolver {
        return None;
    }
    first_a(&buf[..n], id)
}

/// The page's whoami: one line, the address the page saw.
pub fn whoami(addr: SocketAddr, host: &str, timeout: Duration) -> Option<String> {
    let mut s = TcpStream::connect_timeout(&addr, timeout).ok()?;
    s.set_read_timeout(Some(timeout)).ok()?;
    // One write: `write!` on a bare stream sends each piece on its own, and a
    // server that answers after the first one closes on unread bytes, which
    // Windows turns into a reset that loses the answer.
    let req = format!("GET /cgi-bin/whoami HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).ok()?;
    let mut body = String::new();
    s.read_to_string(&mut body).ok()?;
    let (head, rest) = body.split_once("\r\n\r\n")?;
    if !head.starts_with("HTTP/1.") || !head.split_whitespace().nth(1)?.starts_with('2') {
        return None;
    }
    let line = rest.lines().next()?.trim().to_string();
    (!line.is_empty()).then_some(line)
}

/// Run every check for `name` against the tunnel resolver.
pub fn check(name: &str, resolver: Ipv4Addr, timeout: Duration) -> UnderReport {
    let tunnel_answer = ask(SocketAddr::new(IpAddr::V4(resolver), 53), name, timeout);
    let system_answer = (name, 80)
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .map(|a| a.ip());
    let target = tunnel_answer
        .map(IpAddr::V4)
        .or(system_answer)
        .map(|ip| SocketAddr::new(ip, 80));
    let seen = target.and_then(|t| whoami(t, name, timeout));
    UnderReport {
        name: name.to_string(),
        resolver,
        tunnel_answer,
        system_answer,
        seen,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// A canned answer for `name`: the query echoed back with one A record.
    fn answer_for(query: &[u8], ip: [u8; 4]) -> Vec<u8> {
        let mut r = query.to_vec();
        r[2] = 0x81;
        r[3] = 0x80;
        r[7] = 1;
        r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        r.extend_from_slice(&ip);
        r
    }

    #[test]
    fn a_query_is_what_a_resolver_reads() {
        let q = a_query(0x1234, "amiunder.vpn.");
        assert_eq!(&q[..2], &[0x12, 0x34]);
        assert_eq!(&q[12..], b"\x08amiunder\x03vpn\x00\x00\x01\x00\x01");
    }

    #[test]
    fn the_answer_is_read_back_and_nothing_else_is() {
        let q = a_query(7, "amiunder.vpn");
        let r = answer_for(&q, [172, 29, 172, 253]);
        assert_eq!(first_a(&r, 7), Some(Ipv4Addr::new(172, 29, 172, 253)));
        assert_eq!(first_a(&r, 8), None, "another query's answer");
        let mut nx = r.clone();
        nx[3] = 0x83;
        assert_eq!(first_a(&nx, 7), None, "NXDOMAIN");
        assert_eq!(first_a(&r[..20], 7), None, "truncated");
    }

    #[test]
    fn the_whole_check_against_a_local_resolver_and_page() {
        let dns = UdpSocket::bind("127.0.0.1:0").unwrap();
        let resolver = dns.local_addr().unwrap();
        let page = TcpListener::bind("127.0.0.1:0").unwrap();
        let page_addr = page.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (n, from) = dns.recv_from(&mut buf).unwrap();
            dns.send_to(&answer_for(&buf[..n], [127, 0, 0, 1]), from)
                .unwrap();
        });
        std::thread::spawn(move || {
            let (mut s, _) = page.accept().unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 512];
            while !req.ends_with(b"\r\n\r\n") {
                let n = s.read(&mut buf).unwrap();
                assert!(n > 0, "the request ended before its headers did");
                req.extend_from_slice(&buf[..n]);
            }
            assert!(req.starts_with(b"GET /cgi-bin/whoami HTTP/1.0\r\nHost: amiunder.vpn\r\n"));
            s.write_all(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n10.8.1.2\n")
                .unwrap();
        });
        let t = Duration::from_secs(3);
        assert_eq!(ask(resolver, "amiunder.vpn", t), Some(Ipv4Addr::LOCALHOST));
        assert_eq!(
            whoami(page_addr, "amiunder.vpn", t).as_deref(),
            Some("10.8.1.2")
        );
    }
}
