//! A full tunnel with holes in it: the AllowedIPs that route everything except
//! the given CIDRs.
//!
//! WireGuard has no "exclude" key; a client routes what AllowedIPs lists. To
//! keep a LAN or a single site off the tunnel, AllowedIPs has to be the
//! complement: `0.0.0.0/0` and `::/0` cut into the fewest prefixes that cover
//! everything else. The node image's `awg-peer` does the same in bash for
//! `AWG_CLIENT_EXCLUDE`, and `utiltest.sh` holds it to the vectors tested here.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{Error, Result};

/// One parsed prefix, its address in the low `width` bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Prefix {
    addr: u128,
    len: u8,
}

/// The AllowedIPs of a full tunnel minus `excluded`, IPv4 first, each family
/// in address order. A family nothing is excluded from stays one default
/// route. Host bits in an excluded CIDR are dropped, as the daemon drops them.
pub fn allowed_ips_excluding(excluded: &[&str]) -> Result<Vec<String>> {
    let (mut v4, mut v6) = (Vec::new(), Vec::new());
    for raw in excluded.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let (ip, len) = match raw.split_once('/') {
            Some((ip, len)) => (ip, Some(len)),
            None => (raw, None),
        };
        let bad = || Error::Config(format!("{raw:?} is not an IPv4 or IPv6 CIDR"));
        let ip: IpAddr = ip.parse().map_err(|_| bad())?;
        let (width, addr, family) = match ip {
            IpAddr::V4(a) => (32, u128::from(u32::from(a)), &mut v4),
            IpAddr::V6(a) => (128, u128::from(a), &mut v6),
        };
        let len = match len {
            Some(l) => l
                .parse::<u8>()
                .ok()
                .filter(|l| *l <= width)
                .ok_or_else(bad)?,
            None => width,
        };
        family.push(Prefix {
            addr: addr & mask(len, width),
            len,
        });
    }
    let mut out = Vec::new();
    walk(Prefix { addr: 0, len: 0 }, 32, &v4, &mut |p| {
        out.push(format!("{}/{}", Ipv4Addr::from(p.addr as u32), p.len))
    });
    walk(Prefix { addr: 0, len: 0 }, 128, &v6, &mut |p| {
        out.push(format!("{}/{}", Ipv6Addr::from(p.addr), p.len))
    });
    Ok(out)
}

/// The top `len` bits of a `width`-bit address.
fn mask(len: u8, width: u8) -> u128 {
    let all = if width == 128 {
        u128::MAX
    } else {
        (1u128 << width) - 1
    };
    // A shift by the full 128 bits overflows, so both ends are spelled out.
    match len {
        0 => 0,
        l if l >= width => all,
        l => all & !(all >> l),
    }
}

/// Emit `p` whole if no exclusion touches it, nothing if one covers it, and
/// otherwise each half in turn, lower half first.
fn walk(p: Prefix, width: u8, excluded: &[Prefix], emit: &mut impl FnMut(Prefix)) {
    let covered = excluded
        .iter()
        .any(|e| e.len <= p.len && p.addr & mask(e.len, width) == e.addr);
    if covered {
        return;
    }
    let inside = excluded
        .iter()
        .any(|e| e.len > p.len && e.addr & mask(p.len, width) == p.addr);
    if !inside {
        emit(p);
        return;
    }
    let len = p.len + 1;
    walk(Prefix { addr: p.addr, len }, width, excluded, emit);
    let high = p.addr | 1u128 << (width - len);
    walk(Prefix { addr: high, len }, width, excluded, emit);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ex(list: &[&str]) -> Vec<String> {
        allowed_ips_excluding(list).unwrap()
    }

    #[test]
    fn nothing_excluded_is_a_full_tunnel() {
        assert_eq!(ex(&[]), ["0.0.0.0/0", "::/0"]);
    }

    // The same vectors are in utiltest.sh for awg-peer's bash version.
    #[test]
    fn a_private_range_leaves_the_rest_of_ipv4_and_all_of_ipv6() {
        assert_eq!(
            ex(&["192.168.0.0/16"]),
            [
                "0.0.0.0/1",
                "128.0.0.0/2",
                "192.0.0.0/9",
                "192.128.0.0/11",
                "192.160.0.0/13",
                "192.169.0.0/16",
                "192.170.0.0/15",
                "192.172.0.0/14",
                "192.176.0.0/12",
                "192.192.0.0/10",
                "193.0.0.0/8",
                "194.0.0.0/7",
                "196.0.0.0/6",
                "200.0.0.0/5",
                "208.0.0.0/4",
                "224.0.0.0/3",
                "::/0",
            ]
        );
    }

    #[test]
    fn a_host_and_an_ipv6_prefix_are_cut_out_of_their_own_families() {
        assert_eq!(
            ex(&["10.0.0.1", "fd00::/8"]),
            [
                "0.0.0.0/5",
                "8.0.0.0/7",
                "10.0.0.0/32",
                "10.0.0.2/31",
                "10.0.0.4/30",
                "10.0.0.8/29",
                "10.0.0.16/28",
                "10.0.0.32/27",
                "10.0.0.64/26",
                "10.0.0.128/25",
                "10.0.1.0/24",
                "10.0.2.0/23",
                "10.0.4.0/22",
                "10.0.8.0/21",
                "10.0.16.0/20",
                "10.0.32.0/19",
                "10.0.64.0/18",
                "10.0.128.0/17",
                "10.1.0.0/16",
                "10.2.0.0/15",
                "10.4.0.0/14",
                "10.8.0.0/13",
                "10.16.0.0/12",
                "10.32.0.0/11",
                "10.64.0.0/10",
                "10.128.0.0/9",
                "11.0.0.0/8",
                "12.0.0.0/6",
                "16.0.0.0/4",
                "32.0.0.0/3",
                "64.0.0.0/2",
                "128.0.0.0/1",
                "::/1",
                "8000::/2",
                "c000::/3",
                "e000::/4",
                "f000::/5",
                "f800::/6",
                "fc00::/8",
                "fe00::/7",
            ]
        );
    }

    #[test]
    fn ipv6_zero_runs_are_written_the_way_bash_writes_them() {
        // The longest run of zero groups becomes "::", the first on a tie.
        let got = ex(&["2001:db8::1:0:0:1/128"]);
        let at = got
            .iter()
            .position(|c| c == "2001:db8:0:0:1::/128")
            .unwrap();
        assert_eq!(got[at + 1], "2001:db8::1:0:0:2/127");
    }

    #[test]
    fn overlapping_and_whole_family_exclusions_are_handled() {
        // The wider prefix wins; host bits are dropped.
        assert_eq!(
            ex(&["10.1.2.3/8", "10.5.0.0/16", "::/0"]),
            ex(&["10.0.0.0/8", "::/0"])
        );
        assert_eq!(ex(&["0.0.0.0/0", "::/0"]), Vec::<String>::new());
        assert_eq!(ex(&["0.0.0.0/1"]), ["128.0.0.0/1", "::/0"]);
    }

    #[test]
    fn the_complement_and_the_exclusions_tile_the_space() {
        // Every address is in exactly one of the two lists.
        let excluded = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "100.64.0.0/10",
        ];
        let allowed = ex(&excluded);
        let total: u64 = allowed
            .iter()
            .chain(
                excluded
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .iter(),
            )
            .filter(|c| !c.contains(':'))
            .map(|c| 1u64 << (32 - c.split('/').nth(1).unwrap().parse::<u32>().unwrap()))
            .sum();
        assert_eq!(total, 1u64 << 32);
    }

    #[test]
    fn junk_is_refused_with_the_input_named() {
        for bad in [
            "10.0.0.0/33",
            "fd00::/129",
            "example.org",
            "10.0.0.0/x",
            "::ffff:/",
        ] {
            let e = allowed_ips_excluding(&[bad]).unwrap_err().to_string();
            assert!(e.contains(bad), "{e}");
        }
    }
}
