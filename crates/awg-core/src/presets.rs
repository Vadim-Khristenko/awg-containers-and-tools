//! What each protocol version's switches start from.
//!
//! Picking a version is picking a feature set, so the switches follow it. One
//! place, so the CLI, the UI and the tests cannot each hold their own idea of
//! "recommended". Ported from Architect 4.5.0 `generator/presets.ts`.

use crate::versions::{AwgVersion, GenOptions};

/// MTU for everything but 3.1: the Ethernet default the tool always had.
pub const MTU_DEFAULT: u32 = 1500;

/// 3.1 starts at 1280, the IPv6 minimum.
///
/// Random trailers lengthen a packet up to the largest one seen from the peer
/// (amneziawg-go `peer.udpWindow`, raised in `receive.go`, read in `send.go`),
/// so with trailers on a large share of the traffic goes out at full size. Full
/// size has to be one every path carries without fragmenting, since a
/// fragmented tunnel is both slower and conspicuous, and 1280 is the one size
/// every IPv6 path is required to carry.
pub const MTU_31: u32 = 1280;

/// H1-H4 when they are disabled: WireGuard's own message types, which is what
/// Amnezia VPN writes for its 3.x containers.
pub const DISABLED_HEADERS: [u32; 4] = [1, 2, 3, 4];

/// The fields a preset sets. Everything else stays as the caller left it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionPreset {
    pub mtu: u32,
    pub header_protection: bool,
    pub content_padding: bool,
    pub random_timings: bool,
    pub random_trailers: bool,
    pub disable_cookies: bool,
    pub narrow_h: bool,
    pub same_s: bool,
    pub disable_h: bool,
}

const OFF: VersionPreset = VersionPreset {
    mtu: MTU_DEFAULT,
    header_protection: false,
    content_padding: false,
    random_timings: false,
    random_trailers: false,
    disable_cookies: false,
    narrow_h: false,
    same_s: false,
    disable_h: false,
};

pub fn version_preset(version: AwgVersion) -> VersionPreset {
    match version {
        AwgVersion::V1_0 | AwgVersion::V1_5 | AwgVersion::V2_0 => OFF,
        AwgVersion::V3_0 => VersionPreset {
            header_protection: true,
            content_padding: true,
            random_timings: true,
            ..OFF
        },
        // Trailers on and, with them and header protection, plain 1-4 headers:
        // the ranges hide nothing under the cipher, and under trailers their
        // width is lost packets. Cookies stay on, since silencing them breaks
        // keepalive behind NAT under load.
        AwgVersion::V3_1 => VersionPreset {
            mtu: MTU_31,
            header_protection: true,
            content_padding: true,
            random_timings: true,
            random_trailers: true,
            disable_h: true,
            ..OFF
        },
    }
}

/// Whether the switches that hang off header protection and random trailers
/// can act: "Disable H1-H4" and "Unite S1-S4". 3.1 only, both parents on.
///
/// The request is what counts, and here the request is also what is emitted:
/// this tool always writes the key it was asked for, into both ends. 1-4
/// without the cipher would put WireGuard's own type bytes on the wire.
pub fn linked_switches_on(opts: &GenOptions) -> bool {
    opts.version == AwgVersion::V3_1 && opts.header_protection && opts.random_trailers
}

impl GenOptions {
    /// Put the version's switches where that version recommends.
    pub fn apply_preset(&mut self) {
        let p = version_preset(self.version);
        self.mimic.mtu = p.mtu;
        self.header_protection = p.header_protection;
        self.content_padding = p.content_padding;
        self.random_timings = p.random_timings;
        self.random_trailers = p.random_trailers;
        self.disable_cookies = p.disable_cookies;
        self.narrow_h = p.narrow_h;
        self.same_s = p.same_s;
        self.disable_h = p.disable_h;
    }

    /// Options for `version` with its preset applied.
    pub fn for_version(version: AwgVersion) -> Self {
        let mut o = GenOptions {
            version,
            ..Default::default()
        };
        o.apply_preset();
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_one_starts_small_with_trailers_and_plain_headers() {
        let p = version_preset(AwgVersion::V3_1);
        assert_eq!(p.mtu, 1280);
        assert!(p.header_protection && p.random_trailers && p.disable_h);
        assert!(!p.disable_cookies, "cookies stay on");
        assert!(!p.same_s);
    }

    #[test]
    fn nothing_below_three_carries_a_three_x_switch() {
        for v in [AwgVersion::V1_0, AwgVersion::V1_5, AwgVersion::V2_0] {
            assert_eq!(version_preset(v), OFF, "{v}");
        }
        let p = version_preset(AwgVersion::V3_0);
        assert!(p.header_protection && p.content_padding && p.random_timings);
        assert!(!p.random_trailers && !p.disable_h);
    }

    #[test]
    fn the_linked_switches_need_three_one_and_both_parents() {
        let mut o = GenOptions::for_version(AwgVersion::V3_1);
        assert!(linked_switches_on(&o));
        o.random_trailers = false;
        assert!(!linked_switches_on(&o));
        let mut o = GenOptions::for_version(AwgVersion::V3_1);
        o.header_protection = false;
        assert!(!linked_switches_on(&o));
        let mut o = GenOptions::for_version(AwgVersion::V3_0);
        o.random_trailers = true;
        assert!(!linked_switches_on(&o));
    }

    #[test]
    fn the_default_options_are_the_three_zero_preset() {
        let d = GenOptions::default();
        let p = GenOptions::for_version(AwgVersion::V3_0);
        assert_eq!(d.header_protection, p.header_protection);
        assert_eq!(d.content_padding, p.content_padding);
        assert_eq!(d.random_timings, p.random_timings);
        assert_eq!(d.mimic.mtu, p.mimic.mtu);
    }
}
