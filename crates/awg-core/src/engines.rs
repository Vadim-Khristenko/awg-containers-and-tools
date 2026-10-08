//! What actually parses I1-I5.
//!
//! A chain tag is not a property of the app around the tunnel. It is a property
//! of the code that reads the chain, and in the open there are two of those:
//!
//! * `amneziawg-go`, `device/obf.go`: the `obfBuilders` map is the whole 2.0+
//!   vocabulary, `b t r rc rd d ds dz`. No `c`. On 1.5 the same daemon read
//!   chains with `device/awg/tag_parser.go` instead, `b c t r wt`, which is
//!   what [`AwgVersion::chain_tags`] records per generation.
//! * `amneziawg-linux-kernel-module`, `src/junk.c`, `jp_parse_tags`: a chain of
//!   `strcmp` ending in `-EINVAL`, `b c t r rc rd`. No `d`, `ds` or `dz`. The
//!   1.0.x and 3.0.x lines of the module carry the same six.
//!
//! Neither parser skips what it does not know. go refuses the whole junk spec,
//! the module returns `-EINVAL`, so one wrong tag costs the packet it was in.
//!
//! Ported from Architect `generator/engines.ts`; the tag sets there were read
//! out of the sources on 6 aug 2026, and `device/obf.go` is byte-identical
//! (blob `cf2275c5`) from v3.0.0 to `master`.
//!
//! The payload transforms `d`, `ds` and `dz` are left out of every set below:
//! nothing here generates them, and [`crate::mimic::dsl`] refuses them by name.

use crate::mimic::TagKind;
use crate::versions::AwgVersion;

/// An implementation of the tunnel, as far as the chain parser goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Engine {
    /// amneziawg-go: every Amnezia app, mihomo, WG Tunnel, and the images
    /// this repository ships.
    Go,
    /// amneziawg-linux-kernel-module. The only engine with `<c>` on 2.0+.
    Kmod,
    /// `net/amnezia-kmod` behind OPNsense. A third implementation, derived from
    /// FreeBSD's `if_wg`; its chain parser has not been read.
    KmodBsd,
    /// WireSock's BoringTun fork. It reads no chain at all and, since 3.4.5.1,
    /// silently drops I1-I5 instead of refusing them.
    WireSock,
    /// awg-quick on Linux: the kernel module when the host has it, amneziawg-go
    /// when it does not (amneziawg-tools `src/wg-quick/linux.bash`, `add_if`).
    /// The same config has to work on both, so it gets what both accept.
    AwgQuick,
    /// A closed or unidentified engine. It gets the tags both read engines
    /// share and nothing that would be a guess.
    Unverified,
}

/// `src/junk.c`, `jp_parse_tags`.
const KMOD_TAGS: &[TagKind] = &[
    TagKind::Bytes,
    TagKind::Counter,
    TagKind::Timestamp,
    TagKind::Random,
    TagKind::RandomLetters,
    TagKind::RandomDigits,
];

/// What both read engines accept on 2.0+, which is the most anyone can claim
/// for an engine nobody has read.
const SHARED_TAGS: &[TagKind] = &[
    TagKind::Bytes,
    TagKind::Timestamp,
    TagKind::Random,
    TagKind::RandomLetters,
    TagKind::RandomDigits,
];

impl Engine {
    pub const ALL: [Engine; 6] = [
        Engine::Go,
        Engine::Kmod,
        Engine::KmodBsd,
        Engine::WireSock,
        Engine::AwgQuick,
        Engine::Unverified,
    ];

    pub fn id(&self) -> &'static str {
        match self {
            Engine::Go => "amneziawg-go",
            Engine::Kmod => "amneziawg-kmod",
            Engine::KmodBsd => "amnezia-kmod-bsd",
            Engine::WireSock => "wiresock-boringtun",
            Engine::AwgQuick => "awg-quick",
            Engine::Unverified => "unverified",
        }
    }

    /// The package as it names itself, for tables and messages.
    pub fn label(&self) -> &'static str {
        match self {
            Engine::Go => "amneziawg-go",
            Engine::Kmod => "amneziawg-linux-kernel-module",
            Engine::KmodBsd => "amnezia-kmod (FreeBSD)",
            Engine::WireSock => "WireSock (BoringTun fork)",
            Engine::AwgQuick => "awg-quick (kernel module, or amneziawg-go without it)",
            Engine::Unverified => "an unidentified engine",
        }
    }

    /// Accepts the short spellings people actually type.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().to_ascii_lowercase();
        match s.as_str() {
            "go" | "amneziawg-go" | "userspace" => Some(Engine::Go),
            "kmod" | "kernel" | "amneziawg-kmod" => Some(Engine::Kmod),
            "kmod-bsd" | "bsd" | "amnezia-kmod-bsd" | "opnsense" => Some(Engine::KmodBsd),
            "wiresock" | "wiresock-boringtun" | "boringtun" => Some(Engine::WireSock),
            "awg-quick" | "quick" => Some(Engine::AwgQuick),
            "unverified" | "unknown" => Some(Engine::Unverified),
            _ => None,
        }
    }

    /// Whether the tag set was read out of the engine's own source rather than
    /// inferred from documentation or left as the safe intersection.
    pub fn verified(&self) -> bool {
        matches!(self, Engine::Go | Engine::Kmod | Engine::AwgQuick)
    }

    /// Every tag this engine's parser accepts in a chain for `version`.
    ///
    /// Empty where the version has no chains or the engine reads none. Ordered
    /// as [`TagKind`] is declared, so two sets compare by value.
    pub fn tags(&self, version: AwgVersion) -> Vec<TagKind> {
        if !version.supports_cps() {
            return Vec::new();
        }
        let go = version.chain_tags();
        let own: &[TagKind] = match self {
            Engine::Go => go,
            Engine::Kmod => KMOD_TAGS,
            Engine::WireSock => &[],
            // awg-quick may land on either engine, so only what go of this
            // generation also takes. The others are bounded the same way:
            // whatever they run, it is not older than the generation's go.
            Engine::AwgQuick => KMOD_TAGS,
            Engine::KmodBsd | Engine::Unverified => SHARED_TAGS,
        };
        // The module's own six are read for 2.0+. What its older line takes in
        // a 1.5 chain is not, so there it gets no more than go of 1.5 does.
        let bounded_by_go = match self {
            Engine::Go => false,
            Engine::Kmod => version.cps_is_client_only(),
            _ => true,
        };
        TagKind::ALL
            .into_iter()
            .filter(|k| own.contains(k) && (!bounded_by_go || go.contains(k)))
            .collect()
    }

    pub fn has_tag(&self, version: AwgVersion, kind: TagKind) -> bool {
        self.tags(version).contains(&kind)
    }
}

impl std::fmt::Display for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// The tags a chain may carry when both ends have to parse it.
///
/// From 2.0 the server's device parses I1-I5 too (it sends them when it
/// initiates), so a tag one end lacks is refused there. On 1.5 the chains are
/// client-only and the server never reads them, so only the client counts.
pub fn shared_tags(version: AwgVersion, client: Engine, server: Engine) -> Vec<TagKind> {
    let client_tags = client.tags(version);
    if version.cps_is_client_only() {
        return client_tags;
    }
    let server_tags = server.tags(version);
    client_tags
        .into_iter()
        .filter(|k| server_tags.contains(k))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(tags: &[TagKind]) -> Vec<&'static str> {
        tags.iter().map(|k| k.as_str()).collect()
    }

    #[test]
    fn the_two_read_engines_are_their_parsers() {
        // Spelled out rather than derived: a misremembered parser has to fail
        // here, not in a tunnel.
        for v in [AwgVersion::V2_0, AwgVersion::V3_0, AwgVersion::V3_1] {
            assert_eq!(
                set(&Engine::Go.tags(v)),
                ["<b 0x…>", "<r N>", "<rc N>", "<rd N>", "<t>"],
                "go on {v}"
            );
            assert_eq!(
                set(&Engine::Kmod.tags(v)),
                ["<b 0x…>", "<r N>", "<rc N>", "<rd N>", "<c>", "<t>"],
                "kmod on {v}"
            );
        }
    }

    #[test]
    fn counter_is_the_kernel_module_s_alone_from_2_0() {
        for v in [AwgVersion::V2_0, AwgVersion::V3_0, AwgVersion::V3_1] {
            for e in Engine::ALL {
                assert_eq!(
                    e.has_tag(v, TagKind::Counter),
                    e == Engine::Kmod,
                    "{} on {v}",
                    e.id()
                );
            }
        }
    }

    #[test]
    fn no_engine_reads_a_chain_on_1_0_and_wiresock_reads_none_anywhere() {
        for e in Engine::ALL {
            assert!(e.tags(AwgVersion::V1_0).is_empty(), "{}", e.id());
        }
        for v in AwgVersion::ALL {
            assert!(Engine::WireSock.tags(v).is_empty());
        }
    }

    #[test]
    fn engines_nobody_read_get_no_more_than_go_of_their_generation() {
        for v in AwgVersion::ALL {
            let go = Engine::Go.tags(v);
            for e in [Engine::AwgQuick, Engine::KmodBsd, Engine::Unverified] {
                for k in e.tags(v) {
                    assert!(go.contains(&k), "{} on {v} claims {}", e.id(), k.as_str());
                }
            }
        }
        // And the unread ones never claim the counter, even on 1.5 where go
        // has it: claiming it would be claiming a parser on no evidence.
        assert!(!Engine::Unverified.has_tag(AwgVersion::V1_5, TagKind::Counter));
        assert!(!Engine::KmodBsd.has_tag(AwgVersion::V1_5, TagKind::Counter));
        assert!(Engine::AwgQuick.has_tag(AwgVersion::V1_5, TagKind::Counter));
    }

    #[test]
    fn both_ends_count_from_2_0_and_only_the_client_on_1_5() {
        let v = AwgVersion::V3_0;
        assert!(shared_tags(v, Engine::Kmod, Engine::Kmod).contains(&TagKind::Counter));
        assert!(!shared_tags(v, Engine::Kmod, Engine::Go).contains(&TagKind::Counter));
        assert!(!shared_tags(v, Engine::Go, Engine::Kmod).contains(&TagKind::Counter));
        assert!(shared_tags(v, Engine::WireSock, Engine::Go).is_empty());

        let v15 = AwgVersion::V1_5;
        assert_eq!(
            shared_tags(v15, Engine::Go, Engine::WireSock),
            Engine::Go.tags(v15)
        );
    }

    #[test]
    fn engine_spellings_round_trip() {
        for e in Engine::ALL {
            assert_eq!(Engine::parse(e.id()), Some(e));
        }
        assert_eq!(Engine::parse(" Kernel "), Some(Engine::Kmod));
        assert_eq!(Engine::parse("vpp"), None);
    }
}
