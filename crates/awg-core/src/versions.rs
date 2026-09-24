//! Protocol versions, client capabilities, and generation that respects both.
//!
//! Ported from `Any-Tech-ARCHITECT/src/utils/generator/` — `index.ts` for the
//! assembly, `clients.ts` for the capability matrix, `validators.ts` for the
//! findings and `render.ts` for the per-version line list.
//!
//! What each version actually carries, per upstream and the Architect FAQ entry
//! `version-differences`:
//!
//! * **1.0** — junk packets (Jc/Jmin/Jmax), S1/S2 padding, fixed H1–H4. No CPS.
//! * **1.5** — adds the I1–I5 chains, but only the client sends them, and its
//!   tag vocabulary is its own: `<c>` exists here and nowhere else, `<rc>`/`<rd>`
//!   do not exist yet. See [`AwgVersion::chain_tags`].
//! * **2.0** — adds S3/S4 (cookie and transport padding) and turns H1–H4 into
//!   ranges, so the magic header is redrawn per packet instead of being a stable
//!   per-server fingerprint.
//! * **3.0** — adds HeaderProtectionKey, ContentPaddingAddition and the
//!   randomised protocol timers.
//!
//! Nothing here re-implements a parameter that already has an owner: the junk
//! and padding numbers come from [`BaseObfuscation`], the 3.0 block from
//! [`crate::awg3`], the chains from [`crate::mimic`]. This module decides which
//! of them a given version and client is allowed to see.

use crate::awg3::{
    self, Awg3Options, Awg3Params, Intensity, MIN_S_WITH_HEADER_PROTECTION, UintRange,
};
use crate::deploy::config::{
    BaseObfuscation, MAX_S4, MESSAGE_COOKIE_SIZE, MESSAGE_INITIATION_SIZE, MESSAGE_RESPONSE_SIZE,
};
use crate::mimic::{self, Chain, MimicOptions, MimicProfile, Tag, TagKind};
use crate::render::{awg3_conf_lines, awg3_uapi_lines};
use crate::rng::Rng;
use crate::{Error, Result};

/// Padding draw bounds (Architect `strategy.ts`, `index.ts`).
pub const S_MAX: u32 = 150;
pub const ROUTER_S_MAX: u32 = 20;
pub const S3_MAX: u32 = 64;
pub const S3_MAX_EXTREME: u32 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AwgVersion {
    V1_0,
    V1_5,
    V2_0,
    V3_0,
    V3_1,
}

impl AwgVersion {
    pub const ALL: [AwgVersion; 5] = [
        AwgVersion::V1_0,
        AwgVersion::V1_5,
        AwgVersion::V2_0,
        AwgVersion::V3_0,
        AwgVersion::V3_1,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            AwgVersion::V1_0 => "1.0",
            AwgVersion::V1_5 => "1.5",
            AwgVersion::V2_0 => "2.0",
            AwgVersion::V3_0 => "3.0",
            AwgVersion::V3_1 => "3.1",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        AwgVersion::ALL.into_iter().find(|v| v.as_str() == s.trim())
    }

    /// I1–I5 exist from 1.5 on.
    pub fn supports_cps(&self) -> bool {
        *self >= AwgVersion::V1_5
    }

    /// In 1.5 the chains are sent by the client only, so the server config that
    /// pairs with it carries none. Worth saying in the file, because a config
    /// with I-values on one side and not the other looks like a mistake.
    pub fn cps_is_client_only(&self) -> bool {
        *self == AwgVersion::V1_5
    }

    /// The I-chain tags this generation's daemon will actually parse.
    ///
    /// The vocabulary was *replaced* between 1.5 and 2.0, not extended, so this
    /// is not a widening chain like every other capability on this type:
    ///
    /// * 1.5 (`v0.2.13` … `v0.2.14-beta-awg-1.5-1`) parses I1–I5 in
    ///   `device/awg/tag_parser.go`, whose `generatorCreator` map holds
    ///   `b c t r wt` — and nothing else. `<c>` works here and only here.
    /// * From `v0.2.16` (AWG 2.0) `uapi.go` hands `i1`…`i5` to `newObfChain` in
    ///   `device/obf.go`, whose `obfBuilders` map holds `b t r rc rd d ds dz` —
    ///   no `c`, no `wt`. `<rc>`/`<rd>` work here and not on 1.5.
    ///
    /// Getting this wrong is not a degraded chain, it is
    /// `IPC error -22: invalid i1: invalid tag: rc` and an interface that never
    /// comes up. `wt` (a send-time delay) and `d`/`ds`/`dz` (payload
    /// transforms, dead until AWG 4.0 — see [`crate::mimic::dsl`]) are omitted
    /// because nothing here generates them.
    pub fn chain_tags(&self) -> &'static [TagKind] {
        const NONE: &[TagKind] = &[];
        const V15: &[TagKind] = &[
            TagKind::Bytes,
            TagKind::Random,
            TagKind::Counter,
            TagKind::Timestamp,
        ];
        const V20: &[TagKind] = &[
            TagKind::Bytes,
            TagKind::Random,
            TagKind::RandomLetters,
            TagKind::RandomDigits,
            TagKind::Timestamp,
        ];
        match self {
            AwgVersion::V1_0 => NONE,
            AwgVersion::V1_5 => V15,
            AwgVersion::V2_0 | AwgVersion::V3_0 | AwgVersion::V3_1 => V20,
        }
    }

    /// Tags the 1.5 parser allows at most once per chain.
    ///
    /// `uniqueTags` in `device/awg/tag_parser.go` — a second `<c>` or `<t>` is
    /// `tag c needs to be unique`, i.e. the same -22 as an unknown tag. The
    /// 2.0+ builder has no such rule.
    pub fn chain_tags_must_be_unique(&self) -> &'static [TagKind] {
        const NONE: &[TagKind] = &[];
        const UNIQ: &[TagKind] = &[TagKind::Counter, TagKind::Timestamp];
        match self {
            AwgVersion::V1_5 => UNIQ,
            _ => NONE,
        }
    }

    /// From 2.0 a magic header is a range redrawn per packet, not one number.
    pub fn h_is_range(&self) -> bool {
        *self >= AwgVersion::V2_0
    }

    /// S3 (cookie reply) and S4 (transport) padding arrived in 2.0.
    pub fn supports_s3_s4(&self) -> bool {
        *self >= AwgVersion::V2_0
    }

    pub fn supports_awg3(&self) -> bool {
        *self >= AwgVersion::V3_0
    }

    /// The 3.1 switches: RandomTrailers and DisableCookies.
    ///
    /// Both keys are new vocabulary — a 3.0 device refuses them at config
    /// parse (`amneziawg-tools` `master` `src/config.c` knows neither), so
    /// they are emitted only where the version reads them. Verified against
    /// the `amneziawg-go` v3.1 tags: `random_trailers` and `disable_cookies`
    /// in `device/uapi.go`, both boolean.
    pub fn supports_feature_flags(&self) -> bool {
        *self >= AwgVersion::V3_1
    }

    /// Exactly the `.conf` keys this version defines — no more, no fewer.
    pub fn fields(&self) -> &'static [&'static str] {
        const BASE_1X: &[&str] = &["H1", "H2", "H3", "H4", "S1", "S2", "Jc", "Jmin", "Jmax"];
        const V15: &[&str] = &[
            "H1", "H2", "H3", "H4", "S1", "S2", "Jc", "Jmin", "Jmax", "I1", "I2", "I3", "I4", "I5",
        ];
        const V20: &[&str] = &[
            "H1", "H2", "H3", "H4", "S1", "S2", "S3", "S4", "Jc", "Jmin", "Jmax", "I1", "I2", "I3",
            "I4", "I5",
        ];
        const V30: &[&str] = &[
            "H1",
            "H2",
            "H3",
            "H4",
            "S1",
            "S2",
            "S3",
            "S4",
            "Jc",
            "Jmin",
            "Jmax",
            "I1",
            "I2",
            "I3",
            "I4",
            "I5",
            "HeaderProtectionKey",
            "ContentPaddingAddition",
            "RekeyAfterTime",
            "RekeyTimeout",
            "RejectAfterTime",
            "KeepaliveTimeout",
            "MaxHandshakeAttempts",
        ];
        const V31: &[&str] = &[
            "H1",
            "H2",
            "H3",
            "H4",
            "S1",
            "S2",
            "S3",
            "S4",
            "Jc",
            "Jmin",
            "Jmax",
            "I1",
            "I2",
            "I3",
            "I4",
            "I5",
            "HeaderProtectionKey",
            "ContentPaddingAddition",
            "RekeyAfterTime",
            "RekeyTimeout",
            "RejectAfterTime",
            "KeepaliveTimeout",
            "MaxHandshakeAttempts",
            "RandomTrailers",
            "DisableCookies",
        ];
        match self {
            AwgVersion::V1_0 => BASE_1X,
            AwgVersion::V1_5 => V15,
            AwgVersion::V2_0 => V20,
            AwgVersion::V3_0 => V30,
            AwgVersion::V3_1 => V31,
        }
    }
}

impl std::fmt::Display for AwgVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ------------------------------------------------------------ client matrix

/// What one concrete AmneziaWG implementation will actually accept.
///
/// Ported verbatim from `clients.ts`, whose source data is upstream
/// amneziawg-android / -windows / -go, AmneziaVPN desktop and mobile, community
/// firmware packages and user reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientCapability {
    pub id: &'static str,
    pub name: &'static str,
    pub platforms: &'static [&'static str],
    /// Largest H the client's parser survives — `UINT32_MAX` for most,
    /// `INT32_MAX` for the Windows client.
    pub max_h_value: u32,
    pub supports_s3_s4: bool,
    pub supports_tag_c: bool,
    pub supports_tag_rc: bool,
    pub supports_tag_rd: bool,
    pub supports_i1_i5: bool,
    pub max_jc: u32,
    pub max_s4: u32,
    pub known_issues: &'static [&'static str],
}

const UINT32_MAX: u32 = 4_294_967_295;
/// The Windows client parses H into a signed 32-bit integer — issue #85.
const INT32_MAX: u32 = 2_147_483_647;

pub const CLIENTS: [ClientCapability; 10] = [
    ClientCapability {
        id: "amneziawg-android",
        name: "AmneziaWG Android",
        platforms: &["Android 5+"],
        max_h_value: UINT32_MAX,
        supports_s3_s4: true,
        supports_tag_c: true,
        supports_tag_rc: true,
        supports_tag_rd: true,
        supports_i1_i5: true,
        max_jc: 10,
        max_s4: 32,
        known_issues: &[],
    },
    ClientCapability {
        id: "amneziawg-ios",
        name: "AmneziaWG iOS",
        platforms: &["iOS 15+"],
        max_h_value: UINT32_MAX,
        supports_s3_s4: true,
        supports_tag_c: true,
        supports_tag_rc: true,
        supports_tag_rd: true,
        supports_i1_i5: true,
        max_jc: 10,
        max_s4: 32,
        known_issues: &[],
    },
    ClientCapability {
        id: "amneziawg-windows",
        name: "AmneziaWG Windows",
        platforms: &["Windows 10+"],
        max_h_value: INT32_MAX,
        supports_s3_s4: true,
        supports_tag_c: false,
        supports_tag_rc: false,
        supports_tag_rd: false,
        supports_i1_i5: true,
        max_jc: 10,
        max_s4: 32,
        known_issues: &["H-value cap at INT32_MAX (issue #85)"],
    },
    ClientCapability {
        id: "amneziavpn",
        name: "Amnezia VPN",
        platforms: &["Android", "iOS", "Windows", "macOS", "Linux"],
        max_h_value: UINT32_MAX,
        supports_s3_s4: true,
        supports_tag_c: true,
        supports_tag_rc: true,
        supports_tag_rd: true,
        supports_i1_i5: true,
        max_jc: 10,
        max_s4: 32,
        known_issues: &[],
    },
    ClientCapability {
        id: "wg-tunnel",
        name: "WG Tunnel",
        platforms: &["Android"],
        max_h_value: UINT32_MAX,
        supports_s3_s4: true,
        supports_tag_c: false,
        supports_tag_rc: false,
        supports_tag_rd: false,
        supports_i1_i5: true,
        max_jc: 10,
        max_s4: 32,
        known_issues: &["Large S3/S4 may drain battery or behave inconsistently; keep S4 modest."],
    },
    ClientCapability {
        id: "wiresock",
        name: "WireSock",
        platforms: &["Windows"],
        max_h_value: UINT32_MAX,
        supports_s3_s4: true,
        supports_tag_c: false,
        supports_tag_rc: false,
        supports_tag_rd: false,
        supports_i1_i5: true,
        max_jc: 10,
        max_s4: 32,
        known_issues: &[],
    },
    ClientCapability {
        id: "keenetic-native",
        name: "Keenetic (native)",
        platforms: &["Keenetic OS 4.x"],
        max_h_value: UINT32_MAX,
        supports_s3_s4: true,
        supports_tag_c: true,
        supports_tag_rc: true,
        supports_tag_rd: true,
        supports_i1_i5: true,
        max_jc: 128,
        max_s4: 32,
        known_issues: &["I1 sensitivity: prefer simple <r 64> or DNS mimicry profiles."],
    },
    ClientCapability {
        id: "awg-go-legacy",
        name: "amneziawg-go (legacy)",
        platforms: &["Linux", "macOS"],
        max_h_value: UINT32_MAX,
        supports_s3_s4: true,
        supports_tag_c: false,
        supports_tag_rc: false,
        supports_tag_rd: false,
        supports_i1_i5: true,
        max_jc: 128,
        max_s4: 32,
        known_issues: &["Tag <c> is not implemented — ErrorCode 1000."],
    },
    ClientCapability {
        id: "openwrt",
        name: "OpenWRT",
        platforms: &["OpenWrt"],
        max_h_value: UINT32_MAX,
        supports_s3_s4: true,
        supports_tag_c: true,
        supports_tag_rc: true,
        supports_tag_rd: true,
        supports_i1_i5: true,
        max_jc: 128,
        max_s4: 32,
        known_issues: &[],
    },
    ClientCapability {
        id: "asus-merlin",
        name: "ASUS Merlin",
        platforms: &["Asuswrt-Merlin"],
        max_h_value: UINT32_MAX,
        supports_s3_s4: true,
        supports_tag_c: true,
        supports_tag_rc: true,
        supports_tag_rd: true,
        supports_i1_i5: true,
        max_jc: 128,
        max_s4: 32,
        known_issues: &[],
    },
];

/// The safe recommendation for someone who has not said what they run.
pub const DEFAULT_CLIENT_ID: &str = "amneziavpn";

pub fn client(id: &str) -> Option<&'static ClientCapability> {
    let id = id.trim();
    CLIENTS.iter().find(|c| c.id == id)
}

pub fn default_client() -> &'static ClientCapability {
    client(DEFAULT_CLIENT_ID).expect("the default client is in the matrix")
}

// -------------------------------------------------------------- validation

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// The config will be refused, or will fail in a way nothing reports.
    Error,
    /// The config works but gives something away.
    Warn,
}

/// One concrete complaint about one named field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub field: String,
    pub level: Level,
    /// Stable identifier for the rule, so a UI can translate without parsing
    /// the message.
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let level = match self.level {
            Level::Error => "error",
            Level::Warn => "warning",
        };
        write!(f, "{level}: {}: {}", self.field, self.message)
    }
}

impl Violation {
    fn err(field: impl Into<String>, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            level: Level::Error,
            code,
            message: message.into(),
        }
    }

    fn warn(field: impl Into<String>, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            level: Level::Warn,
            code,
            message: message.into(),
        }
    }
}

// ------------------------------------------------------------------ params

/// A generated parameter set, tagged with the version it belongs to.
#[derive(Debug, Clone)]
pub struct VersionedParams {
    pub version: AwgVersion,
    pub profile: MimicProfile,
    /// Junk counts, S1–S4, and the low end of each magic header.
    pub base: BaseObfuscation,
    /// The high end of each header range — 2.0 and up only. `base.h` holds the
    /// low ends, so there is still one place where a magic header lives.
    pub h_hi: Option<[u32; 4]>,
    /// I1–I5, 1.5 and up.
    pub chains: Option<[String; 5]>,
    pub awg3: Option<Awg3Params>,
}

impl VersionedParams {
    /// Header `i` (0-based) as the daemon parses it: `"lo"` before 2.0, `"lo-hi"`
    /// after.
    pub fn h_range(&self, i: usize) -> UintRange {
        match self.h_hi {
            Some(hi) => UintRange::new(self.base.h[i], hi[i]),
            None => UintRange::new(self.base.h[i], self.base.h[i]),
        }
    }

    /// The `.conf` `[Interface]` body for this version.
    ///
    /// Ordering follows `render.ts` rather than [`BaseObfuscation::conf_lines`]:
    /// that one always emits the full 3.0 set for the deploy path, which is
    /// exactly what a 1.0 config must not contain.
    pub fn conf_lines(&self) -> Vec<String> {
        let mut out = vec![format!("# AmneziaWG {}", self.version)];

        for i in 0..4 {
            out.push(format!("H{} = {}", i + 1, self.h_range(i)));
        }
        let s_count = if self.version.supports_s3_s4() { 4 } else { 2 };
        for i in 0..s_count {
            out.push(format!("S{} = {}", i + 1, self.base.s[i]));
        }
        out.push(format!("Jc = {}", self.base.jc));
        out.push(format!("Jmin = {}", self.base.jmin));
        out.push(format!("Jmax = {}", self.base.jmax));

        match &self.chains {
            None => out.push("# I1-I5 are not supported in AWG 1.0".into()),
            Some(chains) => {
                if self.version.cps_is_client_only() {
                    out.push("# I1-I5 are client-side only in AWG 1.5:".into());
                }
                for (i, c) in chains.iter().enumerate() {
                    out.push(format!("I{} = {c}", i + 1));
                }
            }
        }

        if let Some(p) = &self.awg3 {
            out.extend(awg3_conf_lines(p));
        }
        out
    }

    /// The same set as UAPI `key=value` lines.
    ///
    /// This is the path the containers use: one request format covers 1.0
    /// through 3.1, so the keys reach the daemon however the tools parse them.
    pub fn uapi_lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        for i in 0..4 {
            out.push(format!("h{}={}", i + 1, self.h_range(i)));
        }
        let s_count = if self.version.supports_s3_s4() { 4 } else { 2 };
        for i in 0..s_count {
            out.push(format!("s{}={}", i + 1, self.base.s[i]));
        }
        out.push(format!("jc={}", self.base.jc));
        out.push(format!("jmin={}", self.base.jmin));
        out.push(format!("jmax={}", self.base.jmax));
        if let Some(chains) = &self.chains {
            for (i, c) in chains.iter().enumerate() {
                out.push(format!("i{}={c}", i + 1));
            }
        }
        if let Some(p) = &self.awg3 {
            out.extend(awg3_uapi_lines(p));
        }
        out
    }

    /// The `.conf` keys actually emitted, in order. Used to check a version
    /// carries its own field set and nothing else.
    /// The `.conf` keys actually emitted, in order. Used to check a version
    /// carries its own field set and nothing else.
    pub fn field_names(&self) -> Vec<String> {
        self.conf_lines()
            .iter()
            .filter_map(|l| l.split_once(" = ").map(|(k, _)| k.to_string()))
            .collect()
    }
}

/// Junk bounds by intensity (Architect's JMIN/JMAX_BY_INTENSITY and router bands).
const JMIN_LOW: (u32, u32) = (64, 256);
const JMIN_MEDIUM: (u32, u32) = (128, 512);
const JMIN_HIGH: (u32, u32) = (256, 768);
const JMAX_LOW: (u32, u32) = (256, 512);
const JMAX_MEDIUM: (u32, u32) = (512, 1024);
const JMAX_HIGH: (u32, u32) = (768, 1280);
const JUNK_ROUTER_JMIN: (u32, u32) = (16, 31);
const JUNK_ROUTER_JMAX: (u32, u32) = (96, 128);

/// Widest window a header range opens (Architect's `rRange`, `RANGE_MAX_WIDTH`).
const RANGE_MAX_WIDTH: u32 = 50_000;
const RANGE_MIN_WIDTH: u32 = 1_000;

/// `MessageInitiationSize - MessageResponseSize`. Two S values this far apart
/// make an initiation and a response the same size on the wire.
const INIT_RESPONSE_DELTA: u32 = MESSAGE_INITIATION_SIZE - MESSAGE_RESPONSE_SIZE;
/// `MessageInitiationSize - MessageCookieSize`.
const INIT_COOKIE_DELTA: u32 = MESSAGE_INITIATION_SIZE - MESSAGE_COOKIE_SIZE;
/// `MessageResponseSize - MessageCookieSize`.
const RESPONSE_COOKIE_DELTA: u32 = MESSAGE_RESPONSE_SIZE - MESSAGE_COOKIE_SIZE;

/// Everything both ends of one tunnel have to agree on, and roughly how hard
/// each knob is pressed.
///
/// `junk_level`, `extreme` and `narrow_h` mirror the Architect knobs of the
/// same names; the `client_*` fields are the target build's ceilings.
pub struct BaseCtx<'a> {
    pub version: AwgVersion,
    pub intensity: Intensity,
    pub router_mode: bool,
    pub extreme: bool,
    pub junk_level: u8,
    pub narrow_h: bool,
    pub client_max_h: u32,
    pub client_max_jc: u32,
    pub client_max_s4: u32,
    pub header_protection: bool,
    pub phantom: std::marker::PhantomData<&'a ()>,
}

/// One of four ordered non-overlapping header windows.
struct Zone {
    min: u32,
    max: u32,
    spread: u32,
}

/// H1–H4 zones for one client ceiling and mode, ordered by message type.
fn header_zones(max_h: u32, extreme: bool, narrow_h: bool) -> [Zone; 4] {
    const NARROW_SPREAD: u32 = 20_000;
    const NARROW_H4_SPREAD: u32 = 30_000;

    if max_h == u32::MAX {
        let wide = if narrow_h {
            NARROW_SPREAD
        } else if extreme {
            10_000_000
        } else {
            100_000_000
        };
        let wide_h4 = if narrow_h {
            NARROW_H4_SPREAD
        } else if extreme {
            15_000_000
        } else {
            150_000_000
        };
        return [
            Zone {
                min: 100_000_000,
                max: 900_000_000,
                spread: wide,
            },
            Zone {
                min: 1_200_000_000,
                max: 2_000_000_000,
                spread: wide,
            },
            Zone {
                min: 2_400_000_000,
                max: 3_200_000_000,
                spread: wide,
            },
            Zone {
                min: 3_600_000_000,
                max: 4_000_000_000,
                spread: wide_h4,
            },
        ];
    }

    let zone = max_h / 5;
    let gap = 10_000u32;
    let room = zone.saturating_sub(gap);
    let wide = if narrow_h {
        NARROW_SPREAD
    } else if extreme {
        10_000_000
    } else {
        100_000_000
    };
    let wide_h4 = if narrow_h {
        NARROW_H4_SPREAD
    } else if extreme {
        15_000_000
    } else {
        150_000_000
    };
    [
        Zone {
            min: zone,
            max: zone.saturating_mul(2).saturating_sub(gap),
            spread: wide.min(room),
        },
        Zone {
            min: zone.saturating_mul(2),
            max: zone.saturating_mul(3).saturating_sub(gap),
            spread: wide.min(room),
        },
        Zone {
            min: zone.saturating_mul(3),
            max: zone.saturating_mul(4).saturating_sub(gap),
            spread: wide.min(room),
        },
        Zone {
            min: zone.saturating_mul(4),
            max: max_h,
            spread: wide_h4.min(room),
        },
    ]
}

// -------------------------------------------------------------- generation

/// What a caller wants generated.
#[derive(Debug, Clone)]
pub struct GenOptions {
    pub version: AwgVersion,
    pub profile: MimicProfile,
    pub intensity: Intensity,
    pub client: &'static ClientCapability,
    pub mimic: MimicOptions,
    /// 3.0 only; ignored by every other version.
    pub header_protection: bool,
    pub content_padding: bool,
    pub random_timings: bool,
    /// 3.1 only: a random-length trailer on every outgoing packet.
    pub random_trailers: bool,
    /// 3.1 only: the device stays silent instead of sending cookie replies.
    /// Off by default — without cookies, keepalive behind NAT breaks under
    /// load, and a server that quietly breaks tunnels is worse than one the
    /// operator turns on knowingly.
    pub disable_cookies: bool,
    /// Low-power router: fewer junk packets, smaller padding, I1 only.
    pub router_mode: bool,
    /// Push ceilings instead of expectations: Jc to 128, S3 past 64, headers
    /// across 10M windows.
    pub extreme: bool,
    /// How much junk goes out before the handshake; 5 is the Architect default.
    pub junk_level: u8,
    /// 3.1 only: narrow H ranges to ~20k as a CPU workaround. Ignored elsewhere.
    pub narrow_h: bool,
}

impl Default for GenOptions {
    fn default() -> Self {
        Self {
            version: AwgVersion::V3_0,
            profile: MimicProfile::QuicInitial,
            intensity: Intensity::Medium,
            client: default_client(),
            mimic: MimicOptions::default(),
            header_protection: true,
            content_padding: true,
            random_timings: true,
            random_trailers: false,
            disable_cookies: false,
            router_mode: false,
            extreme: false,
            junk_level: 5,
            narrow_h: false,
        }
    }
}

/// A header range inside its own zone, Architect's `rRange` with the zone's
/// ceiling slid rather than clamped.
///
/// `base` is the single header drawn first for the same zone: the range opens
/// *inside* it (`rnd(base, base + spread)`), which is the whole point of the
/// room reservation. A collapsed edge is its own fallback rather than an
/// error: `UintRange::new` reads `(30, 4)` as a single value, which is also
/// what the parser accepts.
fn header_window(
    rng: &mut impl Rng,
    base: u32,
    zone: &Zone,
    max_h: u32,
    narrow: bool,
) -> UintRange {
    let limit = zone.max.min(max_h);
    if narrow {
        // `rRange(base, narrowSpread)`: `start = rnd(base, base + spread)`,
        // `end = start + rnd(RANGE_MIN_WIDTH, spread)` — the width is bounded
        // by the *spread*, never by the zone.
        let spread = zone.spread;
        let start = base.saturating_add(rng.range(0, spread)).min(limit);
        let end = start
            .saturating_add(rng.range(RANGE_MIN_WIDTH, spread.max(1)))
            .min(limit);
        return UintRange::new(start.min(end), end.max(start.min(limit)));
    }
    let width = rng.range(RANGE_MIN_WIDTH, RANGE_MAX_WIDTH);
    // Slide the window down rather than clamping both ends onto the ceiling:
    // `rRange` never parks every capped-client range on the cap itself.
    let mut start = base.saturating_add(rng.range(0, zone.spread)).min(limit);
    start = start.min(limit.saturating_sub(width));
    let end = start.saturating_add(width).min(limit);
    UintRange::new(start.min(end), end.max(start.min(limit)))
}

/// A single header for 1.0/1.5, out of the same zones as the ranges.
fn draw_header_single(
    rng: &mut impl Rng,
    zones: &[Zone; 4],
    i: usize,
    extreme: bool,
    max_h: u32,
) -> u32 {
    let spread = if i == 0 {
        if extreme { 10_000_000 } else { 4_000_000 }
    } else {
        zones[i].spread
    };
    zones[i]
        .min
        .saturating_add(rng.range(0, spread))
        .min(max_h)
        .max(5)
}

/// How many junk packets go out before the handshake.
///
/// Architect's `drawJc` exactly: the version-1.0 branch is the plain level,
/// every other version drifts `junkLevel` by ±1 inside the ceiling, and level
/// 0 is the off switch — unless `extreme` re-arms a small draw. `router_mode`
/// is a cap applied afterwards, and it never re-arms zero.
fn draw_junk(rng: &mut impl Rng, ctx: &BaseCtx<'_>) -> (u32, u32, u32) {
    let ceiling = ctx.client_max_jc.min(if ctx.extreme { 128 } else { 15 });
    let extreme_ceiling = ctx.client_max_jc.min(128);
    let mut jc = if ctx.version == AwgVersion::V1_0 {
        u32::from(ctx.junk_level.max(4)).min(ceiling)
    } else if ctx.junk_level > 0 {
        let drift = rng.range(0, 2) as i64 - 1;
        ((i64::from(ctx.junk_level) + drift)
            .max(1)
            .min(i64::from(ceiling.max(1)))) as u32
    } else if ctx.extreme {
        rng.range(1, 8.min(extreme_ceiling.max(1)))
    } else {
        0
    };
    if ctx.router_mode {
        // A cap, applied to whatever was drawn. Zero stays zero: a user who
        // turned the junk train off asked for it off, and router mode used to
        // hand them three packets anyway.
        let cap = ctx.client_max_jc.min(if ctx.version == AwgVersion::V1_0 {
            4
        } else {
            3
        });
        jc = if jc == 0 { 0 } else { jc.min(cap.max(1)) };
    }

    let (jmin_lo, jmin_hi) = if ctx.router_mode {
        JUNK_ROUTER_JMIN
    } else {
        match ctx.intensity {
            Intensity::Low => JMIN_LOW,
            Intensity::Medium => JMIN_MEDIUM,
            Intensity::High => JMIN_HIGH,
        }
    };
    let (jmax_lo, jmax_hi) = if ctx.router_mode {
        JUNK_ROUTER_JMAX
    } else {
        match ctx.intensity {
            Intensity::Low => JMAX_LOW,
            Intensity::Medium => JMAX_MEDIUM,
            Intensity::High => JMAX_HIGH,
        }
    };
    let jmax_lo_jmax_hi = rng.range(jmax_lo, jmax_hi);
    let jmin = rng.range(jmin_lo, jmin_hi);
    let jmax = resolve_jmax(rng, jmin, jmax_lo_jmax_hi, ctx.version);
    (jc, jmin, jmax)
}

/// `Jmax` with room for `Jmin` underneath, and the 1.0 floor above 81.
fn resolve_jmax(rng: &mut impl Rng, jmin: u32, drawn: u32, version: AwgVersion) -> u32 {
    let mut jmax = if drawn <= jmin.saturating_add(64) {
        jmin.saturating_add(rng.range(64, 256))
    } else {
        drawn
    };
    if version == AwgVersion::V1_0 && jmax <= 81 {
        jmax = 82 + rng.range(50, 200);
    }
    jmax
}

/// Padding sizes, after the rules that involve more than one of them.
fn draw_sizes(rng: &mut impl Rng, ctx: &BaseCtx<'_>) -> [u32; 4] {
    let s_max = if ctx.router_mode { ROUTER_S_MAX } else { S_MAX };
    let s3_max = if ctx.extreme { S3_MAX_EXTREME } else { S3_MAX };
    let max_s4 = MAX_S4.min(ctx.client_max_s4);

    let mut s1 = rng.range(1, s_max);
    let mut s2 = rng.range(1, s_max);
    let mut s3 = if ctx.extreme {
        rng.range(S3_MAX + 1, S3_MAX_EXTREME)
    } else {
        rng.range(1, S3_MAX)
    };
    let mut s4 = rng.range(1, max_s4.max(1));

    s2 = avoid_collision(s2, s_max, |v| v == s1 + INIT_RESPONSE_DELTA);
    s3 = avoid_collision(s3, s3_max, |v| {
        v == s1 + INIT_COOKIE_DELTA || v == s2 + RESPONSE_COOKIE_DELTA
    });
    s4 = s4.min(max_s4);

    if ctx.header_protection {
        s1 = lift_above_floor(rng, s1, MIN_S_WITH_HEADER_PROTECTION, s_max);
        s2 = lift_above_floor(rng, s2, MIN_S_WITH_HEADER_PROTECTION, s_max);
        s2 = avoid_collision(s2, s_max, |v| v == s1 + INIT_RESPONSE_DELTA);
        s3 = lift_above_floor(rng, s3, MIN_S_WITH_HEADER_PROTECTION, s3_max);
        s4 = lift_above_floor(rng, s4, MIN_S_WITH_HEADER_PROTECTION, max_s4);
        s3 = avoid_collision(s3, s3_max, |v| {
            v == s1 + INIT_COOKIE_DELTA || v == s2 + RESPONSE_COOKIE_DELTA
        });
        s4 = s4.min(max_s4);
    }

    [s1, s2, s3, s4]
}

/// Step a size off a colliding length without leaving its range.
fn avoid_collision(value: u32, ceiling: u32, collides: impl Fn(u32) -> bool) -> u32 {
    if !collides(value) {
        return value;
    }
    let step: i64 = if value >= ceiling { -1 } else { 1 };
    let mut v = value as i64 + step;
    for _ in 0..10u8 {
        if v < 1 || v > i64::from(ceiling) || !collides(v as u32) {
            break;
        }
        v += step;
    }
    v.clamp(1, i64::from(ceiling.max(1))) as u32
}

/// Bring a size up to the floor without collapsing onto it.
fn lift_above_floor(rng: &mut impl Rng, value: u32, floor: u32, high: u32) -> u32 {
    if value >= floor {
        return value;
    }
    if high > floor {
        rng.range(floor, high)
    } else {
        floor
    }
}

/// Generate a complete parameter set for one version and one client.
///
/// Every install calls this for itself. A shared parameter set would give every
/// server built with this tool a single DPI fingerprint, which is the one thing
/// obfuscation cannot survive.
pub fn generate(rng: &mut impl Rng, opts: &GenOptions) -> Result<VersionedParams> {
    let client = opts.client;
    let header_protection = opts.header_protection && opts.version.supports_awg3();

    let ctx = BaseCtx {
        version: opts.version,
        intensity: opts.intensity,
        router_mode: opts.router_mode,
        extreme: opts.extreme,
        junk_level: opts.junk_level,
        narrow_h: opts.narrow_h && opts.version == AwgVersion::V3_1,
        client_max_h: client.max_h_value,
        client_max_jc: client.max_jc,
        client_max_s4: client.max_s4,
        header_protection,
        phantom: std::marker::PhantomData,
    };
    let (jc, jmin, jmax) = draw_junk(rng, &ctx);
    let mut s = draw_sizes(rng, &ctx);
    let zones = header_zones(ctx.client_max_h, ctx.extreme, ctx.narrow_h);
    let mut h = [0u32; 4];
    for (i, v) in h.iter_mut().enumerate() {
        *v = draw_header_single(rng, &zones, i, ctx.extreme, ctx.client_max_h);
    }
    if !opts.version.supports_s3_s4() {
        s[2] = 0;
        s[3] = 0;
    }

    let mut base = BaseObfuscation {
        jc,
        jmin,
        jmax: jmax.max(jmin + 1),
        s,
        h,
    };
    base.validate()?;

    let h_hi = opts.version.h_is_range().then(|| {
        let mut hi = [0u32; 4];
        for (i, zone) in zones.iter().enumerate() {
            // `base.h` doubles as the rendered low end on range versions.
            let window = header_window(rng, base.h[i], zone, client.max_h_value, ctx.narrow_h);
            hi[i] = window.hi.max(base.h[i]);
            base.h[i] = window.lo.min(base.h[i]);
        }
        hi
    });

    let chains = if opts.version.supports_cps() && client.supports_i1_i5 {
        // A tag the daemon or the client does not implement is not a smaller
        // packet, it is a config that is refused outright — so they are filtered
        // before generation, not validated after it. The version comes first:
        // the client matrix records what an implementation added on top of its
        // generation, never a tag its generation does not have.
        let vocab = opts.version.chain_tags();
        let has = |k: TagKind| vocab.contains(&k);
        let mimic = MimicOptions {
            // Not `opts.mimic.tag_c`: `<c>` is 1.5's only counter and is a parse
            // error from 2.0 on, so it is the generation that decides, not a
            // preference. The opt-in flag only ever meant "I am on 1.5".
            tag_c: has(TagKind::Counter) && client.supports_tag_c,
            tag_t: opts.mimic.tag_t && has(TagKind::Timestamp),
            tag_r: opts.mimic.tag_r && has(TagKind::Random),
            tag_rc: opts.mimic.tag_rc && has(TagKind::RandomLetters) && client.supports_tag_rc,
            tag_rd: opts.mimic.tag_rd && has(TagKind::RandomDigits) && client.supports_tag_rd,
            router_mode: opts.router_mode,
            ..opts.mimic.clone()
        };
        Some(mimic::generate_chains(
            rng,
            opts.profile,
            opts.intensity,
            &mimic,
        ))
    } else {
        None
    };

    let awg3 = if opts.version.supports_awg3() {
        Some(awg3::generate(
            rng,
            Awg3Options {
                header_protection: opts.header_protection,
                content_padding: opts.content_padding,
                random_timings: opts.random_timings,
                // The 3.1 switches exist only where the version reads them:
                // a 3.0 device refuses both keys at config parse.
                random_trailers: opts.random_trailers && opts.version.supports_feature_flags(),
                disable_cookies: opts.disable_cookies && opts.version.supports_feature_flags(),
                intensity: opts.intensity,
                router_mode: opts.router_mode,
            },
        )?)
    } else {
        None
    };

    let params = VersionedParams {
        version: opts.version,
        profile: opts.profile,
        base,
        h_hi,
        chains,
        awg3,
    };

    // Safety net: never hand out a config our own validator would refuse.
    let fatal: Vec<String> = validate_for_client(&params, client)
        .into_iter()
        .filter(|v| v.level == Level::Error)
        .map(|v| format!("{}: {}", v.field, v.message))
        .collect();
    if !fatal.is_empty() {
        return Err(Error::Invariant(format!(
            "generated config failed its own validation: {}",
            fatal.join("; ")
        )));
    }

    Ok(params)
}

// -------------------------------------------------------------- validators

/// Check a parameter set against one client, returning every concrete problem.
///
/// Errors are configs that will be refused or that will fail silently; warnings
/// are configs that work and give something away.
pub fn validate_for_client(params: &VersionedParams, client: &ClientCapability) -> Vec<Violation> {
    let mut out = Vec::new();
    let v = params.version;

    // ---- magic headers
    let ranges: [UintRange; 4] = [
        params.h_range(0),
        params.h_range(1),
        params.h_range(2),
        params.h_range(3),
    ];
    for i in 0..4 {
        for j in (i + 1)..4 {
            if ranges[i].lo <= ranges[j].hi && ranges[j].lo <= ranges[i].hi {
                out.push(Violation::err(
                    format!("H{}/H{}", i + 1, j + 1),
                    "h.overlap",
                    format!(
                        "H{} ({}) and H{} ({}) overlap; the daemon demultiplexes on this number \
                         alone, so a packet in the overlap belongs to two message types",
                        i + 1,
                        ranges[i],
                        j + 1,
                        ranges[j]
                    ),
                ));
            }
        }
        if (1..=4).contains(&ranges[i].lo) {
            out.push(Violation::warn(
                format!("H{}", i + 1),
                "h.reserved",
                format!(
                    "H{} starts at {} — 1..4 are the WireGuard message types this field replaces",
                    i + 1,
                    ranges[i].lo
                ),
            ));
        }
        if ranges[i].hi > client.max_h_value {
            out.push(Violation::err(
                format!("H{}", i + 1),
                "client.h_cap",
                format!(
                    "H{} reaches {} but {} accepts at most {}{}",
                    i + 1,
                    ranges[i].hi,
                    client.name,
                    client.max_h_value,
                    if client.max_h_value == INT32_MAX {
                        " (INT32_MAX — issue #85)"
                    } else {
                        ""
                    }
                ),
            ));
        }
    }

    // ---- padding sizes
    let s = params.base.s;
    if s[0] + INIT_RESPONSE_DELTA == s[1] {
        out.push(Violation::err(
            "S2",
            "s.init_response_collision",
            format!(
                "S1 ({}) + {INIT_RESPONSE_DELTA} = S2 ({}) — a padded initiation would be exactly \
                 the size of a response, and the daemon refuses the pair",
                s[0], s[1]
            ),
        ));
    }
    if v.supports_s3_s4() {
        if s[2] == s[0] + INIT_COOKIE_DELTA {
            out.push(Violation::warn(
                "S3",
                "s.cookie_init_collision",
                format!("S3 = S1 + {INIT_COOKIE_DELTA} — a cookie reply and an initiation would be the same size"),
            ));
        }
        if s[2] == s[1] + RESPONSE_COOKIE_DELTA {
            out.push(Violation::warn(
                "S3",
                "s.cookie_response_collision",
                format!("S3 = S2 + {RESPONSE_COOKIE_DELTA} — a cookie reply and a response would be the same size"),
            ));
        }
        if s[3] > MAX_S4 {
            out.push(Violation::err(
                "S4",
                "s.over_protocol_max",
                format!("S4 = {} exceeds the protocol maximum of {MAX_S4}", s[3]),
            ));
        }
        if s[3] > client.max_s4 {
            out.push(Violation::err(
                "S4",
                "client.s4_cap",
                format!(
                    "S4 = {} exceeds the maximum of {} for {}",
                    s[3], client.max_s4, client.name
                ),
            ));
        }
        if s[3] == 0 {
            out.push(Violation::warn(
                "S4",
                "s.zero",
                "S4 = 0 — transport packets are left unobfuscated".to_string(),
            ));
        }
    }

    // ---- junk train
    if params.base.jmin > params.base.jmax {
        out.push(Violation::err(
            "Jmax",
            "j.inverted",
            format!(
                "Jmin ({}) exceeds Jmax ({})",
                params.base.jmin, params.base.jmax
            ),
        ));
    }
    if params.base.jc > client.max_jc {
        out.push(Violation::warn(
            "Jc",
            "client.jc_cap",
            format!(
                "Jc = {} exceeds the recommended maximum of {} for {}",
                params.base.jc, client.max_jc, client.name
            ),
        ));
    }
    if v == AwgVersion::V1_0 && params.base.jmax <= 81 {
        out.push(Violation::warn(
            "Jmax",
            "j.v10_floor",
            format!(
                "Jmax = {} — AWG 1.0 clients want more than 81 here",
                params.base.jmax
            ),
        ));
    }

    // ---- CPS chains
    match &params.chains {
        Some(chains) => {
            if !v.supports_cps() {
                out.push(Violation::err(
                    "I1-I5",
                    "version.cps_unsupported",
                    format!("I1-I5 are set but AWG {v} has no CPS chains"),
                ));
            }
            if !client.supports_i1_i5 {
                out.push(Violation::err(
                    "I1-I5",
                    "client.i1_i5",
                    format!("{} does not implement I1-I5", client.name),
                ));
            }
            for (i, raw) in chains.iter().enumerate() {
                let field = format!("I{}", i + 1);
                let chain = match Chain::parse(raw) {
                    Ok(c) => c,
                    Err(e) => {
                        out.push(Violation::err(field.clone(), "chain.syntax", e.to_string()));
                        continue;
                    }
                };
                // One complaint per tag kind per chain: a chain with forty
                // `<rc>` tags has one problem, not forty.
                let mut reported: Vec<&'static str> = Vec::new();
                let mut complain = |out: &mut Vec<Violation>, code, message: String| {
                    if !reported.contains(&code) {
                        reported.push(code);
                        out.push(Violation::err(field.clone(), code, message));
                    }
                };

                let vocab = v.chain_tags();
                let mut seen: Vec<TagKind> = Vec::new();
                for tag in chain.tags() {
                    let kind = tag.kind();
                    // The daemon's own vocabulary is checked before the client's:
                    // a tag this generation never had is wrong on every client,
                    // and saying so names the thing that has to change.
                    if !vocab.contains(&kind) {
                        complain(
                            &mut out,
                            "version.tag_vocabulary",
                            format!(
                                "{field} uses {}, which the AWG {v} parser has no builder for — \
                                 the daemon answers `invalid tag`, not a shorter packet",
                                kind.as_str()
                            ),
                        );
                        continue;
                    }
                    if v.chain_tags_must_be_unique().contains(&kind) && seen.contains(&kind) {
                        complain(
                            &mut out,
                            "version.tag_not_unique",
                            format!(
                                "{field} uses {} more than once; the AWG {v} parser allows one \
                                 per chain",
                                kind.as_str()
                            ),
                        );
                    }
                    seen.push(kind);

                    let (supported, name, code) = match tag {
                        Tag::Counter => (client.supports_tag_c, "<c>", "client.tag_c"),
                        Tag::RandomLetters(_) => {
                            (client.supports_tag_rc, "<rc N>", "client.tag_rc")
                        }
                        Tag::RandomDigits(_) => (client.supports_tag_rd, "<rd N>", "client.tag_rd"),
                        _ => continue,
                    };
                    if !supported {
                        complain(
                            &mut out,
                            code,
                            format!(
                                "{field} uses {name}, which {} does not implement",
                                client.name
                            ),
                        );
                    }
                }
            }
        }
        None => {
            if v.supports_cps() && client.supports_i1_i5 {
                out.push(Violation::warn(
                    "I1-I5",
                    "version.cps_missing",
                    format!("AWG {v} supports I1-I5 but none were generated"),
                ));
            }
        }
    }

    // ---- 3.0 block
    if let Some(p) = &params.awg3 {
        if !v.supports_awg3() && !p.is_empty() {
            out.push(Violation::err(
                "AWG3",
                "version.awg3_mismatch",
                format!("3.0 parameters are set but the config version is {v}"),
            ));
        }
        if !v.supports_feature_flags() && (p.random_trailers || p.disable_cookies) {
            out.push(Violation::warn(
                "RandomTrailers",
                "awg3.flags_version_mismatch",
                format!(
                    "3.1 switches are set but the config version is {v} — a 3.0 device refuses these keys"
                ),
            ));
        }
        if p.disable_cookies {
            out.push(Violation::warn(
                "DisableCookies",
                "awg3.cookies_off",
                "DisableCookies also switches the junk train off and breaks NAT keepalive under load".to_string(),
            ));
        }
        if let Err(e) = p.validate() {
            out.push(Violation::err("AWG3", "awg3.timers", e.to_string()));
        }
        if p.header_protection_key.is_some() {
            // send.go slices the ChaCha20 nonce out of the S-padding; padding
            // shorter than the nonce makes it overlap the message body instead
            // of random bytes, with nothing logged either way.
            for (i, value) in s.iter().enumerate() {
                if *value < MIN_S_WITH_HEADER_PROTECTION {
                    out.push(Violation::err(
                        format!("S{}", i + 1),
                        "awg3.s_below_nonce",
                        format!(
                            "S{} = {value} is below {MIN_S_WITH_HEADER_PROTECTION}; with a \
                             HeaderProtectionKey the cipher nonce comes out of this padding",
                            i + 1
                        ),
                    ));
                }
            }
        }
        if let Some(r) = p.content_padding_addition
            && r.hi < 1
        {
            out.push(Violation::warn(
                "ContentPaddingAddition",
                "awg3.cpa_zero",
                "ContentPaddingAddition = 0 — the extra transport padding is off".to_string(),
            ));
        }
    } else if v.supports_awg3() {
        out.push(Violation::warn(
            "AWG3",
            "version.awg3_missing",
            "AWG 3.0 selected but no 3.0 parameters were generated".to_string(),
        ));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mimic::BrowserProfile;
    use crate::rng::SeededRng;
    use std::collections::BTreeSet;

    fn make(version: AwgVersion, seed: u64) -> VersionedParams {
        generate(
            &mut SeededRng::new(seed),
            &GenOptions {
                version,
                // The 3.1 switches must be on for the field-set test to see
                // them: a config with both off is wire-identical to a 3.0 one
                // and renders exactly the 3.0 field list.
                random_trailers: version.supports_feature_flags(),
                disable_cookies: version.supports_feature_flags(),
                ..Default::default()
            },
        )
        .expect("generation must satisfy its own validator")
    }

    fn kv(lines: &[String]) -> BTreeSet<String> {
        lines
            .iter()
            .filter_map(|l| l.split_once(" = ").map(|(k, _)| k.to_string()))
            .collect()
    }

    #[test]
    fn every_version_generates_across_many_seeds() {
        for v in AwgVersion::ALL {
            for seed in 0..200u64 {
                let p = make(v, seed);
                assert_eq!(p.version, v);
                let errs: Vec<_> = validate_for_client(&p, default_client())
                    .into_iter()
                    .filter(|x| x.level == Level::Error)
                    .collect();
                assert!(errs.is_empty(), "{v} seed {seed}: {errs:?}");
            }
        }
    }

    #[test]
    fn each_version_renders_exactly_the_fields_it_supports() {
        for v in AwgVersion::ALL {
            let p = make(v, 42);
            let rendered = kv(&p.conf_lines());
            let expected: BTreeSet<String> = v.fields().iter().map(|s| (*s).to_string()).collect();
            assert_eq!(rendered, expected, "AWG {v} field set");
        }
    }

    #[test]
    fn v31_switches_render_only_when_on_and_only_for_31() {
        // On, on a version that reads them: both keys, in the .conf and over
        // UAPI in the daemon's own spelling.
        let p = make(AwgVersion::V3_1, 7);
        let conf = p.conf_lines().join("\n");
        assert!(conf.contains("RandomTrailers = 1"), "{conf}");
        assert!(conf.contains("DisableCookies = 1"), "{conf}");
        let uapi = p.uapi_lines().join("\n");
        assert!(uapi.contains("random_trailers=1"), "{uapi}");
        assert!(uapi.contains("disable_cookies=1"), "{uapi}");

        // Off: neither spelling anywhere — a 3.1 config with both switches
        // down is wire-identical to a 3.0 one and must look like it.
        let quiet = generate(
            &mut SeededRng::new(7),
            &GenOptions {
                version: AwgVersion::V3_1,
                ..Default::default()
            },
        )
        .expect("generation must satisfy its own validator");
        let conf = quiet.conf_lines().join("\n");
        assert!(!conf.contains("RandomTrailers"), "{conf}");
        assert!(!conf.contains("DisableCookies"), "{conf}");
        assert!(
            !quiet
                .uapi_lines()
                .iter()
                .any(|l| l.contains("random_trailers") || l.contains("disable_cookies"))
        );

        // Asked for on a 3.0 generation: the capability gate eats the wish —
        // a 3.0 device refuses both keys at config parse.
        let v30 = generate(
            &mut SeededRng::new(7),
            &GenOptions {
                version: AwgVersion::V3_0,
                random_trailers: true,
                disable_cookies: true,
                ..Default::default()
            },
        )
        .expect("generation must satisfy its own validator");
        let conf = v30.conf_lines().join("\n");
        assert!(!conf.contains("RandomTrailers"), "{conf}");
        assert!(!conf.contains("DisableCookies"), "{conf}");
    }

    #[test]
    fn v1_0_carries_no_chains_and_no_s3_s4() {
        let p = make(AwgVersion::V1_0, 3);
        assert!(p.chains.is_none());
        assert!(p.awg3.is_none());
        assert!(p.h_hi.is_none());
        let conf = p.conf_lines().join("\n");
        assert!(conf.contains("# I1-I5 are not supported in AWG 1.0"));
        for absent in ["S3 = ", "S4 = ", "I1 = ", "HeaderProtectionKey"] {
            assert!(!conf.contains(absent), "1.0 emitted {absent}:\n{conf}");
        }
        // A 1.x header is one number, not a range.
        assert!(
            !conf
                .lines()
                .any(|l| l.starts_with("H1 = ") && l.contains('-'))
        );
    }

    #[test]
    fn v1_5_has_chains_and_says_they_are_client_side_only() {
        let p = make(AwgVersion::V1_5, 4);
        assert!(p.chains.is_some());
        assert!(p.h_hi.is_none(), "1.5 headers are still single values");
        let conf = p.conf_lines().join("\n");
        assert!(conf.contains("client-side only in AWG 1.5"));
        assert!(conf.contains("I1 = "));
        assert!(!conf.contains("S3 = "));
    }

    #[test]
    fn v2_0_turns_headers_into_ranges_and_adds_s3_s4() {
        let p = make(AwgVersion::V2_0, 5);
        assert!(p.h_hi.is_some());
        let conf = p.conf_lines().join("\n");
        assert!(conf.contains("S3 = ") && conf.contains("S4 = "));
        assert!(!conf.contains("HeaderProtectionKey"));
        // At least one header must actually be a range, or 2.0 gained nothing.
        assert!(
            (0..4).any(|i| p.h_range(i).lo != p.h_range(i).hi),
            "no header widened into a range"
        );
    }

    #[test]
    fn v3_0_adds_the_header_key_padding_and_timers_on_top_of_2_0() {
        let p = make(AwgVersion::V3_0, 6);
        let conf = p.conf_lines().join("\n");
        for expected in [
            "HeaderProtectionKey = ",
            "ContentPaddingAddition = ",
            "RekeyAfterTime = ",
            "RejectAfterTime = ",
            "MaxHandshakeAttempts = ",
            "S4 = ",
            "I1 = ",
        ] {
            assert!(conf.contains(expected), "3.0 is missing {expected}");
        }
        // The nonce floor has to hold, or the header cipher quietly weakens.
        assert!(p.base.s.iter().all(|s| *s >= MIN_S_WITH_HEADER_PROTECTION));
    }

    #[test]
    fn header_ranges_never_overlap() {
        for seed in 0..300u64 {
            let p = make(AwgVersion::V3_0, seed);
            let mut spans: Vec<UintRange> = (0..4).map(|i| p.h_range(i)).collect();
            spans.sort_by_key(|r| r.lo);
            for w in spans.windows(2) {
                assert!(
                    w[0].hi < w[1].lo,
                    "seed {seed}: {} and {} overlap",
                    w[0],
                    w[1]
                );
            }
        }
    }

    #[test]
    fn the_windows_int32_cap_is_reported_with_the_field_named() {
        // Issue #85: the Windows client parses H into a signed 32-bit integer.
        // Every other header is pinned below the cap: generation targets the
        // default client's UINT32_MAX ceiling, so seed 7 may carry a second
        // header past INT32_MAX and the test would name two fields, not one.
        let mut p = make(AwgVersion::V2_0, 7);
        p.base.h = [100, 200, 3_000_000_000, 400];
        let hi = p.h_hi.as_mut().unwrap();
        hi[0] = 150;
        hi[1] = 250;
        hi[2] = 3_000_100_000;
        hi[3] = 450;

        let win = client("amneziawg-windows").unwrap();
        let found: Vec<_> = validate_for_client(&p, win)
            .into_iter()
            .filter(|v| v.code == "client.h_cap")
            .collect();
        assert_eq!(found.len(), 1, "expected exactly one H cap violation");
        assert_eq!(found[0].field, "H3", "the violating field must be named");
        assert_eq!(found[0].level, Level::Error);
        assert!(found[0].message.contains("2147483647"));
        assert!(found[0].message.contains("issue #85"));
        assert!(found[0].message.contains("AmneziaWG Windows"));

        // The same value is fine on a client that reads the full 32-bit range.
        assert!(
            validate_for_client(&p, default_client())
                .iter()
                .all(|v| v.code != "client.h_cap")
        );
    }

    #[test]
    fn generation_for_windows_never_trips_its_own_cap() {
        let win = client("amneziawg-windows").unwrap();
        for seed in 0..300u64 {
            let p = generate(
                &mut SeededRng::new(seed),
                &GenOptions {
                    version: AwgVersion::V3_0,
                    client: win,
                    ..Default::default()
                },
            )
            .unwrap();
            for i in 0..4 {
                assert!(
                    p.h_range(i).hi <= INT32_MAX,
                    "seed {seed}: H{} overflows",
                    i + 1
                );
            }
        }
    }

    #[test]
    fn tags_a_client_cannot_parse_are_never_generated_for_it() {
        // Windows, WireSock, WG Tunnel and legacy amneziawg-go implement none of
        // <c>, <rc> and <rd>; a chain using one is refused outright, not degraded.
        for id in [
            "amneziawg-windows",
            "wiresock",
            "wg-tunnel",
            "awg-go-legacy",
        ] {
            let c = client(id).unwrap();
            for seed in 0..40u64 {
                let p = generate(
                    &mut SeededRng::new(seed),
                    &GenOptions {
                        version: AwgVersion::V2_0,
                        client: c,
                        mimic: MimicOptions {
                            tag_c: true,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                )
                .unwrap();
                let joined = p.chains.as_ref().unwrap().join("");
                assert!(!joined.contains("<c>"), "{id} got <c>");
                assert!(!joined.contains("<rc "), "{id} got <rc>");
                assert!(!joined.contains("<rd "), "{id} got <rd>");
                assert!(
                    validate_for_client(&p, c)
                        .iter()
                        .all(|v| v.level != Level::Error)
                );
            }
        }
    }

    #[test]
    fn an_unsupported_tag_smuggled_into_a_chain_is_reported_by_field() {
        // Generated for Windows, so the chains start clean and the only tags it
        // cannot parse are the ones planted here.
        let win = client("amneziawg-windows").unwrap();
        let mut p = generate(
            &mut SeededRng::new(9),
            &GenOptions {
                version: AwgVersion::V2_0,
                client: win,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            validate_for_client(&p, win)
                .iter()
                .all(|v| v.level != Level::Error)
        );

        // `<c>` is left out: on 2.0 that is the daemon's problem before it is
        // Windows' — see tags_outside_the_version_vocabulary_are_reported.
        p.chains.as_mut().unwrap()[2] = "<b 0xdead><rc 12><rd 4>".into();
        let found = validate_for_client(&p, win);
        for code in ["client.tag_rc", "client.tag_rd"] {
            let hits: Vec<_> = found.iter().filter(|v| v.code == code).collect();
            assert_eq!(hits.len(), 1, "{code} in {found:?}");
            assert_eq!(hits[0].field, "I3", "the offending chain must be named");
            assert_eq!(hits[0].level, Level::Error);
            assert!(hits[0].message.contains("AmneziaWG Windows"));
        }
    }

    #[test]
    fn every_version_emits_only_tags_its_own_daemon_parses() {
        // The regression this exists for: `gen --version 1.5` shipped <rc>/<rd>,
        // which the 1.5 parser has never had, and the interface answered
        // `IPC error -22: invalid i1: invalid tag: rc`.
        for v in [AwgVersion::V1_5, AwgVersion::V2_0, AwgVersion::V3_0] {
            let vocab = v.chain_tags();
            for c in CLIENTS.iter() {
                for profile in MimicProfile::ALL {
                    for seed in 0..25u64 {
                        let p = generate(
                            &mut SeededRng::new(seed),
                            &GenOptions {
                                version: v,
                                profile,
                                client: c,
                                mimic: MimicOptions {
                                    mimic_all: true,
                                    // Ask for everything; the version gate is
                                    // what has to say no.
                                    tag_c: true,
                                    ..Default::default()
                                },
                                ..Default::default()
                            },
                        )
                        .unwrap();
                        for (i, raw) in p.chains.as_ref().unwrap().iter().enumerate() {
                            let chain = Chain::parse(raw).unwrap();
                            for tag in chain.tags() {
                                assert!(
                                    vocab.contains(&tag.kind()),
                                    "AWG {v} {} {} I{} emitted {}: {raw}",
                                    c.id,
                                    profile.id(),
                                    i + 1,
                                    tag.kind().as_str()
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn the_two_vocabularies_are_the_upstream_ones() {
        // Spelled out rather than derived, so that changing chain_tags() to
        // match a misremembered daemon fails here instead of in a tunnel.
        assert!(AwgVersion::V1_0.chain_tags().is_empty());

        // device/awg/tag_parser.go: b, c, t, r, wt.
        let v15 = AwgVersion::V1_5.chain_tags();
        assert!(v15.contains(&TagKind::Counter), "1.5 has <c>");
        assert!(!v15.contains(&TagKind::RandomLetters), "1.5 has no <rc>");
        assert!(!v15.contains(&TagKind::RandomDigits), "1.5 has no <rd>");

        // device/obf.go: b, t, r, rc, rd, d, ds, dz — note the absence of c.
        for v in [AwgVersion::V2_0, AwgVersion::V3_0] {
            let tags = v.chain_tags();
            assert!(!tags.contains(&TagKind::Counter), "{v} has no <c>");
            assert!(tags.contains(&TagKind::RandomLetters), "{v} has <rc>");
            assert!(tags.contains(&TagKind::RandomDigits), "{v} has <rd>");
        }
    }

    #[test]
    fn v1_5_actually_uses_the_counter_tag_it_is_allowed() {
        // <c> is the only tag 1.5 gained over the padding primitives, and until
        // this fix the generator never emitted it on any version.
        let mut with_counter = 0;
        for seed in 0..25u64 {
            let p = generate(
                &mut SeededRng::new(seed),
                &GenOptions {
                    version: AwgVersion::V1_5,
                    ..Default::default()
                },
            )
            .unwrap();
            if p.chains.as_ref().unwrap().join("").contains("<c>") {
                with_counter += 1;
            }
        }
        assert!(with_counter > 0, "1.5 never emitted <c>");

        // ...but not for the clients that never implemented it.
        for id in ["amneziawg-windows", "wiresock", "awg-go-legacy"] {
            let c = client(id).unwrap();
            for seed in 0..25u64 {
                let p = generate(
                    &mut SeededRng::new(seed),
                    &GenOptions {
                        version: AwgVersion::V1_5,
                        client: c,
                        ..Default::default()
                    },
                )
                .unwrap();
                assert!(
                    !p.chains.as_ref().unwrap().join("").contains("<c>"),
                    "{id} got <c>"
                );
            }
        }
    }

    #[test]
    fn tags_outside_the_version_vocabulary_are_reported() {
        for (v, planted, spelled) in [
            (AwgVersion::V1_5, "<b 0x01><rc 12>", "<rc N>"),
            (AwgVersion::V1_5, "<b 0x01><rd 4>", "<rd N>"),
            (AwgVersion::V2_0, "<b 0x01><c>", "<c>"),
            (AwgVersion::V3_0, "<b 0x01><c>", "<c>"),
        ] {
            let mut p = make(v, 3);
            p.chains.as_mut().unwrap()[0] = planted.into();
            let found = validate_for_client(&p, default_client());
            let hit = found
                .iter()
                .find(|x| x.code == "version.tag_vocabulary")
                .unwrap_or_else(|| panic!("AWG {v} accepted {planted}: {found:?}"));
            assert_eq!(hit.field, "I1");
            assert_eq!(hit.level, Level::Error);
            assert!(hit.message.contains(spelled), "{}", hit.message);
        }
    }

    #[test]
    fn a_tag_1_5_wants_unique_is_reported_when_repeated() {
        let mut p = make(AwgVersion::V1_5, 4);
        p.chains.as_mut().unwrap()[0] = "<b 0x01><t><r 8><t>".into();
        let found = validate_for_client(&p, default_client());
        let hit = found
            .iter()
            .find(|x| x.code == "version.tag_not_unique")
            .unwrap_or_else(|| panic!("repeated <t> accepted on 1.5: {found:?}"));
        assert_eq!(hit.field, "I1");

        // 2.0 parses chains with device/obf.go, which has no uniqueness rule.
        let mut p = make(AwgVersion::V2_0, 4);
        p.chains.as_mut().unwrap()[0] = "<b 0x01><t><r 8><t>".into();
        assert!(
            validate_for_client(&p, default_client())
                .iter()
                .all(|x| x.code != "version.tag_not_unique")
        );
    }

    #[test]
    fn a_malformed_chain_is_reported_rather_than_shipped() {
        let mut p = make(AwgVersion::V2_0, 10);
        p.chains.as_mut().unwrap()[0] = "<b 0xabc>".into();
        let v = validate_for_client(&p, default_client());
        let found = v
            .iter()
            .find(|v| v.code == "chain.syntax")
            .expect("no syntax error");
        assert_eq!(found.field, "I1");
        assert!(found.message.contains("odd number of hex digits"));
    }

    #[test]
    fn the_s4_and_jc_caps_are_reported_with_the_field_named() {
        let mut p = make(AwgVersion::V2_0, 11);
        p.base.s[3] = 40;
        p.base.jc = 64;
        let found = validate_for_client(&p, default_client());

        let s4: Vec<_> = found.iter().filter(|v| v.field == "S4").collect();
        assert!(
            s4.iter()
                .any(|v| v.code == "s.over_protocol_max" && v.level == Level::Error),
            "S4 = 40 must be refused: {found:?}"
        );
        assert!(s4.iter().any(|v| v.code == "client.s4_cap"));
        assert!(s4[0].message.contains("40"));

        let jc = found
            .iter()
            .find(|v| v.code == "client.jc_cap")
            .expect("no Jc finding");
        assert_eq!(jc.field, "Jc");
        assert_eq!(jc.level, Level::Warn, "Jc over the cap still connects");
        assert!(jc.message.contains("Amnezia VPN"));
    }

    #[test]
    fn overlapping_headers_are_refused_with_both_fields_named() {
        let mut p = make(AwgVersion::V2_0, 12);
        let (lo0, hi0) = (p.base.h[0], p.h_hi.unwrap()[0]);
        p.base.h[1] = lo0;
        p.h_hi.as_mut().unwrap()[1] = hi0;
        let found = validate_for_client(&p, default_client());
        let v = found
            .iter()
            .find(|v| v.code == "h.overlap")
            .expect("overlap not caught");
        assert_eq!(v.field, "H1/H2");
        assert_eq!(v.level, Level::Error);
    }

    #[test]
    fn the_s1_s2_size_collision_is_refused() {
        let mut p = make(AwgVersion::V3_0, 13);
        p.base.s[1] = p.base.s[0] + INIT_RESPONSE_DELTA;
        let found = validate_for_client(&p, default_client());
        assert!(
            found
                .iter()
                .any(|v| v.code == "s.init_response_collision" && v.level == Level::Error)
        );
    }

    #[test]
    fn a_short_s_under_a_header_key_is_refused_by_field() {
        let mut p = make(AwgVersion::V3_0, 14);
        p.base.s[2] = 4;
        let found = validate_for_client(&p, default_client());
        let v = found
            .iter()
            .find(|v| v.code == "awg3.s_below_nonce")
            .expect("short S not caught");
        assert_eq!(v.field, "S3");
        assert!(v.message.contains("HeaderProtectionKey"));
    }

    #[test]
    fn a_3_0_block_on_a_2_0_config_is_refused() {
        let mut p = make(AwgVersion::V3_0, 15);
        p.version = AwgVersion::V2_0;
        let found = validate_for_client(&p, default_client());
        assert!(found.iter().any(|v| v.code == "version.awg3_mismatch"));
    }

    #[test]
    fn chains_on_a_1_0_config_are_refused() {
        let mut p = make(AwgVersion::V1_5, 16);
        p.version = AwgVersion::V1_0;
        let found = validate_for_client(&p, default_client());
        assert!(found.iter().any(|v| v.code == "version.cps_unsupported"));
    }

    #[test]
    fn generated_timers_and_sizes_hold_across_modes() {
        use crate::awg3::Intensity as I;
        for seed in 0..60u64 {
            for intensity in [I::Low, I::Medium, I::High] {
                for (router_mode, extreme) in [(false, false), (true, false), (false, true)] {
                    for version in AwgVersion::ALL {
                        let mut rng = SeededRng::new(seed);
                        let p = generate(
                            &mut rng,
                            &GenOptions {
                                version,
                                intensity,
                                router_mode,
                                extreme,
                                ..Default::default()
                            },
                        )
                        .expect("generated params must satisfy their own invariants");
                        let s = p.base.s;
                        assert_eq!(s[2], if version.supports_s3_s4() { s[2] } else { 0 });
                        let max_s4 = MAX_S4.min(default_client().max_s4);
                        assert!(s[3] <= max_s4, "S4 exceeds the cap");
                        if version.supports_s3_s4() {
                            assert_ne!(
                                s[1],
                                s[0] + INIT_RESPONSE_DELTA,
                                "seed {seed}: S collision"
                            );
                            assert_ne!(s[2], s[0] + INIT_COOKIE_DELTA, "seed {seed}: S collision");
                            assert_ne!(
                                s[2],
                                s[1] + RESPONSE_COOKIE_DELTA,
                                "seed {seed}: S collision"
                            );
                            assert!(p.base.jmin <= p.base.jmax, "seed {seed}: junk inverted");
                        }
                        if p.awg3
                            .as_ref()
                            .is_some_and(|p| p.header_protection_key.is_some())
                        {
                            for (i, v) in s.iter().enumerate() {
                                assert!(
                                    *v >= MIN_S_WITH_HEADER_PROTECTION,
                                    "seed {seed}: S{} below the nonce floor",
                                    i + 1
                                );
                            }
                        }
                        if version.h_is_range() {
                            let ranges: [UintRange; 4] =
                                [p.h_range(0), p.h_range(1), p.h_range(2), p.h_range(3)];
                            for r in &ranges {
                                assert!(r.hi <= default_client().max_h_value);
                            }
                            for i in 0..4 {
                                for j in (i + 1)..4 {
                                    assert!(
                                        ranges[i].hi < ranges[j].lo || ranges[j].hi < ranges[i].lo,
                                        "seed {seed}: H{} and H{} overlap",
                                        i + 1,
                                        j + 1
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn router_junk_is_drawn_not_constant() {
        use std::collections::BTreeSet;
        let mut triples = BTreeSet::new();
        for seed in 0..200u64 {
            let p = generate(
                &mut SeededRng::new(seed),
                &GenOptions {
                    router_mode: true,
                    ..Default::default()
                },
            )
            .unwrap();
            triples.insert((p.base.jc, p.base.jmin, p.base.jmax));
        }
        assert!(
            triples.len() > 10,
            "every router config carries the same junk train"
        );
    }

    #[test]
    fn narrow_h_stays_inside_small_windows_on_3_1() {
        for seed in 0..50u64 {
            let p = generate(
                &mut SeededRng::new(seed),
                &GenOptions {
                    version: AwgVersion::V3_1,
                    narrow_h: true,
                    ..Default::default()
                },
            )
            .unwrap();
            for i in 0..4 {
                let r = p.h_range(i);
                assert!(r.hi - r.lo <= 80_000, "H{} too wide: {r}", i + 1);
            }
        }
    }

    #[test]
    fn narrow_h_is_ignored_off_3_1() {
        let p = generate(
            &mut SeededRng::new(9),
            &GenOptions {
                version: AwgVersion::V3_0,
                narrow_h: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            !(0..4).all(|i| p.h_range(i).hi - p.h_range(i).lo <= 80_000)
                || p.h_range(0).lo >= 100_000_000 - 1,
            "narrow_h must not narrow 3.0 headers"
        );
    }

    #[test]
    fn the_same_seed_gives_the_same_config() {
        for v in AwgVersion::ALL {
            let a = make(v, 777);
            let b = make(v, 777);
            assert_eq!(
                a.conf_lines(),
                b.conf_lines(),
                "AWG {v} is not reproducible"
            );
            assert_eq!(a.uapi_lines(), b.uapi_lines());
        }
    }

    #[test]
    fn different_seeds_give_different_configs() {
        for v in AwgVersion::ALL {
            let mut seen = BTreeSet::new();
            for seed in 0..50u64 {
                seen.insert(make(v, seed).conf_lines().join("\n"));
            }
            assert_eq!(seen.len(), 50, "AWG {v} repeats itself");
        }
    }

    #[test]
    fn the_conf_and_uapi_renderings_carry_the_same_numbers() {
        // They diverge in spelling only; a value in one and not the other is a
        // tunnel that never completes a handshake and reports nothing.
        for v in AwgVersion::ALL {
            let p = make(v, 21);
            let conf = kv(&p.conf_lines());
            let uapi: BTreeSet<String> = p
                .uapi_lines()
                .iter()
                .filter_map(|l| l.split_once('=').map(|(k, _)| k.to_string()))
                .collect();
            let normalised: BTreeSet<String> = conf
                .iter()
                .map(|k| {
                    // .conf uses CamelCase, UAPI lowercases and drops the spaces.
                    let mut out = String::new();
                    for (i, ch) in k.chars().enumerate() {
                        if ch.is_uppercase() && i > 0 {
                            out.push('_');
                        }
                        out.push(ch.to_ascii_lowercase());
                    }
                    out
                })
                .collect();
            assert_eq!(normalised, uapi, "AWG {v}: .conf and UAPI key sets differ");
        }
    }

    #[test]
    fn router_mode_keeps_the_junk_small() {
        // Architect's `routerMode` is a cap on top of the normal draw, and the
        // normal draw starts from `junk_level` (default 5): 5±1 capped at 3 is
        // 3, not 2. The test pins the wire promise — the train stays short —
        // rather than the intermediate draw.
        for v in AwgVersion::ALL {
            for seed in 0..100u64 {
                let p = generate(
                    &mut SeededRng::new(seed),
                    &GenOptions {
                        version: v,
                        router_mode: true,
                        ..Default::default()
                    },
                )
                .unwrap();
                assert!(p.base.jmax <= 128, "{v} seed {seed}: Jmax {}", p.base.jmax);
                assert!(p.base.jmin <= 40);
                if v != AwgVersion::V1_0 {
                    assert!(p.base.jc <= 3, "{v} seed {seed}: Jc {}", p.base.jc);
                }
                if let Some(chains) = &p.chains {
                    assert!(chains[1..].iter().all(|c| c.is_empty()));
                }
            }
        }
    }

    #[test]
    fn the_client_matrix_matches_the_upstream_table() {
        assert_eq!(CLIENTS.len(), 10);
        let mut ids = BTreeSet::new();
        for c in &CLIENTS {
            assert!(ids.insert(c.id), "duplicate client id {}", c.id);
            assert!(!c.name.is_empty() && !c.platforms.is_empty());
            assert!(c.max_s4 <= MAX_S4);
            assert!(c.max_h_value == UINT32_MAX || c.max_h_value == INT32_MAX);
        }
        assert_eq!(client("amneziawg-windows").unwrap().max_h_value, INT32_MAX);
        assert!(!client("awg-go-legacy").unwrap().supports_tag_c);
        assert_eq!(client("keenetic-native").unwrap().max_jc, 128);
        assert_eq!(default_client().id, DEFAULT_CLIENT_ID);
        assert!(client("does-not-exist").is_none());
    }

    #[test]
    fn version_strings_round_trip() {
        for v in AwgVersion::ALL {
            assert_eq!(AwgVersion::parse(v.as_str()), Some(v));
        }
        assert_eq!(AwgVersion::parse(" 2.0 "), Some(AwgVersion::V2_0));
        assert_eq!(AwgVersion::parse("4.0"), None);
        assert!(AwgVersion::V1_0 < AwgVersion::V1_5);
        assert!(AwgVersion::V2_0 < AwgVersion::V3_0);
    }

    #[test]
    fn a_browser_fingerprint_survives_into_the_generated_chains() {
        let p = generate(
            &mut SeededRng::new(31),
            &GenOptions {
                version: AwgVersion::V2_0,
                profile: MimicProfile::QuicInitial,
                mimic: MimicOptions {
                    browser: Some(BrowserProfile::YandexMobile),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        // Yandex Browser on mobile sends a 1232-byte Initial.
        let i1 = Chain::parse(&p.chains.unwrap()[0]).unwrap();
        assert_eq!(i1.wire_len(), 1232);
    }

    #[test]
    fn every_profile_generates_for_every_version() {
        for v in AwgVersion::ALL {
            for profile in MimicProfile::ALL {
                let p = generate(
                    &mut SeededRng::new(55),
                    &GenOptions {
                        version: v,
                        profile,
                        ..Default::default()
                    },
                )
                .unwrap();
                assert_eq!(p.profile, profile);
                if v.supports_cps() {
                    assert!(!p.chains.as_ref().unwrap()[0].is_empty());
                }
            }
        }
    }
}
