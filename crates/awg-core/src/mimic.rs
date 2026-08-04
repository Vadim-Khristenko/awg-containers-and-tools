//! Protocol mimicry — the I1–I5 junk-packet chains.
//!
//! Before the handshake a client may send up to five packets whose only job is
//! to make the start of a session look like something a censor has decided not
//! to block. [`dsl`] is the little language those packets are written in;
//! [`profiles`] builds one packet per protocol worth imitating; this module
//! assembles the five of them.
//!
//! Ported from `Any-Tech-ARCHITECT/src/utils/generator/` — `profiles/*.ts` for
//! the packet shapes, `utils.ts` for the padding arithmetic, `constants.ts` for
//! the host pools and browser tables, and the `genCfg` chain assembly in
//! `index.ts`.
//!
//! What the chains are *not*: they carry no key material and complete no real
//! handshake. Only the opening bytes and the size distribution are imitated,
//! because that is all a DPI box gets to look at before it has to make a call.

pub mod dsl;
mod hosts;
mod profiles;

pub use dsl::{Chain, MAX_TAG_COUNT, PadKind, Tag, TagKind};

// Intensity is shared with the 3.0 generator rather than redeclared: one config
// has one intensity, and two enums that mean the same thing drift.
pub use crate::awg3::Intensity;

use crate::rng::Rng;

/// What the I1 packet pretends to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimicProfile {
    QuicInitial,
    Quic0Rtt,
    TlsClientHello,
    WireguardNoise,
    Dtls,
    Http3,
    Sip,
    /// Composite: a TLS ClientHello followed by a QUIC Initial, the way a
    /// browser that falls back and then upgrades looks.
    TlsToQuic,
    /// Composite: Initial, 0-RTT and an HTTP/3 packet back to back.
    QuicBurst,
    DnsQuery,
    /// Redrawn per packet from the concrete profiles.
    Random,
}

impl MimicProfile {
    /// The profiles `Random` draws from — the dispatch table of `genI1`, in the
    /// same order, so a seeded run can be compared against the TypeScript.
    pub const CONCRETE: [MimicProfile; 10] = [
        MimicProfile::QuicInitial,
        MimicProfile::Quic0Rtt,
        MimicProfile::TlsClientHello,
        MimicProfile::WireguardNoise,
        MimicProfile::Dtls,
        MimicProfile::Http3,
        MimicProfile::Sip,
        MimicProfile::DnsQuery,
        MimicProfile::TlsToQuic,
        MimicProfile::QuicBurst,
    ];

    /// Every value, including `Random`.
    pub const ALL: [MimicProfile; 11] = [
        MimicProfile::QuicInitial,
        MimicProfile::Quic0Rtt,
        MimicProfile::TlsClientHello,
        MimicProfile::WireguardNoise,
        MimicProfile::Dtls,
        MimicProfile::Http3,
        MimicProfile::Sip,
        MimicProfile::TlsToQuic,
        MimicProfile::QuicBurst,
        MimicProfile::DnsQuery,
        MimicProfile::Random,
    ];

    /// The `.conf`-facing identifier, and what `--profile` accepts.
    pub fn id(&self) -> &'static str {
        match self {
            MimicProfile::QuicInitial => "quic",
            MimicProfile::Quic0Rtt => "quic0rtt",
            MimicProfile::TlsClientHello => "tls",
            MimicProfile::WireguardNoise => "noise",
            MimicProfile::Dtls => "dtls",
            MimicProfile::Http3 => "http3",
            MimicProfile::Sip => "sip",
            MimicProfile::TlsToQuic => "tls-to-quic",
            MimicProfile::QuicBurst => "quic-burst",
            MimicProfile::DnsQuery => "dns",
            MimicProfile::Random => "random",
        }
    }

    /// Human-readable name — `PROFILE_LABELS` in the TypeScript.
    pub fn label(&self) -> &'static str {
        match self {
            MimicProfile::QuicInitial => "QUIC Initial",
            MimicProfile::Quic0Rtt => "QUIC 0-RTT",
            MimicProfile::TlsClientHello => "TLS 1.3",
            MimicProfile::WireguardNoise => "Noise_IK",
            MimicProfile::Dtls => "DTLS 1.3",
            MimicProfile::Http3 => "HTTP/3",
            MimicProfile::Sip => "SIP",
            MimicProfile::TlsToQuic => "TLS -> QUIC",
            MimicProfile::QuicBurst => "QUIC Burst",
            MimicProfile::DnsQuery => "DNS Query",
            MimicProfile::Random => "Random",
        }
    }

    /// Accepts both the short CLI spelling and the upstream `snake_case` key, so
    /// a profile copied out of the web generator still resolves.
    pub fn parse(s: &str) -> Option<Self> {
        let key = s.trim().to_ascii_lowercase().replace('_', "-");
        Some(match key.as_str() {
            "quic" | "quic-initial" => MimicProfile::QuicInitial,
            "quic0rtt" | "quic-0rtt" => MimicProfile::Quic0Rtt,
            "tls" | "tls-client-hello" => MimicProfile::TlsClientHello,
            "noise" | "wireguard-noise" => MimicProfile::WireguardNoise,
            "dtls" => MimicProfile::Dtls,
            "http3" => MimicProfile::Http3,
            "sip" => MimicProfile::Sip,
            "tls-to-quic" => MimicProfile::TlsToQuic,
            "quic-burst" => MimicProfile::QuicBurst,
            "dns" | "dns-query" => MimicProfile::DnsQuery,
            "random" => MimicProfile::Random,
            _ => return None,
        })
    }
}

/// Which measured packet-size band a profile should land in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BfpSlot {
    /// QUIC Initial.
    Qi,
    /// QUIC 0-RTT early data.
    Q0,
    /// HTTP/3 DATA packets after the handshake.
    H3,
    /// TLS 1.3 ClientHello.
    Tls,
    /// WireGuard Noise_IK initiation.
    Nx,
    /// DTLS ClientHello.
    Dtls,
}

/// Browser fingerprint: real UDP payload sizes, measured per browser.
///
/// Matching them matters because the sizes are distinctive. Chrome's Initial is
/// exactly 1250 bytes; Yandex Browser on mobile uses 1232. A "QUIC Initial" of
/// 900 bytes is a QUIC Initial nothing else sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserProfile {
    Chrome,
    Edge,
    Firefox,
    Safari,
    YandexDesktop,
    YandexMobile,
}

impl BrowserProfile {
    pub const ALL: [BrowserProfile; 6] = [
        BrowserProfile::Chrome,
        BrowserProfile::Edge,
        BrowserProfile::Firefox,
        BrowserProfile::Safari,
        BrowserProfile::YandexDesktop,
        BrowserProfile::YandexMobile,
    ];

    pub fn id(&self) -> &'static str {
        match self {
            BrowserProfile::Chrome => "chrome",
            BrowserProfile::Edge => "edge",
            BrowserProfile::Firefox => "firefox",
            BrowserProfile::Safari => "safari",
            BrowserProfile::YandexDesktop => "yandex-desktop",
            BrowserProfile::YandexMobile => "yandex-mobile",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let key = s.trim().to_ascii_lowercase().replace('_', "-");
        BrowserProfile::ALL.into_iter().find(|b| b.id() == key)
    }

    /// Chromium aligns its TLS record length up to a multiple of 128; Firefox
    /// and Safari do not, and the step is visible on the wire.
    pub fn is_chromium(&self) -> bool {
        matches!(
            self,
            BrowserProfile::Chrome
                | BrowserProfile::Edge
                | BrowserProfile::YandexDesktop
                | BrowserProfile::YandexMobile
        )
    }

    /// `[min, max]` UDP payload bytes for one slot, excluding UDP/IP headers.
    fn range(&self, slot: BfpSlot) -> (u32, u32) {
        //                 qi            q0            h3            tls         nx            dtls
        let row: [(u32, u32); 6] = match self {
            BrowserProfile::Chrome | BrowserProfile::Edge => [
                (1250, 1250),
                (1250, 1350),
                (1250, 1350),
                (512, 800),
                (1200, 1250),
                (1100, 1200),
            ],
            BrowserProfile::Firefox => [
                (1200, 1252),
                (1200, 1300),
                (1200, 1350),
                (512, 700),
                (1200, 1250),
                (1050, 1200),
            ],
            BrowserProfile::Safari => [
                (1250, 1252),
                (1250, 1300),
                (1250, 1350),
                (512, 750),
                (1200, 1250),
                (1100, 1200),
            ],
            BrowserProfile::YandexDesktop => [
                (1250, 1250),
                (1250, 1350),
                (1350, 1350),
                (512, 800),
                (1200, 1250),
                (1100, 1200),
            ],
            BrowserProfile::YandexMobile => [
                (1232, 1232),
                (1250, 1350),
                (1350, 1350),
                (512, 800),
                (1200, 1250),
                (1100, 1200),
            ],
        };
        row[match slot {
            BfpSlot::Qi => 0,
            BfpSlot::Q0 => 1,
            BfpSlot::H3 => 2,
            BfpSlot::Tls => 3,
            BfpSlot::Nx => 4,
            BfpSlot::Dtls => 5,
        }]
    }
}

/// Everything the chain builders read besides the profile and the intensity.
#[derive(Debug, Clone)]
pub struct MimicOptions {
    /// Path MTU. A chain that overshoots it fragments, and a fragmented "QUIC
    /// Initial" is a signature all by itself.
    pub mtu: u32,
    /// Build all five packets from the profile instead of only I1.
    pub mimic_all: bool,
    /// Override the host pool with one name. Only its length reaches the packet
    /// for most profiles; a DNS query embeds it verbatim.
    pub custom_host: Option<String>,
    /// `<c>` — off by default, because the tag belongs to exactly one
    /// generation: only the 1.5 parser has a builder for it, and from v0.2.16
    /// chains are parsed by `device/obf.go`, whose table has no `c` at all.
    /// That is the ErrorCode 1000 people report. Callers going through
    /// [`crate::versions::generate`] do not set this themselves — the version
    /// decides, see [`crate::versions::AwgVersion::chain_tags`].
    pub tag_c: bool,
    pub tag_t: bool,
    pub tag_r: bool,
    pub tag_rc: bool,
    pub tag_rd: bool,
    /// Target this browser's measured packet sizes.
    pub browser: Option<BrowserProfile>,
    /// Low-power router: I1 only, so the device is not asked to build five
    /// packets it will struggle to send in time.
    pub router_mode: bool,
    /// Failed-attempt counter. Past three, everything is generated one notch
    /// stronger — the previous set was evidently recognised.
    pub iter_count: u32,
}

impl Default for MimicOptions {
    fn default() -> Self {
        Self {
            mtu: 1500,
            mimic_all: false,
            custom_host: None,
            tag_c: false,
            tag_t: true,
            tag_r: true,
            tag_rc: true,
            tag_rd: true,
            browser: None,
            router_mode: false,
            iter_count: 0,
        }
    }
}

impl MimicOptions {
    fn host(&self, rng: &mut impl Rng, pool: &[&'static str]) -> String {
        if let Some(h) = self.custom_host.as_deref().map(str::trim)
            && !h.is_empty()
        {
            return h.to_string();
        }
        pool[rng.range(0, pool.len() as u32 - 1) as usize].to_string()
    }

    fn fp_range(&self, slot: BfpSlot) -> Option<(u32, u32)> {
        self.browser.map(|b| b.range(slot))
    }
}

/// Intensity as the profile builders consume it: a small multiplier applied to
/// padding sizes, bumped once the caller reports repeated failures.
fn intensity_value(intensity: Intensity, iter_count: u32) -> u32 {
    let base = match intensity {
        Intensity::Low => 1,
        Intensity::Medium => 2,
        Intensity::High => 3,
    };
    base + u32::from(iter_count > 3)
}

fn build_one(rng: &mut impl Rng, profile: MimicProfile, opts: &MimicOptions, iv: u32) -> Chain {
    match profile {
        MimicProfile::Random => {
            let pick = MimicProfile::CONCRETE
                [rng.range(0, MimicProfile::CONCRETE.len() as u32 - 1) as usize];
            build_one(rng, pick, opts, iv)
        }
        MimicProfile::QuicInitial => profiles::quic_initial(rng, opts, iv),
        MimicProfile::Quic0Rtt => profiles::quic_0rtt(rng, opts, iv),
        MimicProfile::TlsClientHello => profiles::tls_client_hello(rng, opts, iv),
        MimicProfile::WireguardNoise => profiles::wireguard_noise(rng, opts, iv),
        MimicProfile::Dtls => profiles::dtls(rng, opts, iv),
        MimicProfile::Http3 => profiles::http3(rng, opts, iv),
        MimicProfile::Sip => profiles::sip(rng, opts, iv),
        MimicProfile::DnsQuery => profiles::dns_query(rng, opts, iv),
        // The composites reuse the first packet of their pair when asked for a
        // single one, exactly as the TS dispatch table does.
        MimicProfile::TlsToQuic => profiles::tls_client_hello(rng, opts, iv),
        MimicProfile::QuicBurst => profiles::quic_initial(rng, opts, iv),
    }
}

/// Build I1–I5 as typed chains.
///
/// I1 carries the recognisable signature; I2–I5 default to entropy packets, so
/// the burst does not repeat itself, and only imitate the profile too when
/// [`MimicOptions::mimic_all`] is set.
pub fn generate_chain_set(
    rng: &mut impl Rng,
    profile: MimicProfile,
    intensity: Intensity,
    opts: &MimicOptions,
) -> [Chain; 5] {
    let iv = intensity_value(intensity, opts.iter_count);

    let mut out: [Chain; 5] = match profile {
        MimicProfile::TlsToQuic => {
            let i1 = profiles::tls_client_hello(rng, opts, iv);
            let i2 = profiles::quic_initial(rng, opts, iv);
            let i3 = profiles::entropy(rng, opts, 2, iv);
            let i4 = profiles::entropy(rng, opts, 3, iv);
            let i5 = profiles::entropy(rng, opts, 4, iv);
            [i1, i2, i3, i4, i5]
        }
        MimicProfile::QuicBurst => {
            let i1 = profiles::quic_initial(rng, opts, iv);
            let i2 = profiles::quic_0rtt(rng, opts, iv);
            let i3 = profiles::http3(rng, opts, iv);
            let i4 = profiles::entropy(rng, opts, 3, iv);
            let i5 = profiles::entropy(rng, opts, 4, iv);
            [i1, i2, i3, i4, i5]
        }
        MimicProfile::DnsQuery => {
            let i1 = profiles::dns_query(rng, opts, iv);
            // A DNS burst walks the intensity so the five queries do not all ask
            // for the same record type.
            let mut rest = [1u32, 2, 3, 4].map(|_| Chain::new());
            for (k, slot) in rest.iter_mut().enumerate() {
                let k = k as u32 + 1;
                *slot = if opts.mimic_all {
                    profiles::dns_query(rng, opts, iv + k)
                } else {
                    profiles::entropy(rng, opts, k, iv)
                };
            }
            let [i2, i3, i4, i5] = rest;
            [i1, i2, i3, i4, i5]
        }
        _ => {
            let i1 = build_one(rng, profile, opts, iv);
            let mut rest = [1u32, 2, 3, 4].map(|_| Chain::new());
            for (k, slot) in rest.iter_mut().enumerate() {
                *slot = if opts.mimic_all {
                    build_one(rng, profile, opts, iv)
                } else {
                    profiles::entropy(rng, opts, k as u32 + 1, iv)
                };
            }
            let [i2, i3, i4, i5] = rest;
            [i1, i2, i3, i4, i5]
        }
    };

    if opts.router_mode {
        // One signature packet and nothing else: the point of router mode is to
        // stay cheap, and four extra packets per handshake is the expensive part.
        for chain in &mut out[1..] {
            *chain = Chain::new();
        }
    }
    out
}

/// Build I1–I5 as the strings a `.conf` carries.
pub fn generate_chains(
    rng: &mut impl Rng,
    profile: MimicProfile,
    intensity: Intensity,
    opts: &MimicOptions,
) -> [String; 5] {
    generate_chain_set(rng, profile, intensity, opts).map(|c| c.render())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::SeededRng;

    fn all_tags() -> MimicOptions {
        MimicOptions {
            tag_c: true,
            ..Default::default()
        }
    }

    #[test]
    fn every_profile_produces_chains_that_parse_back() {
        for profile in MimicProfile::ALL {
            for seed in 0..40u64 {
                let mut rng = SeededRng::new(seed);
                let chains = generate_chains(&mut rng, profile, Intensity::High, &all_tags());
                for (i, s) in chains.iter().enumerate() {
                    let parsed = Chain::parse(s).unwrap_or_else(|e| {
                        panic!("{} I{} ({s}) failed to parse: {e}", profile.id(), i + 1)
                    });
                    assert_eq!(&parsed.render(), s, "{} I{}", profile.id(), i + 1);
                }
            }
        }
    }

    #[test]
    fn i1_always_carries_a_literal_signature() {
        // The whole point of I1 is the recognisable prefix; an I1 of pure random
        // bytes imitates nothing.
        for profile in MimicProfile::ALL {
            for seed in 0..40u64 {
                let mut rng = SeededRng::new(seed);
                let chains = generate_chain_set(&mut rng, profile, Intensity::Medium, &all_tags());
                assert!(
                    matches!(chains[0].tags().first(), Some(Tag::Bytes(_))),
                    "{} I1 does not start with literal bytes: {}",
                    profile.id(),
                    chains[0]
                );
            }
        }
    }

    #[test]
    fn no_chain_exceeds_the_mtu() {
        for profile in MimicProfile::ALL {
            for mtu in [576u32, 1280, 1500] {
                let opts = MimicOptions {
                    mtu,
                    mimic_all: true,
                    ..all_tags()
                };
                for seed in 0..30u64 {
                    let mut rng = SeededRng::new(seed);
                    for (i, c) in generate_chain_set(&mut rng, profile, Intensity::High, &opts)
                        .iter()
                        .enumerate()
                    {
                        assert!(
                            c.wire_len() <= mtu,
                            "{} I{} is {} bytes at MTU {mtu}: {c}",
                            profile.id(),
                            i + 1,
                            c.wire_len()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn no_single_tag_exceeds_the_per_tag_limit() {
        for profile in MimicProfile::ALL {
            for seed in 0..30u64 {
                let mut rng = SeededRng::new(seed);
                for c in generate_chain_set(&mut rng, profile, Intensity::High, &all_tags()) {
                    for tag in c.tags() {
                        if let Tag::Random(n) | Tag::RandomLetters(n) | Tag::RandomDigits(n) = tag {
                            assert!(*n <= MAX_TAG_COUNT, "{} emitted <{n}>", profile.id());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn chains_differ_between_runs() {
        // A fixed chain is a fixed fingerprint for every install of this tool,
        // which is the failure mode the whole crate exists to avoid.
        for profile in MimicProfile::ALL {
            let mut seen = std::collections::BTreeSet::new();
            for seed in 0..25u64 {
                let mut rng = SeededRng::new(seed);
                seen.insert(
                    generate_chains(&mut rng, profile, Intensity::Medium, &all_tags()).join("|"),
                );
            }
            assert_eq!(
                seen.len(),
                25,
                "{} repeats itself across seeds",
                profile.id()
            );
        }
    }

    #[test]
    fn the_same_seed_gives_the_same_chains() {
        for profile in MimicProfile::ALL {
            let a = generate_chains(
                &mut SeededRng::new(1234),
                profile,
                Intensity::High,
                &all_tags(),
            );
            let b = generate_chains(
                &mut SeededRng::new(1234),
                profile,
                Intensity::High,
                &all_tags(),
            );
            assert_eq!(a, b, "{} is not reproducible from a seed", profile.id());
        }
    }

    #[test]
    fn a_disabled_tag_never_appears() {
        let off = MimicOptions {
            tag_c: false,
            tag_t: false,
            tag_r: false,
            tag_rc: false,
            tag_rd: false,
            mimic_all: true,
            ..Default::default()
        };
        for profile in MimicProfile::ALL {
            for seed in 0..30u64 {
                let mut rng = SeededRng::new(seed);
                for c in generate_chain_set(&mut rng, profile, Intensity::High, &off) {
                    for tag in c.tags() {
                        assert!(
                            // The entropy fallback is the one exception, and it
                            // only fires when a pattern would be empty.
                            matches!(tag, Tag::Bytes(_) | Tag::Random(10)),
                            "{} emitted {tag:?} with every tag switched off",
                            profile.id()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn each_tag_type_reaches_the_output_when_enabled() {
        // Entropy packets are the only place <rd> is used, so this needs the
        // default (non-mimic-all) chain shape.
        let opts = all_tags();
        let mut seen_rc = false;
        let mut seen_rd = false;
        let mut seen_c = false;
        let mut seen_t = false;
        let mut seen_r = false;
        for seed in 0..40u64 {
            let mut rng = SeededRng::new(seed);
            for c in generate_chain_set(&mut rng, MimicProfile::QuicInitial, Intensity::High, &opts)
            {
                for tag in c.tags() {
                    match tag {
                        Tag::RandomLetters(_) => seen_rc = true,
                        Tag::RandomDigits(_) => seen_rd = true,
                        Tag::Counter => seen_c = true,
                        Tag::Timestamp => seen_t = true,
                        Tag::Random(_) => seen_r = true,
                        Tag::Bytes(_) => {}
                    }
                }
            }
        }
        assert!(seen_rc && seen_rd && seen_c && seen_t && seen_r);
    }

    #[test]
    fn router_mode_sends_one_packet_and_no_more() {
        let opts = MimicOptions {
            router_mode: true,
            mimic_all: true,
            ..all_tags()
        };
        for profile in MimicProfile::ALL {
            let mut rng = SeededRng::new(3);
            let chains = generate_chain_set(&mut rng, profile, Intensity::Low, &opts);
            assert!(
                !chains[0].is_empty(),
                "{} lost its signature packet",
                profile.id()
            );
            assert!(chains[1..].iter().all(Chain::is_empty), "{}", profile.id());
        }
    }

    #[test]
    fn a_custom_host_reaches_the_dns_query_verbatim() {
        // DNS is the one profile where the name is in the packet rather than
        // just its length, so a wrong encoding would be invisible elsewhere.
        let opts = MimicOptions {
            custom_host: Some("example.org".into()),
            ..all_tags()
        };
        let mut rng = SeededRng::new(5);
        let chains = generate_chain_set(&mut rng, MimicProfile::DnsQuery, Intensity::Low, &opts);
        let Some(Tag::Bytes(b)) = chains[0].tags().first() else {
            panic!("DNS I1 must start with literal bytes");
        };
        // 7"example" 3"org" 0
        let wire: &[u8] = b"\x07example\x03org\x00";
        assert!(
            b.windows(wire.len()).any(|w| w == wire),
            "the query name is not encoded as DNS labels: {b:02x?}"
        );
    }

    #[test]
    fn a_browser_fingerprint_puts_the_packet_in_the_measured_band() {
        // Chrome's QUIC Initial is exactly 1250 bytes. Landing anywhere else is
        // the fingerprint this option exists to avoid.
        let opts = MimicOptions {
            browser: Some(BrowserProfile::Chrome),
            ..all_tags()
        };
        for seed in 0..50u64 {
            let mut rng = SeededRng::new(seed);
            let chains = generate_chain_set(
                &mut rng,
                MimicProfile::QuicInitial,
                Intensity::Medium,
                &opts,
            );
            // The band is a single value, so the padding has to hit it exactly.
            assert_eq!(
                chains[0].wire_len(),
                1250,
                "seed {seed}: Chrome QUIC Initial missed its measured size"
            );
        }
    }

    #[test]
    fn mimic_all_makes_every_packet_look_like_the_profile() {
        let opts = MimicOptions {
            mimic_all: true,
            ..all_tags()
        };
        let mut rng = SeededRng::new(17);
        let chains = generate_chain_set(&mut rng, MimicProfile::Sip, Intensity::Low, &opts);
        for (i, c) in chains.iter().enumerate() {
            let Some(Tag::Bytes(b)) = c.tags().first() else {
                panic!("I{} is not a SIP packet", i + 1);
            };
            assert!(b.starts_with(b"REGISTER sip:"), "I{} is not SIP", i + 1);
        }
    }

    #[test]
    fn profile_names_round_trip_through_the_cli_spelling() {
        for p in MimicProfile::ALL {
            assert_eq!(MimicProfile::parse(p.id()), Some(p));
            assert!(!p.label().is_empty());
        }
        // The upstream snake_case keys resolve too.
        assert_eq!(
            MimicProfile::parse("quic_initial"),
            Some(MimicProfile::QuicInitial)
        );
        assert_eq!(
            MimicProfile::parse("dns_query"),
            Some(MimicProfile::DnsQuery)
        );
        assert_eq!(
            MimicProfile::parse("wireguard_noise"),
            Some(MimicProfile::WireguardNoise)
        );
        assert_eq!(MimicProfile::parse("nope"), None);
        for b in BrowserProfile::ALL {
            assert_eq!(BrowserProfile::parse(b.id()), Some(b));
        }
    }

    #[test]
    fn the_composite_profiles_lay_their_packets_out_in_order() {
        let mut rng = SeededRng::new(21);
        let burst = generate_chain_set(
            &mut rng,
            MimicProfile::QuicBurst,
            Intensity::Low,
            &all_tags(),
        );
        let first_byte = |c: &Chain| match c.tags().first() {
            Some(Tag::Bytes(b)) => b[0],
            _ => panic!("expected literal bytes"),
        };
        assert_eq!(
            first_byte(&burst[0]) & 0xf0,
            0xc0,
            "I1 must be a QUIC Initial"
        );
        assert_eq!(first_byte(&burst[1]) & 0xf0, 0xd0, "I2 must be 0-RTT");

        let mut rng = SeededRng::new(22);
        let ttq = generate_chain_set(
            &mut rng,
            MimicProfile::TlsToQuic,
            Intensity::Low,
            &all_tags(),
        );
        assert_eq!(first_byte(&ttq[0]), 0x16, "I1 must be a TLS record");
        assert_eq!(
            first_byte(&ttq[1]) & 0xf0,
            0xc0,
            "I2 must be a QUIC Initial"
        );
    }

    #[test]
    fn intensity_scales_the_padding_it_is_asked_to_scale() {
        let opts = all_tags();
        let total = |intensity, seed| -> u32 {
            let mut rng = SeededRng::new(seed);
            generate_chain_set(&mut rng, MimicProfile::Sip, intensity, &opts)
                .iter()
                .map(Chain::wire_len)
                .sum()
        };
        let low: u32 = (0..30).map(|s| total(Intensity::Low, s)).sum();
        let high: u32 = (0..30).map(|s| total(Intensity::High, s)).sum();
        assert!(
            high > low,
            "high intensity produced {high} bytes against low's {low}"
        );
    }

    #[test]
    fn repeated_failures_strengthen_the_next_attempt() {
        // iterCount > 3 bumps the multiplier: the previous set was evidently
        // recognised, so the next one should not look like it.
        let quiet = MimicOptions {
            iter_count: 0,
            ..all_tags()
        };
        let loud = MimicOptions {
            iter_count: 4,
            ..all_tags()
        };
        let sum = |opts: &MimicOptions| -> u32 {
            (0..30u64)
                .map(|s| {
                    generate_chain_set(
                        &mut SeededRng::new(s),
                        MimicProfile::Sip,
                        Intensity::Low,
                        opts,
                    )
                    .iter()
                    .map(Chain::wire_len)
                    .sum::<u32>()
                })
                .sum()
        };
        assert!(sum(&loud) > sum(&quiet));
    }

    #[test]
    fn no_generated_chain_ever_contains_an_awg4_tag() {
        // The parser refuses them; this proves the generator cannot produce a
        // string the parser would then reject.
        for profile in MimicProfile::ALL {
            for seed in 0..30u64 {
                let mut rng = SeededRng::new(seed);
                for s in generate_chains(&mut rng, profile, Intensity::High, &all_tags()) {
                    for forbidden in ["<d ", "<d>", "<ds", "<dz"] {
                        assert!(
                            !s.contains(forbidden),
                            "{} emitted {forbidden}",
                            profile.id()
                        );
                    }
                }
            }
        }
    }
}
