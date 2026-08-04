//! AmneziaWG 3.0 parameter generation.
//!
//! Ported from `Any-Tech-ARCHITECT/src/utils/generator/awg3.ts`, which was in
//! turn derived from the protocol implementation rather than the docs (the docs
//! still describe 2.0):
//!
//! * `amneziawg-go v3.0.1`
//!   - `device/uapi.go`        — accepted keys and their parsers
//!   - `device/noise-types.go` — `UintRange` (`"lo"` or `"lo-hi"`), `HeaderCipherKey`
//!   - `device/send.go`        — where the header cipher nonce comes from
//!   - `device/timers.go`      — how the randomised timers are consumed
//!
//! Keeping this a library (rather than logic living in the web generator) is
//! deliberate: the same crate compiles to WASM for the web UI, so the protocol
//! rules cannot drift between the site and the CLI.

use crate::rng::Rng;
use crate::{Error, Result};

/// `HeaderCipherKeySize` — `device/noise-types.go`.
pub const HEADER_PROTECTION_KEY_BYTES: usize = 32;

/// `HeaderCipherNonceSize` — `device/noise-types.go`.
pub const HEADER_CIPHER_NONCE_SIZE: u32 = 12;

/// Minimum S1–S4 when a header-protection key is set.
///
/// `send.go` builds `crypt := buf[:padding]` and then uses
/// `crypt[:HeaderCipherNonceSize]` as the ChaCha20 nonce. With padding below 12
/// that slice runs past the padding into the message body — legal in Go, still
/// inside `cap`, so there is no crash and no log line, just a nonce that is no
/// longer random padding. This is a floor, **not** a fixed value: real configs
/// carry S3=39, S4=32 and so on.
pub const MIN_S_WITH_HEADER_PROTECTION: u32 = HEADER_CIPHER_NONCE_SIZE;

/// Stock WireGuard timings in seconds — `device/constants.go`.
pub mod wg_defaults {
    pub const REKEY_AFTER_TIME: u32 = 120;
    pub const REKEY_TIMEOUT: u32 = 5;
    pub const REJECT_AFTER_TIME: u32 = 180;
    pub const KEEPALIVE_TIMEOUT: u32 = 10;
    /// `MaxTimerHandshakes` = `RekeyAttemptTime / RekeyTimeout` = 90 / 5.
    pub const MAX_HANDSHAKE_ATTEMPTS: u32 = 18;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intensity {
    Low,
    Medium,
    High,
}

/// An inclusive range as `amneziawg-go` parses it back: `"lo"` or `"lo-hi"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UintRange {
    pub lo: u32,
    pub hi: u32,
}

impl UintRange {
    pub fn new(lo: u32, hi: u32) -> Self {
        Self { lo, hi: hi.max(lo) }
    }
}

impl std::fmt::Display for UintRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.lo == self.hi {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "{}-{}", self.lo, self.hi)
        }
    }
}

/// The 3.0-only block of a config.
#[derive(Debug, Clone, Default)]
pub struct Awg3Params {
    /// 32 raw bytes. Rendered base64 in `.conf`, hex over UAPI.
    pub header_protection_key: Option<[u8; HEADER_PROTECTION_KEY_BYTES]>,
    pub content_padding_addition: Option<UintRange>,
    pub rekey_after_time: Option<UintRange>,
    pub rekey_timeout: Option<UintRange>,
    pub reject_after_time: Option<UintRange>,
    pub keepalive_timeout: Option<UintRange>,
    pub max_handshake_attempts: Option<UintRange>,
}

impl Awg3Params {
    pub fn is_empty(&self) -> bool {
        self.header_protection_key.is_none()
            && self.content_padding_addition.is_none()
            && self.rekey_after_time.is_none()
    }

    /// Check the invariants the daemon relies on but does not enforce.
    ///
    /// `timers.go` computes
    /// `keyRefreshTimeoutReceiving = RejectAfterTime.PickOne()
    ///     − KeepaliveTimeout.Lo() − RekeyTimeout.Lo()`
    /// clamped at zero. If it reaches zero the receiving side stops refreshing
    /// keys and the tunnel dies a few minutes in — with no error anywhere. So
    /// the low end of `RejectAfterTime` has to clear the sum of the other two
    /// low ends by a margin, and `RekeyAfterTime` has to finish before
    /// `RejectAfterTime` or the session is rejected before it ever rekeys.
    pub fn validate(&self) -> Result<()> {
        let (Some(reject), Some(keepalive), Some(rekey_to), Some(rekey_after)) = (
            self.reject_after_time,
            self.keepalive_timeout,
            self.rekey_timeout,
            self.rekey_after_time,
        ) else {
            return Ok(()); // timers not randomised — stock constants apply
        };

        let refresh_floor = keepalive.lo + rekey_to.lo;
        if reject.lo <= refresh_floor {
            return Err(Error::Invariant(format!(
                "RejectAfterTime low end ({}) must exceed KeepaliveTimeout.lo + RekeyTimeout.lo ({}), \
                 otherwise the receiving side stops refreshing keys",
                reject.lo, refresh_floor
            )));
        }
        if rekey_after.hi >= reject.lo {
            return Err(Error::Invariant(format!(
                "RekeyAfterTime high end ({}) must stay below RejectAfterTime low end ({}), \
                 otherwise a session can be rejected before it rekeys",
                rekey_after.hi, reject.lo
            )));
        }
        Ok(())
    }
}

/// Content padding widens with intensity: wider ranges cost bandwidth but
/// flatten the packet-size histogram harder.
fn gen_content_padding(rng: &mut impl Rng, intensity: Intensity, router_mode: bool) -> UintRange {
    if router_mode {
        return UintRange::new(4, 32);
    }
    let (lo, hi) = match intensity {
        Intensity::Low => (8, 64),
        Intensity::Medium => (16, 128),
        Intensity::High => (24, 200),
    };
    let min = rng.range(lo, (lo + hi) / 2);
    UintRange::new(min, rng.range(min + 8, hi))
}

/// Randomised timers, built so the invariants in [`Awg3Params::validate`] hold
/// by construction rather than by luck.
fn gen_timings(rng: &mut impl Rng, intensity: Intensity) -> Awg3Params {
    let spread = match intensity {
        Intensity::Low => 10,
        Intensity::Medium => 25,
        Intensity::High => 45,
    };

    let rekey_timeout_lo = rng.range(4, 6);
    let rekey_timeout = UintRange::new(rekey_timeout_lo, rekey_timeout_lo + rng.range(1, 4));

    let keepalive_lo = rng.range(8, 14);
    let keepalive = UintRange::new(keepalive_lo, keepalive_lo + rng.range(2, 8));

    let rekey_after_lo = rng.range(100, 120);
    let rekey_after = UintRange::new(rekey_after_lo, rekey_after_lo + rng.range(10, spread));

    // Hard margin over the sum of the low ends so the receiving-side refresh
    // window can never collapse to zero.
    let reject_floor = rekey_after.hi + keepalive.hi + rekey_timeout.hi + 15;
    let reject_lo = reject_floor.max(170);
    let reject = UintRange::new(reject_lo, reject_lo + rng.range(10, spread));

    let attempts_lo = rng.range(12, 18);
    let attempts = UintRange::new(attempts_lo, attempts_lo + rng.range(2, 10));

    Awg3Params {
        rekey_after_time: Some(rekey_after),
        rekey_timeout: Some(rekey_timeout),
        reject_after_time: Some(reject),
        keepalive_timeout: Some(keepalive),
        max_handshake_attempts: Some(attempts),
        ..Default::default()
    }
}

/// What the caller wants switched on.
#[derive(Debug, Clone, Copy)]
pub struct Awg3Options {
    pub header_protection: bool,
    pub content_padding: bool,
    pub random_timings: bool,
    pub intensity: Intensity,
    pub router_mode: bool,
}

impl Default for Awg3Options {
    fn default() -> Self {
        Self {
            header_protection: true,
            content_padding: true,
            random_timings: true,
            intensity: Intensity::Medium,
            router_mode: false,
        }
    }
}

/// Generate the 3.0 block. Every install must call this for itself — a shared
/// parameter set would give the whole fleet one DPI fingerprint.
pub fn generate(rng: &mut impl Rng, opts: Awg3Options) -> Result<Awg3Params> {
    let mut p = if opts.random_timings {
        gen_timings(rng, opts.intensity)
    } else {
        Awg3Params::default()
    };

    if opts.header_protection {
        let mut key = [0u8; HEADER_PROTECTION_KEY_BYTES];
        rng.fill(&mut key);
        p.header_protection_key = Some(key);
    }
    if opts.content_padding {
        p.content_padding_addition =
            Some(gen_content_padding(rng, opts.intensity, opts.router_mode));
    }

    p.validate()?;
    Ok(p)
}

/// Raise S1–S4 to the nonce floor when header protection is on.
///
/// Returns the clamped value; callers keep whatever larger value they chose.
pub fn clamp_s_for_header_protection(s: u32, header_protection: bool) -> u32 {
    if header_protection {
        s.max(MIN_S_WITH_HEADER_PROTECTION)
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::SeededRng;

    #[test]
    fn range_renders_the_way_the_daemon_parses_it() {
        assert_eq!(UintRange::new(12, 12).to_string(), "12");
        assert_eq!(UintRange::new(4, 32).to_string(), "4-32");
        // hi below lo is nonsense the parser would reject
        assert_eq!(UintRange::new(30, 4).to_string(), "30");
    }

    #[test]
    fn s_values_are_floored_not_fixed() {
        assert_eq!(clamp_s_for_header_protection(5, true), 12);
        assert_eq!(clamp_s_for_header_protection(39, true), 39);
        assert_eq!(clamp_s_for_header_protection(5, false), 5);
    }

    #[test]
    fn generated_timers_always_satisfy_the_refresh_invariant() {
        for seed in 0..500u64 {
            let mut rng = SeededRng::new(seed);
            for intensity in [Intensity::Low, Intensity::Medium, Intensity::High] {
                let p = generate(
                    &mut rng,
                    Awg3Options {
                        intensity,
                        ..Default::default()
                    },
                )
                .expect("generated params must satisfy their own invariants");
                let reject = p.reject_after_time.unwrap();
                let keepalive = p.keepalive_timeout.unwrap();
                let rekey_to = p.rekey_timeout.unwrap();
                let rekey_after = p.rekey_after_time.unwrap();
                assert!(reject.lo > keepalive.lo + rekey_to.lo);
                assert!(rekey_after.hi < reject.lo);
            }
        }
    }

    #[test]
    fn validate_rejects_a_collapsing_refresh_window() {
        let bad = Awg3Params {
            reject_after_time: Some(UintRange::new(20, 25)),
            keepalive_timeout: Some(UintRange::new(14, 20)),
            rekey_timeout: Some(UintRange::new(6, 9)),
            rekey_after_time: Some(UintRange::new(10, 15)),
            ..Default::default()
        };
        assert!(bad.validate().is_err());
    }
}
