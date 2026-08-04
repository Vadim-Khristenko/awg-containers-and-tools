//! One builder per protocol the I1 packet can pretend to be.
//!
//! Ported from `Any-Tech-ARCHITECT/src/utils/generator/profiles/*.ts`. The
//! draws are kept in the same order as the TypeScript, so the two can be
//! compared draw-for-draw if the pools ever need re-verifying.
//!
//! Two things stay implicit in the TS and are worth saying here. First, only the
//! *shape* of the packet is imitated — the leading bytes, the field lengths and
//! the total size — because that is all a DPI box gets to see before it has to
//! decide. Nothing here completes a real handshake. Second, the byte builder
//! removes a whole class of bug the TS has to guard against with
//! `assertEvenHex`: it works in bytes, so half a byte is unrepresentable.

use super::dsl::{Chain, PadKind, Tag};
use super::{BfpSlot, MimicOptions};
use crate::rng::Rng;

/// Growable byte buffer with the field helpers the profiles need.
struct Buf(Vec<u8>);

impl Buf {
    fn new() -> Self {
        Self(Vec::new())
    }

    /// `hexPad(value, len)` — the low `len` bytes of `value`, big-endian.
    fn be(&mut self, value: u32, len: usize) -> &mut Self {
        let bytes = value.to_be_bytes();
        self.0.extend_from_slice(&bytes[4 - len..]);
        self
    }

    fn u8(&mut self, value: u32) -> &mut Self {
        self.be(value, 1)
    }

    fn lit(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.extend_from_slice(bytes);
        self
    }

    /// `rh(n)` — n random bytes.
    fn random(&mut self, rng: &mut impl Rng, n: u32) -> &mut Self {
        let at = self.0.len();
        self.0.resize(at + n as usize, 0);
        rng.fill(&mut self.0[at..]);
        self
    }

    fn len(&self) -> u32 {
        self.0.len() as u32
    }

    fn into_tag(self) -> Tag {
        Tag::Bytes(self.0)
    }
}

/// `tagOverhead` — `<c>` and `<t>` are four bytes each.
fn tag_overhead(opts: &MimicOptions) -> u32 {
    u32::from(opts.tag_c) * 4 + u32::from(opts.tag_t) * 4
}

/// `calcPadding` — how much filler to add so the packet lands where a real one
/// would.
///
/// With a browser fingerprint the target is a measured size band, and the pad is
/// whatever it takes to reach it plus a little jitter. Without one it is a
/// function of intensity alone. Either way it is clamped so the packet cannot
/// exceed the MTU and fragment — a fragmented "QUIC Initial" is a giveaway on
/// its own.
fn calc_padding(
    rng: &mut impl Rng,
    header_b: u32,
    extra_b: u32,
    range: Option<(u32, u32)>,
    iv: u32,
    mtu: u32,
) -> u32 {
    let max_pad = mtu.saturating_sub(header_b + extra_b);

    let Some((min, max)) = range else {
        return (rng.range(20, 80) * iv).min(500).min(max_pad);
    };

    let occupied = header_b + extra_b;
    let clamped_min = min.min(mtu);
    let clamped_max = max.min(mtu);
    let needed = clamped_min.saturating_sub(occupied);
    // Signed arithmetic on purpose: every one of these terms goes negative for a
    // header that already overshoots the band, and the TS relies on Math.max(0).
    let jitter = (i64::from(clamped_max) - i64::from(clamped_min))
        .min(i64::from(clamped_max) - i64::from(occupied) - i64::from(needed))
        .clamp(0, 20) as u32;
    let pad = needed + if jitter > 0 { rng.range(0, jitter) } else { 0 };
    pad.min(max_pad)
}

/// Chromium rounds its ClientHello record up to a multiple of 128 bytes; Firefox
/// and Safari do not, and the difference is visible on the wire.
fn align_to_128(n: u32) -> u32 {
    n.div_ceil(128) * 128
}

// ------------------------------------------------------------------- profiles

pub(super) fn quic_initial(rng: &mut impl Rng, opts: &MimicOptions, iv: u32) -> Chain {
    let host = opts.host(rng, super::hosts::QUIC_INITIAL);
    let dcid = rng.range(8, 20);
    let scid = rng.range(0, 20);
    // Half of all real Initials carry no token at all.
    let token_len = if rng.range(0, 1) == 0 {
        0
    } else {
        rng.range(8, 32)
    };
    let sni_rc = (host.len() as u32 + rng.range(0, 6)).min(64);

    let mut b = Buf::new();
    b.u8(0xc0 | rng.range(0, 3)) // long header, Initial, random packet-number length
        .lit(&[0x00, 0x00, 0x00, 0x01]) // version 1
        .u8(dcid)
        .random(rng, dcid)
        .u8(scid)
        .random(rng, scid)
        .u8(token_len)
        .random(rng, token_len)
        .random(rng, 4);

    let header_b = b.len();
    let extra_b = if opts.tag_rc { sni_rc } else { 0 } + tag_overhead(opts);
    let pad = calc_padding(
        rng,
        header_b,
        extra_b,
        opts.fp_range(BfpSlot::Qi),
        iv,
        opts.mtu,
    );

    let mut c = Chain::new();
    c.push(b.into_tag())
        .push_if(opts.tag_rc, Tag::RandomLetters(sni_rc))
        .push_if(opts.tag_c, Tag::Counter)
        .push_if(opts.tag_t, Tag::Timestamp);
    if opts.tag_r {
        c.push_padding(pad, PadKind::Bytes);
    }
    c
}

pub(super) fn quic_0rtt(rng: &mut impl Rng, opts: &MimicOptions, iv: u32) -> Chain {
    let host = opts.host(rng, super::hosts::QUIC_0RTT);
    let dcid = rng.range(8, 20);
    let scid = rng.range(0, 20);
    let ticket_hint = (host.len() as u32 + rng.range(4, 16)).min(48);

    let mut b = Buf::new();
    b.u8(0xd0 | rng.range(0, 3)) // long header, 0-RTT
        .lit(&[0x00, 0x00, 0x00, 0x01])
        .u8(dcid)
        .random(rng, dcid)
        .u8(scid)
        .random(rng, scid)
        .random(rng, 4);

    let header_b = b.len();
    let extra_b = if opts.tag_rc { ticket_hint } else { 0 } + tag_overhead(opts);
    let pad = calc_padding(
        rng,
        header_b,
        extra_b,
        opts.fp_range(BfpSlot::Q0),
        iv,
        opts.mtu,
    );

    let mut c = Chain::new();
    c.push(b.into_tag()).push_if(opts.tag_t, Tag::Timestamp);
    if opts.tag_r {
        c.push_padding(pad, PadKind::Bytes);
    }
    c.push_if(opts.tag_rc, Tag::RandomLetters(ticket_hint))
        .push_if(opts.tag_c, Tag::Counter);
    c
}

pub(super) fn http3(rng: &mut impl Rng, opts: &MimicOptions, iv: u32) -> Chain {
    // HTTP/3 rides on established QUIC, so this draws from the same pool but
    // uses the short-header and 1-RTT packet types.
    const PTYPES: [u32; 7] = [0xc0, 0xc1, 0xc2, 0xc3, 0xe0, 0xe1, 0xe2];
    let host = opts.host(rng, super::hosts::QUIC_INITIAL);
    let dcid = rng.range(8, 20);
    let scid = rng.range(0, 20);
    // +9 for the `:authority` framing a real HEADERS frame puts around the host.
    let sni_len = (host.len() as u32 + 9 + rng.range(0, 6)).min(64);

    let mut b = Buf::new();
    b.u8(PTYPES[rng.range(0, PTYPES.len() as u32 - 1) as usize])
        .lit(&[0x00, 0x00, 0x00, 0x01])
        .u8(dcid)
        .random(rng, dcid)
        .u8(scid)
        .random(rng, scid)
        .random(rng, 4);

    let header_b = b.len();
    let extra_b = if opts.tag_rc { sni_len } else { 0 } + tag_overhead(opts);
    let pad = calc_padding(
        rng,
        header_b,
        extra_b,
        opts.fp_range(BfpSlot::H3),
        iv,
        opts.mtu,
    );

    let mut c = Chain::new();
    c.push(b.into_tag())
        .push_if(opts.tag_rc, Tag::RandomLetters(sni_len));
    if opts.tag_r {
        c.push_padding(pad, PadKind::Bytes);
    }
    c.push_if(opts.tag_c, Tag::Counter)
        .push_if(opts.tag_t, Tag::Timestamp);
    c
}

pub(super) fn tls_client_hello(rng: &mut impl Rng, opts: &MimicOptions, iv: u32) -> Chain {
    let host = opts.host(rng, super::hosts::TLS_CLIENT_HELLO);
    // The server_name extension around the host: ext type, ext len, list len,
    // name type, name len, name.
    let sni_ext = 2 + 2 + 2 + 1 + 2 + host.len() as u32;
    let sni_rc = sni_ext.min(64);

    let fp_range = opts.fp_range(BfpSlot::Tls);
    let base_len = match fp_range {
        Some((lo, hi)) => rng.range(lo, hi),
        None => rng.range(300, 550),
    };
    let rec_len = if opts.browser.is_some_and(|b| b.is_chromium()) {
        align_to_128(base_len)
    } else {
        base_len
    };
    // The handshake message sits inside the record, minus the record header.
    let hs_len = rec_len.saturating_sub(rng.range(4, 9));

    let r_len = (rng.range(20, 60) * iv)
        .min(300)
        .min(opts.mtu.saturating_sub(44 + sni_rc + tag_overhead(opts)));

    let mut b = Buf::new();
    b.lit(&[0x16, 0x03, 0x01]) // handshake record, legacy version TLS 1.0
        .be(rec_len, 2)
        .lit(&[0x01]) // ClientHello
        .be(hs_len, 3)
        .lit(&[0x03, 0x03]) // legacy_version TLS 1.2, as TLS 1.3 requires
        .random(rng, 32); // client random

    let mut c = Chain::new();
    c.push(b.into_tag())
        .push_if(opts.tag_rc, Tag::RandomLetters(sni_rc));
    if opts.tag_r {
        c.push_padding(r_len, PadKind::Bytes);
    }
    c.push_if(opts.tag_c, Tag::Counter)
        .push_if(opts.tag_t, Tag::Timestamp);
    c
}

pub(super) fn dtls(rng: &mut impl Rng, opts: &MimicOptions, iv: u32) -> Chain {
    let host = opts.host(rng, super::hosts::DTLS);
    let frag_len = rng.range(100, 300);
    let sni_rc = (host.len() as u32 + rng.range(2, 8)).min(60);
    let epoch = rng.range(0, 255);

    let mut b = Buf::new();
    b.lit(&[0x16]) // handshake
        .lit(&[0xfe, 0xfd]) // DTLS 1.2
        .be(epoch, 2)
        .random(rng, 6) // sequence number
        .be(frag_len, 2)
        .lit(&[0x01]) // ClientHello
        .random(rng, 6) // length + message sequence
        .lit(&[0xfe, 0xfd, 0x00, 0x00])
        .random(rng, 4)
        .random(rng, 32);

    let header_b = b.len();
    let extra_b = if opts.tag_rc { sni_rc } else { 0 } + tag_overhead(opts);
    let pad = calc_padding(
        rng,
        header_b,
        extra_b,
        opts.fp_range(BfpSlot::Dtls),
        iv,
        opts.mtu,
    );

    let mut c = Chain::new();
    c.push(b.into_tag())
        .push_if(opts.tag_rc, Tag::RandomLetters(sni_rc))
        .push_if(opts.tag_c, Tag::Counter)
        .push_if(opts.tag_t, Tag::Timestamp);
    if opts.tag_r {
        c.push_padding(pad, PadKind::Bytes);
    }
    c
}

pub(super) fn sip(rng: &mut impl Rng, opts: &MimicOptions, iv: u32) -> Chain {
    let host = opts.host(rng, super::hosts::SIP);

    let mut b = Buf::new();
    b.lit(b"REGISTER sip:")
        .lit(host.as_bytes())
        .lit(b" ")
        .random(rng, 4);

    let header_b = b.len();
    // Where the branch parameter, Call-ID and the rest of the header block would
    // be — letters, because that is what a DPI box reading SIP expects to find.
    let rc_val = (host.len() as u32 + rng.range(8, 24) * iv).min(150);
    let r_len = (rng.range(5, 30) * iv).min(120).min(
        opts.mtu
            .saturating_sub(header_b + rc_val + tag_overhead(opts)),
    );

    let mut c = Chain::new();
    c.push(b.into_tag())
        .push_if(opts.tag_rc, Tag::RandomLetters(rc_val))
        .push_if(opts.tag_c, Tag::Counter)
        .push_if(opts.tag_t, Tag::Timestamp);
    if opts.tag_r {
        c.push_padding(r_len, PadKind::Bytes);
    }
    c
}

pub(super) fn dns_query(rng: &mut impl Rng, opts: &MimicOptions, iv: u32) -> Chain {
    let host = opts.host(rng, super::hosts::DNS);

    let mut name = Vec::new();
    for label in host.split('.') {
        name.push(label.len() as u8);
        name.extend_from_slice(label.as_bytes());
    }
    name.push(0); // root

    let mut b = Buf::new();
    b.random(rng, 2) // transaction id
        .lit(&[0x01, 0x00]) // standard query, recursion desired
        .lit(&[0x00, 0x01]) // QDCOUNT
        .lit(&[0x00, 0x00]) // ANCOUNT
        .lit(&[0x00, 0x00]) // NSCOUNT
        .lit(&[0x00, 0x00]) // ARCOUNT
        .lit(&name)
        // Alternating A and AAAA across the chain, so five packets do not all
        // ask the same question.
        .lit(if iv.is_multiple_of(2) {
            &[0x00, 0x01]
        } else {
            &[0x00, 0x1c]
        })
        .lit(&[0x00, 0x01]); // IN

    let header_b = b.len();
    // A real query is padded out by the resolver's own EDNS options; 512 is the
    // classic UDP DNS ceiling.
    let target_size = rng.range(64, 512.min(opts.mtu.saturating_sub(20)));
    let r_len = target_size.saturating_sub(header_b);

    let mut c = Chain::new();
    c.push(b.into_tag());
    if opts.tag_r && r_len > 0 {
        c.push_padding(r_len.min(200), PadKind::Bytes);
    }
    c.push_if(opts.tag_t, Tag::Timestamp)
        .push_if(opts.tag_c, Tag::Counter);
    c
}

pub(super) fn wireguard_noise(rng: &mut impl Rng, opts: &MimicOptions, iv: u32) -> Chain {
    // Stock WireGuard's own initiation, as a decoy: a censor that drops
    // AmneziaWG but tolerates WireGuard sees what it tolerates.
    const MESSAGE_INITIATION_SIZE: u32 = 148;
    let rc_len = rng.range(4, 12);

    let extra_b = if opts.tag_rc { rc_len } else { 0 } + tag_overhead(opts);
    let range = opts.fp_range(BfpSlot::Nx);
    let pad = match range {
        Some(_) => calc_padding(rng, MESSAGE_INITIATION_SIZE, extra_b, range, iv, opts.mtu),
        None => (rng.range(10, 40) * iv)
            .min(200)
            .min(opts.mtu.saturating_sub(MESSAGE_INITIATION_SIZE + extra_b)),
    };

    let mut c = Chain::new();
    // Type 1 + three reserved zero bytes, then sender index.
    let mut head = Buf::new();
    head.lit(&[0x01, 0x00, 0x00, 0x00]).random(rng, 4);
    c.push(head.into_tag());
    for n in [32u32, 48, 28, 32] {
        // ephemeral, encrypted static, encrypted timestamp, MACs
        let mut part = Buf::new();
        part.random(rng, n);
        c.push(part.into_tag());
    }
    if opts.tag_r {
        c.push_padding(pad, PadKind::Bytes);
    }
    c.push_if(opts.tag_t, Tag::Timestamp)
        .push_if(opts.tag_rc, Tag::RandomLetters(rc_len));
    c
}

/// I2–I5 when the chain is not imitating anything in particular.
///
/// The point is variety rather than resemblance: eight tag orderings, a size
/// that is usually small but occasionally large, and a leading literal that only
/// appears at higher intensities. A burst where every packet has the same shape
/// is itself a signature.
pub(super) fn entropy(rng: &mut impl Rng, opts: &MimicOptions, idx: u32, iv: u32) -> Chain {
    let is_big = rng.range(1, 10) > 6;
    let base_len = if is_big {
        rng.range(200, 500)
    } else {
        rng.range(4, 20)
    };
    let r_len = (base_len * iv)
        .min(if is_big { 500 } else { 60 })
        .min(opts.mtu.saturating_sub(20 + tag_overhead(opts)));

    let rc_len = rng.range(4, 12);
    let rd_len = rng.range(4, 8);

    let mut b = None;
    if iv >= 2 {
        let n = rng.range(4, 8 * iv);
        let mut buf = Buf::new();
        buf.random(rng, n);
        b = Some(buf.into_tag());
    }
    let mut b2 = None;
    if iv >= 3 {
        let n = rng.range(2, 4);
        let mut buf = Buf::new();
        buf.random(rng, n);
        b2 = Some(buf.into_tag());
    }

    // Each slot is either a tag or nothing, matching the TS string concatenation
    // of possibly-empty fragments.
    let c_tag = opts.tag_c.then_some(Tag::Counter);
    let t_tag = opts.tag_t.then_some(Tag::Timestamp);
    let rc_tag = opts.tag_rc.then_some(Tag::RandomLetters(rc_len));
    let rd_tag = opts.tag_rd.then_some(Tag::RandomDigits(rd_len));

    #[derive(Clone, Copy)]
    enum Slot {
        B,
        B2,
        R,
        C,
        T,
        Rc,
        Rd,
    }
    use Slot::*;
    const PATTERNS: [&[Slot]; 8] = [
        &[B, R, T, Rc, C, Rd],
        &[C, T, B, R, Rc, Rd],
        &[Rc, B, R, C, T, Rd],
        &[T, R, C, Rc, B, Rd],
        &[R, Rc, B, T, C, Rd],
        &[B2, T, R, B, Rc, C, Rd],
        &[Rd, B, Rc, R, T, C, B2],
        &[C, B, B2, T, Rc, R, Rd],
    ];

    let pattern =
        PATTERNS[((idx + rng.range(0, PATTERNS.len() as u32 - 1)) as usize) % PATTERNS.len()];
    let mut chain = Chain::new();
    for slot in pattern {
        match slot {
            B => {
                if let Some(t) = b.clone() {
                    chain.push(t);
                }
            }
            B2 => {
                if let Some(t) = b2.clone() {
                    chain.push(t);
                }
            }
            R => {
                if opts.tag_r {
                    chain.push_padding(r_len, PadKind::Bytes);
                }
            }
            C => {
                if let Some(t) = c_tag.clone() {
                    chain.push(t);
                }
            }
            T => {
                if let Some(t) = t_tag.clone() {
                    chain.push(t);
                }
            }
            Rc => {
                if let Some(t) = rc_tag.clone() {
                    chain.push(t);
                }
            }
            Rd => {
                if let Some(t) = rd_tag.clone() {
                    chain.push(t);
                }
            }
        }
    }

    if chain.is_empty() {
        // Every tag switched off, or a zero-length pad. An empty I-value is
        // legal but pointless, so fall back to the smallest useful packet.
        chain.push(Tag::Random(10));
    }
    chain
}
