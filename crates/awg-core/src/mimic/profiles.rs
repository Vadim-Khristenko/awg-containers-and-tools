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

    /// A QUIC variable-length integer, RFC 9000 §16: the top two bits of the
    /// first byte give the length (1, 2, 4 or 8 bytes), the rest is the value.
    fn varint(&mut self, value: u32) -> &mut Self {
        let v = u64::from(value);
        match v {
            0..0x40 => self.0.push(v as u8),
            0x40..0x4000 => self.0.extend_from_slice(&(0x4000 | v as u16).to_be_bytes()),
            0x4000..0x4000_0000 => self
                .0
                .extend_from_slice(&(0x8000_0000 | v as u32).to_be_bytes()),
            _ => self
                .0
                .extend_from_slice(&(0xc000_0000_0000_0000 | v).to_be_bytes()),
        }
        self
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

/// A QUIC Initial, per RFC 9000 §17.2.2.
///
/// The header is built in wire order, and the Length field is computed rather
/// than filled with random bytes: it is a varint covering the packet number and
/// everything after it, so the padding is decided first and the header
/// assembled around it. The tags after the `<b>` are on the wire behind the
/// header too, so their bytes belong in the Length as much as the padding does.
///
/// First byte: long header, fixed bit, type Initial, reserved bits, then the
/// packet number length minus one. A client's first Initial carries a
/// Destination Connection ID of at least 8 bytes (§7.2); both IDs cap at 20.
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
    let pn_len = rng.range(1, 4);

    let mut b = Buf::new();
    b.u8(0xc0 | (pn_len - 1))
        .lit(&QUIC_V1)
        .u8(dcid)
        .random(rng, dcid)
        .u8(scid)
        .random(rng, scid)
        .varint(token_len)
        .random(rng, token_len);

    let extra_b = if opts.tag_rc { sni_rc } else { 0 } + tag_overhead(opts);
    let pad = quic_pad(
        rng,
        &b,
        pn_len,
        extra_b,
        opts.fp_range(BfpSlot::Qi),
        iv,
        opts.mtu,
    );
    let sent_pad = if opts.tag_r { pad } else { 0 };
    b.varint(pn_len + sent_pad + extra_b).random(rng, pn_len);

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

/// A QUIC 0-RTT packet, per RFC 9000 §17.2.3: type `01` and, unlike an
/// Initial, no token field.
pub(super) fn quic_0rtt(rng: &mut impl Rng, opts: &MimicOptions, iv: u32) -> Chain {
    let host = opts.host(rng, super::hosts::QUIC_0RTT);
    let dcid = rng.range(8, 20);
    let scid = rng.range(0, 20);
    let ticket_hint = (host.len() as u32 + rng.range(4, 16)).min(48);
    let pn_len = rng.range(1, 4);

    let mut b = Buf::new();
    b.u8(0xd0 | (pn_len - 1))
        .lit(&QUIC_V1)
        .u8(dcid)
        .random(rng, dcid)
        .u8(scid)
        .random(rng, scid);

    let extra_b = if opts.tag_rc { ticket_hint } else { 0 } + tag_overhead(opts);
    let pad = quic_pad(
        rng,
        &b,
        pn_len,
        extra_b,
        opts.fp_range(BfpSlot::Q0),
        iv,
        opts.mtu,
    );
    let sent_pad = if opts.tag_r { pad } else { 0 };
    b.varint(pn_len + sent_pad + extra_b).random(rng, pn_len);

    let mut c = Chain::new();
    c.push(b.into_tag()).push_if(opts.tag_t, Tag::Timestamp);
    if opts.tag_r {
        c.push_padding(pad, PadKind::Bytes);
    }
    c.push_if(opts.tag_rc, Tag::RandomLetters(ticket_hint))
        .push_if(opts.tag_c, Tag::Counter);
    c
}

/// A long-header packet from an HTTP/3 connection's opening: Initial or
/// Handshake.
///
/// The two differ in more than the type nibble: an Initial carries a token
/// length and a Handshake does not (§17.2.2, §17.2.4). Picking a first byte
/// from both types and writing one structure for all of them gave half the
/// packets a field their own type says is not there.
pub(super) fn http3(rng: &mut impl Rng, opts: &MimicOptions, iv: u32) -> Chain {
    let host = opts.host(rng, super::hosts::QUIC_INITIAL);
    let dcid = rng.range(8, 20);
    let scid = rng.range(0, 20);
    // +9 for the `:authority` framing a real HEADERS frame puts around the host.
    let sni_len = (host.len() as u32 + 9 + rng.range(0, 6)).min(64);
    let pn_len = rng.range(1, 4);
    let is_initial = rng.range(0, 1) == 0;
    let token_len = if is_initial && rng.range(0, 1) == 1 {
        rng.range(8, 32)
    } else {
        0
    };

    let mut b = Buf::new();
    b.u8(if is_initial { 0xc0 } else { 0xe0 } | (pn_len - 1))
        .lit(&QUIC_V1)
        .u8(dcid)
        .random(rng, dcid)
        .u8(scid)
        .random(rng, scid);
    if is_initial {
        b.varint(token_len).random(rng, token_len);
    }

    let extra_b = if opts.tag_rc { sni_len } else { 0 } + tag_overhead(opts);
    let pad = quic_pad(
        rng,
        &b,
        pn_len,
        extra_b,
        opts.fp_range(BfpSlot::H3),
        iv,
        opts.mtu,
    );
    let sent_pad = if opts.tag_r { pad } else { 0 };
    b.varint(pn_len + sent_pad + extra_b).random(rng, pn_len);

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

/// QUIC version 1.
const QUIC_V1: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

/// The padding for a long-header packet whose Length is still to be written.
/// Two bytes are reserved for that varint: any payload past 63 bytes needs
/// them, and an Initial shorter than that would be strange in itself.
fn quic_pad(
    rng: &mut impl Rng,
    prefix: &Buf,
    pn_len: u32,
    extra_b: u32,
    range: Option<(u32, u32)>,
    iv: u32,
    mtu: u32,
) -> u32 {
    calc_padding(rng, prefix.len() + 2 + pn_len, extra_b, range, iv, mtu)
}

/// TLS record header: content type, legacy version, and the length that follows.
const TLS_RECORD_HEADER: u32 = 5;
/// What the `<b>` blob writes of the ClientHello: handshake type and its
/// three-byte length, legacy version, and the 32-byte client random.
const TLS_HELLO_PREFIX: u32 = 1 + 3 + 2 + 32;
/// A handshake body length excludes its own type and length bytes.
const TLS_HANDSHAKE_HEADER: u32 = 4;

/// A TLS 1.3 ClientHello: record layer per RFC 8446 §5.1, handshake per §4.1.2.
///
/// Both length fields are computed. The record declares how many bytes follow
/// it and the handshake declares its own body; both used to be drawn at random,
/// so the record claimed one size while the packet carried another, which is
/// the first thing anything parsing TLS checks. Everything after the `<b>`
/// blob is inside the record (the SNI-sized `<rc>`, the `<r>` padding, the
/// counter and timestamp), so the padding is decided first and the lengths
/// written around it.
pub(super) fn tls_client_hello(rng: &mut impl Rng, opts: &MimicOptions, iv: u32) -> Chain {
    let host = opts.host(rng, super::hosts::TLS_CLIENT_HELLO);
    // server_name extension: ext type, ext len, list len, name type, name len.
    let sni_ext = 2 + 2 + 2 + 1 + 2 + host.len() as u32;
    let sni_rc = sni_ext.min(64);

    let base_len = match opts.fp_range(BfpSlot::Tls) {
        Some((lo, hi)) => rng.range(lo, hi),
        None => rng.range(300, 550),
    };
    // Chromium pads its ClientHello to a multiple of 128 bytes, which is part
    // of what makes a Chrome handshake look like one.
    let target = if opts.browser.is_some_and(|b| b.is_chromium()) {
        align_to_128(base_len)
    } else {
        base_len
    };

    let tag_bytes = if opts.tag_rc { sni_rc } else { 0 } + tag_overhead(opts);
    let fixed = TLS_RECORD_HEADER + TLS_HELLO_PREFIX + tag_bytes;
    let padding = if opts.tag_r {
        let drawn = (rng.range(20, 60) * iv).min(300);
        target
            .saturating_sub(fixed)
            .min(opts.mtu.saturating_sub(fixed))
            .min(drawn)
    } else {
        0
    };

    let record_len = TLS_HELLO_PREFIX + tag_bytes + padding;
    let handshake_len = record_len - TLS_HANDSHAKE_HEADER;

    let mut b = Buf::new();
    b.lit(&[0x16, 0x03, 0x01]) // handshake record, legacy version TLS 1.0
        .be(record_len, 2)
        .lit(&[0x01]) // ClientHello
        .be(handshake_len, 3)
        .lit(&[0x03, 0x03]) // legacy_version TLS 1.2, as TLS 1.3 requires
        .random(rng, 32); // client random

    let mut c = Chain::new();
    c.push(b.into_tag())
        .push_if(opts.tag_rc, Tag::RandomLetters(sni_rc));
    if opts.tag_r {
        c.push_padding(padding, PadKind::Bytes);
    }
    c.push_if(opts.tag_c, Tag::Counter)
        .push_if(opts.tag_t, Tag::Timestamp);
    c
}

/// DTLS record header: type, version, epoch, sequence number, length.
const DTLS_RECORD_HEADER: u32 = 1 + 2 + 2 + 6 + 2;
/// DTLS handshake header: type, length, message sequence, fragment offset,
/// fragment length. Both versions frame the first flight the same way.
const DTLS_HANDSHAKE_HEADER: u32 = 1 + 3 + 2 + 3 + 3;

/// The ClientHello tail a DTLS 1.3 client sends after its random, RFC 9147
/// §5.3: empty session id, empty cookie (a 1.3-only client sends zero
/// length), the three DTLS-OK TLS 1.3 suites, null compression, and one
/// supported_versions extension announcing 0xfefc. The version fields on the
/// wire stay 0xfefd; that is what the RFC asks for.
const DTLS13_TAIL: &[u8] = &[
    0x00, 0x00, // session id, cookie: both empty
    0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, // suites
    0x01, 0x00, // compression: null
    0x00, 0x07, // extensions length
    0x00, 0x2b, 0x00, 0x03, 0x02, 0xfe, 0xfc, // supported_versions: DTLS 1.3
];

/// A DTLS 1.2 ClientHello: client version 0xfefd (ones' complement, so DTLS
/// counts down where TLS counts up) and the 32-byte random. RFC 6347 §4.1,
/// handshake §4.2.2.
pub(super) fn dtls12(rng: &mut impl Rng, opts: &MimicOptions, iv: u32) -> Chain {
    let mut body = Buf::new();
    body.lit(&[0xfe, 0xfd]).random(rng, 32);
    dtls_flight(rng, opts, iv, body.0)
}

/// A DTLS 1.3 ClientHello: legacy_version, random, and the §5.3 tail.
pub(super) fn dtls13(rng: &mut impl Rng, opts: &MimicOptions, iv: u32) -> Chain {
    let mut body = Buf::new();
    body.lit(&[0xfe, 0xfd]).random(rng, 32).lit(DTLS13_TAIL);
    dtls_flight(rng, opts, iv, body.0)
}

/// One unfragmented DTLS first flight around a ClientHello body.
///
/// A ClientHello opens the first flight, before any cipher change, so its epoch
/// is 0 and nothing else is possible: a random epoch is a giveaway, not
/// variety. Message sequence 0, fragment offset 0, fragment length equal to the
/// whole body, and a record length that describes what it precedes, tags
/// included.
fn dtls_flight(rng: &mut impl Rng, opts: &MimicOptions, iv: u32, body: Vec<u8>) -> Chain {
    let host = opts.host(rng, super::hosts::DTLS);
    let sni_rc = (host.len() as u32 + rng.range(2, 8)).min(60);
    let tag_bytes = if opts.tag_rc { sni_rc } else { 0 } + tag_overhead(opts);

    let fixed = DTLS_RECORD_HEADER + DTLS_HANDSHAKE_HEADER + body.len() as u32;
    let padding = if opts.tag_r {
        calc_padding(
            rng,
            fixed,
            tag_bytes,
            opts.fp_range(BfpSlot::Dtls),
            iv,
            opts.mtu,
        )
    } else {
        0
    };
    let body_len = body.len() as u32 + tag_bytes + padding;
    let record_len = DTLS_HANDSHAKE_HEADER + body_len;

    let mut b = Buf::new();
    b.lit(&[0x16]) // handshake
        // legacy_record_version is {254,253} in both versions: RFC 6347 §4.1,
        // RFC 9147 §4.
        .lit(&[0xfe, 0xfd])
        .lit(&[0x00, 0x00]) // epoch 0
        // A 48-bit sequence number. Real stacks start at zero and count up.
        .be(0, 4)
        .be(rng.range(0, 4), 2)
        .be(record_len, 2)
        .lit(&[0x01]) // ClientHello
        .be(body_len, 3)
        .lit(&[0x00, 0x00]) // first message of the flight
        .lit(&[0x00, 0x00, 0x00]) // fragment offset
        .be(body_len, 3) // unfragmented
        .lit(&body);

    let mut c = Chain::new();
    c.push(b.into_tag())
        .push_if(opts.tag_rc, Tag::RandomLetters(sni_rc))
        .push_if(opts.tag_c, Tag::Counter)
        .push_if(opts.tag_t, Tag::Timestamp);
    if opts.tag_r {
        c.push_padding(padding, PadKind::Bytes);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::SeededRng;

    fn read_varint(b: &[u8], at: &mut usize) -> u64 {
        let len = 1usize << (b[*at] >> 6);
        let mut v = u64::from(b[*at] & 0x3f);
        for i in 1..len {
            v = (v << 8) | u64::from(b[*at + i]);
        }
        *at += len;
        v
    }

    /// Walk a long header the way a QUIC reader does and return
    /// (first byte, declared Length, bytes actually behind the Length field).
    fn parse_long_header(pkt: &[u8]) -> (u8, u64, usize) {
        let first = pkt[0];
        assert_eq!(first & 0xc0, 0xc0, "long header with the fixed bit");
        assert_eq!(&pkt[1..5], &QUIC_V1, "version 1");
        let mut at = 5;
        let dcid = pkt[at] as usize;
        assert!((8..=20).contains(&dcid), "DCID {dcid}");
        at += 1 + dcid;
        let scid = pkt[at] as usize;
        assert!(scid <= 20, "SCID {scid}");
        at += 1 + scid;
        if first & 0x30 == 0x00 {
            let token = read_varint(pkt, &mut at) as usize;
            at += token;
        }
        let length = read_varint(pkt, &mut at);
        (first, length, pkt.len() - at)
    }

    fn all_tags() -> MimicOptions {
        MimicOptions {
            tag_c: true,
            ..Default::default()
        }
    }

    #[test]
    fn varints_take_the_width_their_value_needs() {
        for (value, bytes) in [
            (0u32, vec![0x00]),
            (63, vec![0x3f]),
            (64, vec![0x40, 0x40]),
            (16_383, vec![0x7f, 0xff]),
            (16_384, vec![0x80, 0x00, 0x40, 0x00]),
        ] {
            let mut b = Buf::new();
            b.varint(value);
            assert_eq!(b.0, bytes, "{value}");
            let mut at = 0;
            assert_eq!(read_varint(&b.0, &mut at), u64::from(value));
        }
    }

    #[test]
    fn every_quic_packet_declares_the_length_that_follows_it() {
        type Build = fn(&mut SeededRng, &MimicOptions, u32) -> Chain;
        let builders: [(&str, Build, &[u8]); 3] = [
            ("initial", quic_initial, &[0x00]),
            ("0-rtt", quic_0rtt, &[0x10]),
            ("http3", http3, &[0x00, 0x20]),
        ];
        for (name, build, types) in builders {
            for opts in [
                all_tags(),
                MimicOptions::default(),
                MimicOptions {
                    tag_r: false,
                    tag_rc: false,
                    ..all_tags()
                },
            ] {
                for seed in 0..200u64 {
                    let mut rng = SeededRng::new(seed);
                    let pkt = build(&mut rng, &opts, 2).materialize(&mut rng, 7, 9);
                    let (first, length, behind) = parse_long_header(&pkt);
                    assert!(types.contains(&(first & 0x30)), "{name}: type {first:#x}");
                    assert_eq!(length as usize, behind, "{name} seed {seed}: Length lies");
                    let pn_len = u64::from(first & 0x03) + 1;
                    assert!(
                        length >= pn_len,
                        "{name}: Length shorter than the packet number"
                    );
                    assert!(pkt.len() as u32 <= opts.mtu, "{name}: over the MTU");
                }
            }
        }
    }

    #[test]
    fn the_client_hello_record_and_handshake_lengths_are_true() {
        for opts in [
            all_tags(),
            MimicOptions::default(),
            MimicOptions {
                tag_r: false,
                ..all_tags()
            },
            MimicOptions {
                browser: Some(super::super::BrowserProfile::Chrome),
                ..all_tags()
            },
        ] {
            for seed in 0..200u64 {
                let mut rng = SeededRng::new(seed);
                let pkt = tls_client_hello(&mut rng, &opts, 2).materialize(&mut rng, 3, 4);
                assert_eq!(&pkt[..3], &[0x16, 0x03, 0x01], "handshake record");
                let record = usize::from(u16::from_be_bytes([pkt[3], pkt[4]]));
                assert_eq!(record, pkt.len() - 5, "seed {seed}: record length lies");
                assert_eq!(pkt[5], 0x01, "ClientHello");
                let hs =
                    (usize::from(pkt[6]) << 16) | (usize::from(pkt[7]) << 8) | usize::from(pkt[8]);
                assert_eq!(hs, record - 4, "seed {seed}: handshake length lies");
                assert_eq!(&pkt[9..11], &[0x03, 0x03]);
                assert!(pkt.len() as u32 <= opts.mtu);
            }
        }
    }

    #[test]
    fn dtls_first_flights_are_epoch_zero_and_their_lengths_are_true() {
        type Build = fn(&mut SeededRng, &MimicOptions, u32) -> Chain;
        let builders: [(&str, Build); 2] = [("1.2", dtls12), ("1.3", dtls13)];
        for (name, build) in builders {
            for opts in [
                all_tags(),
                MimicOptions::default(),
                MimicOptions {
                    tag_r: false,
                    ..all_tags()
                },
            ] {
                for seed in 0..150u64 {
                    let mut rng = SeededRng::new(seed);
                    let pkt = build(&mut rng, &opts, 2).materialize(&mut rng, 5, 6);
                    assert_eq!(&pkt[..3], &[0x16, 0xfe, 0xfd], "{name}");
                    assert_eq!(&pkt[3..5], &[0, 0], "{name}: epoch must be 0");
                    let record = usize::from(u16::from_be_bytes([pkt[11], pkt[12]]));
                    assert_eq!(record, pkt.len() - 13, "{name} seed {seed}: record length");
                    assert_eq!(pkt[13], 0x01, "ClientHello");
                    let len24 = |i: usize| {
                        (usize::from(pkt[i]) << 16)
                            | (usize::from(pkt[i + 1]) << 8)
                            | usize::from(pkt[i + 2])
                    };
                    let body = len24(14);
                    assert_eq!(body, record - 12, "{name}: handshake length");
                    assert_eq!(&pkt[17..22], &[0, 0, 0, 0, 0], "{name}: seq 0, offset 0");
                    assert_eq!(len24(22), body, "{name}: unfragmented");
                    assert_eq!(&pkt[25..27], &[0xfe, 0xfd], "{name}: client version");
                }
            }
        }
    }

    #[test]
    fn the_dtls13_tail_declares_the_extensions_it_carries() {
        // session id, cookie, suites, compression, then extensions.
        let at = 2 + 8 + 2;
        let declared = usize::from(u16::from_be_bytes([DTLS13_TAIL[at], DTLS13_TAIL[at + 1]]));
        assert_eq!(declared, DTLS13_TAIL.len() - at - 2);
    }

    #[test]
    fn only_initials_carry_a_token() {
        // A Handshake has no token field, so its Length comes straight after
        // the SCID; parse_long_header would misread it otherwise and the
        // Length check above would fail.
        let mut seen = [false; 2];
        for seed in 0..100u64 {
            let mut rng = SeededRng::new(seed);
            let pkt = http3(&mut rng, &all_tags(), 2).materialize(&mut rng, 1, 1);
            seen[usize::from(pkt[0] & 0x20 != 0)] = true;
        }
        assert_eq!(seen, [true, true], "both Initial and Handshake come out");
    }
}
