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
use super::hostdb::{DnsType, Role};
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
    let host = opts.host(rng, Role::Quic, None);
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
    let host = opts.host(rng, Role::Quic, None);
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
    let host = opts.host(rng, Role::Quic, None);
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
    let host = opts.host(rng, Role::Tls, None);
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

/// The ClientHello a DTLS 1.3 client sends after its random, RFC 9147 §5.3, up
/// to the extensions: empty session id, empty cookie (a 1.3-only client sends
/// zero length), the three DTLS-OK TLS 1.3 suites, null compression. The
/// version fields on the wire stay 0xfefd; that is what the RFC asks for.
const DTLS13_TAIL: &[u8] = &[
    0x00, 0x00, // session id, cookie: both empty
    0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, // suites
    0x01, 0x00, // compression: null
];

/// supported_versions announcing DTLS 1.3: type 0x002b, length 3, a one-byte
/// list length of 2, then 0xfefc. The extensions length in front of it is
/// written by [`dtls_flight`], which also counts what the tags add after it.
const DTLS13_EXTENSIONS: &[u8] = &[0x00, 0x2b, 0x00, 0x03, 0x02, 0xfe, 0xfc];

/// A DTLS 1.2 ClientHello: client version 0xfefd (ones' complement, so DTLS
/// counts down where TLS counts up) and the 32-byte random. RFC 6347 §4.1,
/// handshake §4.2.2.
pub(super) fn dtls12(rng: &mut impl Rng, opts: &MimicOptions, iv: u32) -> Chain {
    let mut body = Buf::new();
    body.lit(&[0xfe, 0xfd]).random(rng, 32);
    dtls_flight(rng, opts, iv, body.0, None)
}

/// A DTLS 1.3 ClientHello: legacy_version, random, the §5.3 tail and its
/// extensions.
pub(super) fn dtls13(rng: &mut impl Rng, opts: &MimicOptions, iv: u32) -> Chain {
    let mut body = Buf::new();
    body.lit(&[0xfe, 0xfd]).random(rng, 32).lit(DTLS13_TAIL);
    dtls_flight(rng, opts, iv, body.0, Some(DTLS13_EXTENSIONS))
}

/// One unfragmented DTLS first flight around a ClientHello body.
///
/// A ClientHello opens the first flight, before any cipher change, so its epoch
/// is 0 and nothing else is possible: a random epoch is a giveaway, not
/// variety. Message sequence 0, fragment offset 0, fragment length equal to the
/// whole body, and a record length that describes what it precedes, tags
/// included.
///
/// A body that reaches its extensions block passes them in `extensions`. Then
/// the extensions length is written here and covers the tag bytes too, which
/// ride in a GREASE extension (RFC 8701) whose content a receiver must ignore,
/// so the ClientHello parses to its last byte. Padding (RFC 7685) would be the
/// obvious home, but its content has to be zeros and `<r>` is not. The shape
/// matches Architect 4.5.1.
fn dtls_flight(
    rng: &mut impl Rng,
    opts: &MimicOptions,
    iv: u32,
    mut body: Vec<u8>,
    extensions: Option<&[u8]>,
) -> Chain {
    let host = opts.host(rng, Role::Dtls, None);
    let sni_rc = (host.len() as u32 + rng.range(2, 8)).min(60);
    let tag_bytes = if opts.tag_rc { sni_rc } else { 0 } + tag_overhead(opts);

    // Two bytes of extensions length and four of GREASE header, when there
    // is an extensions block for the tags to extend.
    let ext_overhead = extensions.map_or(0, |e| e.len() as u32 + 2 + 4);
    let fixed = DTLS_RECORD_HEADER + DTLS_HANDSHAKE_HEADER + body.len() as u32 + ext_overhead;
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
    let trail = tag_bytes + padding;
    if let Some(ext) = extensions {
        let mut grease = Vec::new();
        if trail > 0 {
            // One of 0x0a0a, 0x1a1a ... 0xfafa.
            let n = rng.range(0, 15) as u8;
            grease.extend_from_slice(&[(n << 4) | 0x0a, (n << 4) | 0x0a]);
            grease.extend_from_slice(&(trail as u16).to_be_bytes());
        }
        let ext_len = ext.len() as u32 + grease.len() as u32 + trail;
        body.extend_from_slice(&(ext_len as u16).to_be_bytes());
        body.extend_from_slice(ext);
        body.extend_from_slice(&grease);
    }
    let body_len = body.len() as u32 + trail;
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

/// A SIP REGISTER request, per RFC 3261 §7.1.
///
/// The request line used to be `REGISTER sip:<host> ` and four random bytes
/// where SIP wants the protocol version, which any parser rejects on the first
/// line. A REGISTER also carries mandatory headers: Via with a branch starting
/// with the magic cookie `z9hG4bK`, From and To with the address of record,
/// Call-ID, CSeq naming the method, Max-Forwards and Content-Length.
///
/// The padding goes in the body with Content-Length declaring it, which is how
/// SIP carries arbitrary bytes, so the padded message stays a valid one rather
/// than a valid one with rubbish stuck to the end.
///
/// With [`MimicOptions::compact`] the same request comes in RFC 3261's compact
/// form (§7.3.3): one-letter Via, From, To, Call-ID and Content-Length, no
/// Contact or User-Agent, at about two thirds of the bytes. Phones use it for
/// exactly this, to keep a request inside one datagram; here it keeps five of
/// them inside the kernel module's netlink budget.
pub(super) fn sip(rng: &mut impl Rng, opts: &MimicOptions, iv: u32) -> Chain {
    let host = opts.host(rng, Role::Sip, None);
    let user = format!("user{}", rng.range(1000, 9999));

    let rc_val = (host.len() as u32 + rng.range(8, 24) * iv).min(150);
    let tag_bytes = if opts.tag_rc { rc_val } else { 0 } + tag_overhead(opts);

    let headers: Vec<String> = if opts.compact {
        vec![
            format!("REGISTER sip:{host} SIP/2.0"),
            format!(
                "v: SIP/2.0/UDP {host}:5060;branch=z9hG4bK{};rport",
                hex_token(rng, 5)
            ),
            "Max-Forwards: 70".into(),
            format!("f: <sip:{user}@{host}>;tag={}", hex_token(rng, 4)),
            format!("t: <sip:{user}@{host}>"),
            format!("i: {}@{host}", hex_token(rng, 8)),
            format!("CSeq: {} REGISTER", rng.range(1, 9999)),
        ]
    } else {
        vec![
            format!("REGISTER sip:{host} SIP/2.0"),
            format!(
                "Via: SIP/2.0/UDP {host}:5060;branch=z9hG4bK{};rport",
                hex_token(rng, 7)
            ),
            "Max-Forwards: 70".into(),
            format!("From: <sip:{user}@{host}>;tag={}", hex_token(rng, 5)),
            format!("To: <sip:{user}@{host}>"),
            format!("Call-ID: {}@{host}", hex_token(rng, 10)),
            format!("CSeq: {} REGISTER", rng.range(1, 9999)),
            format!("Contact: <sip:{user}@{host}:5060>;expires=3600"),
            format!(
                "User-Agent: {}",
                if opts.mimic_all {
                    "Linphone/5.2.5"
                } else {
                    "PJSUA v2.13"
                }
            ),
        ]
    };

    let prefix = headers.join("\r\n") + "\r\n";
    // Room for the Content-Length line and the blank line that ends the
    // headers comes off before deciding how much body fits.
    let room = opts.mtu.saturating_sub(
        prefix.len() as u32 + tag_bytes + "Content-Length: 9999\r\n\r\n".len() as u32,
    );
    let padding = if opts.tag_r {
        (rng.range(5, 30) * iv).min(120).min(room)
    } else {
        0
    };
    // Content-Length counts the body: the padding plus what the tags emit.
    let length_header = if opts.compact { "l" } else { "Content-Length" };
    let message = format!("{prefix}{length_header}: {}\r\n\r\n", padding + tag_bytes);

    let mut c = Chain::new();
    c.push(Tag::Bytes(message.into_bytes()))
        .push_if(opts.tag_rc, Tag::RandomLetters(rc_val))
        .push_if(opts.tag_c, Tag::Counter)
        .push_if(opts.tag_t, Tag::Timestamp);
    if opts.tag_r {
        c.push_padding(padding, PadKind::Bytes);
    }
    c
}

/// `rh(n)` as text: n random bytes in lowercase hex, for branch, tag and
/// Call-ID values.
fn hex_token(rng: &mut impl Rng, bytes: usize) -> String {
    let mut raw = vec![0u8; bytes];
    rng.fill(&mut raw);
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

/// The fixed DNS header: ID, flags, and the four section counts.
const DNS_HEADER: u32 = 12;
/// OPT pseudo-record, RFC 6891: name, type, class, TTL, RDLENGTH.
const DNS_OPT_FIXED: u32 = 1 + 2 + 2 + 4 + 2;
/// The Padding option's own header: code and length. RFC 7830.
const DNS_PAD_OPTION_HEADER: u32 = 4;
/// UDP payload size advertised in the OPT record's CLASS field.
const EDNS_UDP_SIZE: u32 = 1232;

/// A hostname as DNS labels ending with the root label. A label past 63 bytes
/// cannot be length-prefixed (the top two bits of the length byte mean a
/// compression pointer), and a name past 255 bytes is not a name.
fn dns_name(host: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in host.split('.').filter(|l| !l.is_empty()) {
        let label = &label.as_bytes()[..label.len().min(63)];
        if out.len() + 1 + label.len() + 1 > 255 {
            break;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }
    out.push(0);
    out
}

/// A DNS query, per RFC 1035 §4.1, padded the way DNS actually pads.
///
/// Padding appended after the question makes the message malformed: with
/// QDCOUNT 1 and nothing else counted, a resolver runs past what it was told to
/// expect. DNS has a mechanism for exactly this, the Padding option (RFC 7830)
/// in an OPT record, which is what DoT and DoH clients send to hide how long a
/// query is. So the message declares ARCOUNT 1 and every byte the tags put
/// after the blob, the timestamp and counter included, is that option's data.
pub(super) fn dns_query(rng: &mut impl Rng, opts: &MimicOptions, iv: u32) -> Chain {
    // A on even iterations, AAAA on odd: a resolver asks for both in practice.
    let wants_ipv6 = !iv.is_multiple_of(2);
    // The name has to be one that answers the type being asked.
    let qtype = if wants_ipv6 {
        DnsType::Aaaa
    } else {
        DnsType::A
    };
    let host = opts.host(rng, Role::Dns, Some(qtype));
    let question_len = dns_name(&host).len() as u32 + 4;

    // Below about 83 the bounds cross; a tiny MTU gets no padding, not a panic.
    let ceiling = 512.min(opts.mtu.saturating_sub(20));
    let wanted = if ceiling <= 64 {
        ceiling
    } else {
        rng.range(64, ceiling)
    };
    let room = opts
        .mtu
        .saturating_sub(DNS_HEADER + question_len + DNS_OPT_FIXED + DNS_PAD_OPTION_HEADER);
    let tag_bytes = tag_overhead(opts);
    let padding = if opts.tag_r {
        wanted
            .saturating_sub(DNS_HEADER + question_len)
            .min(room.saturating_sub(tag_bytes))
            .min(200)
    } else {
        0
    };
    let option_data = padding + tag_bytes;
    let padded = option_data > 0;

    let mut b = Buf::new();
    b.random(rng, 2) // transaction id
        .lit(&[0x01, 0x00]) // standard query, recursion desired
        .lit(&[0x00, 0x01]) // QDCOUNT
        .lit(&[0x00, 0x00]) // ANCOUNT
        .lit(&[0x00, 0x00]) // NSCOUNT
        .be(u32::from(padded), 2) // ARCOUNT
        .lit(&dns_name(&host))
        .lit(if wants_ipv6 {
            &[0x00, 0x1c]
        } else {
            &[0x00, 0x01]
        })
        .lit(&[0x00, 0x01]); // IN
    if padded {
        b.lit(&[0x00]) // root
            .lit(&[0x00, 0x29]) // OPT
            .be(EDNS_UDP_SIZE, 2)
            .lit(&[0x00, 0x00, 0x00, 0x00]) // extended rcode and flags
            .be(DNS_PAD_OPTION_HEADER + option_data, 2)
            .lit(&[0x00, 0x0c]) // Padding
            .be(option_data, 2);
    }

    let mut c = Chain::new();
    c.push(b.into_tag());
    if padding > 0 {
        c.push_padding(padding, PadKind::Bytes);
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
    fn the_dtls13_client_hello_parses_to_its_last_byte() {
        let combos = [
            all_tags(),
            MimicOptions::default(),
            MimicOptions {
                tag_r: false,
                ..all_tags()
            },
            MimicOptions {
                tag_r: false,
                tag_rc: false,
                tag_t: false,
                ..MimicOptions::default()
            },
        ];
        for opts in combos {
            for seed in 0..100u64 {
                let mut rng = SeededRng::new(seed);
                let pkt = dtls13(&mut rng, &opts, 2).materialize(&mut rng, 1, 2);
                let u16_at = |i: usize| usize::from(u16::from_be_bytes([pkt[i], pkt[i + 1]]));
                // record 13 + handshake 12 + version 2 + random 32
                let mut at = 59;
                assert_eq!(pkt[at], 0, "empty session id");
                assert_eq!(pkt[at + 1], 0, "empty cookie");
                at += 2;
                at += 2 + u16_at(at); // suites
                at += 1 + usize::from(pkt[at]); // compression
                let ext_len = u16_at(at);
                at += 2;
                assert_eq!(ext_len, pkt.len() - at, "seed {seed}: extensions length");
                let mut types = Vec::new();
                while at < pkt.len() {
                    types.push(u16_at(at));
                    at += 4 + u16_at(at + 2);
                }
                assert_eq!(
                    at,
                    pkt.len(),
                    "seed {seed}: extensions end where the packet does"
                );
                assert_eq!(types[0], 0x002b, "supported_versions first");
                for t in &types[1..] {
                    assert_eq!(t & 0x0f0f, 0x0a0a, "only GREASE after it: {t:#06x}");
                }
            }
        }
    }

    /// The text of a SIP chain's `<b>` and the body bytes its tags put after it.
    fn sip_parts(c: &Chain) -> (String, u32) {
        let Tag::Bytes(head) = &c.tags()[0] else {
            panic!("SIP starts with its text")
        };
        let body = c.tags()[1..].iter().map(Tag::wire_len).sum();
        (String::from_utf8(head.clone()).unwrap(), body)
    }

    fn sip_opts(compact: bool) -> MimicOptions {
        MimicOptions {
            custom_host: Some("sip.example.org".into()),
            compact,
            ..all_tags()
        }
    }

    #[test]
    fn a_register_carries_what_rfc_3261_requires() {
        for (compact, via, from, to, call_id, len) in [
            (false, "Via", "From", "To", "Call-ID", "Content-Length"),
            (true, "v", "f", "t", "i", "l"),
        ] {
            for seed in 0..60u64 {
                let mut rng = SeededRng::new(seed);
                let (text, body) = sip_parts(&sip(&mut rng, &sip_opts(compact), 2));
                let lines: Vec<&str> = text.split("\r\n").collect();
                assert_eq!(lines[0], "REGISTER sip:sip.example.org SIP/2.0");
                let has = |prefix: &str| lines.iter().any(|l| l.starts_with(prefix));
                assert!(has(&format!(
                    "{via}: SIP/2.0/UDP sip.example.org:5060;branch=z9hG4bK"
                )));
                assert!(has("Max-Forwards: 70"));
                assert!(has(&format!("{from}: <sip:user")));
                assert!(has(&format!("{to}: <sip:user")));
                assert!(has(&format!("{call_id}: ")));
                assert!(
                    lines
                        .iter()
                        .any(|l| l.starts_with("CSeq: ") && l.ends_with(" REGISTER"))
                );
                assert!(text.ends_with("\r\n\r\n"));
                let declared: u32 = lines
                    .iter()
                    .find_map(|l| l.strip_prefix(&format!("{len}: ")))
                    .unwrap()
                    .parse()
                    .unwrap();
                assert_eq!(declared, body, "compact={compact} seed {seed}: body length");
            }
        }
    }

    #[test]
    fn the_compact_register_is_about_two_thirds_of_the_full_one() {
        for seed in 0..40u64 {
            let full = sip_parts(&sip(&mut SeededRng::new(seed), &sip_opts(false), 2)).0;
            let short = sip_parts(&sip(&mut SeededRng::new(seed), &sip_opts(true), 2)).0;
            assert!(
                short.len() * 10 < full.len() * 8,
                "{} vs {}",
                short.len(),
                full.len()
            );
        }
    }

    #[test]
    fn a_dns_query_accounts_for_every_byte_it_carries() {
        for opts in [
            all_tags(),
            MimicOptions::default(),
            MimicOptions {
                tag_r: false,
                ..all_tags()
            },
            MimicOptions {
                tag_r: false,
                tag_t: false,
                ..MimicOptions::default()
            },
            MimicOptions {
                mtu: 80,
                ..all_tags()
            },
        ] {
            for (seed, iv) in (0..120u64).zip([1u32, 2].into_iter().cycle()) {
                let mut rng = SeededRng::new(seed);
                let pkt = dns_query(&mut rng, &opts, iv).materialize(&mut rng, 1, 2);
                let u16_at = |i: usize| usize::from(u16::from_be_bytes([pkt[i], pkt[i + 1]]));
                assert_eq!(&pkt[2..6], &[0x01, 0x00, 0x00, 0x01], "query, one question");
                assert_eq!(u16_at(6) + u16_at(8), 0, "no answers or authority");
                let arcount = u16_at(10);
                let mut at = 12;
                while pkt[at] != 0 {
                    assert!(pkt[at] <= 63, "label length");
                    at += 1 + usize::from(pkt[at]);
                }
                at += 1;
                let qtype = u16_at(at);
                assert_eq!(qtype, if iv % 2 == 0 { 1 } else { 28 }, "A or AAAA");
                at += 4;
                if arcount == 1 {
                    assert_eq!(pkt[at], 0, "OPT owner is the root");
                    assert_eq!(u16_at(at + 1), 41, "OPT");
                    let rdlength = u16_at(at + 9);
                    at += 11;
                    assert_eq!(u16_at(at), 12, "Padding option");
                    assert_eq!(u16_at(at + 2) + 4, rdlength);
                    at += rdlength;
                } else {
                    assert_eq!(arcount, 0);
                }
                assert_eq!(at, pkt.len(), "seed {seed}: bytes past the message");
            }
        }
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
