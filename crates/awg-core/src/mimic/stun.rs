//! STUN and TURN: what a WebRTC call puts on the wire before any media.
//!
//! A Binding request to a STUN server, a TURN Allocate the server answers with
//! 401, the same Allocate again with credentials, and then ICE connectivity
//! checks between the peers. All of it is STUN framing (RFC 8489) on UDP, often
//! to a port that is not 3478 at all, which makes it a reasonable thing for a
//! tunnel's first packets to be.
//!
//! Ported from Architect 4.4 `generator/profiles/stun.ts`.

use super::MimicOptions;
use super::dsl::{Chain, Tag};
use crate::rng::Rng;

/// The packets of the flow, in the order a client sends them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunVariant {
    Binding,
    Allocate,
    AllocateAuth,
    IceCheck,
}

/// One packet per slot: what "apply to I2-I5" means for this profile.
pub const STUN_FLOW: [StunVariant; 5] = [
    StunVariant::Binding,
    StunVariant::Allocate,
    StunVariant::AllocateAuth,
    StunVariant::IceCheck,
    StunVariant::IceCheck,
];

/// RFC 8489 §5: every STUN message carries it at bytes 4..7.
pub const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

/// Message types, method and class packed together (§5). Both are requests.
const BINDING_REQUEST: u16 = 0x0001;
const ALLOCATE_REQUEST: u16 = 0x0003;

/// Attribute types: RFC 8489 §18.3, RFC 8656 §18, RFC 8445 §16.
mod attr {
    pub const USERNAME: u16 = 0x0006;
    pub const MESSAGE_INTEGRITY: u16 = 0x0008;
    pub const REALM: u16 = 0x0014;
    pub const NONCE: u16 = 0x0015;
    pub const REQUESTED_TRANSPORT: u16 = 0x0019;
    pub const PRIORITY: u16 = 0x0024;
    pub const USE_CANDIDATE: u16 = 0x0025;
    pub const FINGERPRINT: u16 = 0x8028;
    pub const ICE_CONTROLLING: u16 = 0x802a;
}

/// XORed into the CRC-32 of a FINGERPRINT (§14.7): "STUN" in ASCII.
const FINGERPRINT_XOR: u32 = 0x5354_554e;

/// Static bytes and send-time tags, counted as they will be on the wire.
///
/// STUN declares its own length in the header, so the count has to include
/// what the tags emit at send time as well as the bytes known now.
#[derive(Default)]
struct Parts(Vec<Tag>);

impl Parts {
    fn wire_len(&self) -> u32 {
        self.0.iter().map(Tag::wire_len).sum()
    }

    /// True when every byte is known now, which a FINGERPRINT needs.
    fn is_static(&self) -> bool {
        self.0.iter().all(|t| matches!(t, Tag::Bytes(_)))
    }

    /// Adjacent static bytes merge into one `<b>`.
    fn bytes(mut self, b: &[u8]) -> Self {
        if b.is_empty() {
            return self;
        }
        if let Some(Tag::Bytes(last)) = self.0.last_mut() {
            last.extend_from_slice(b);
        } else {
            self.0.push(Tag::Bytes(b.to_vec()));
        }
        self
    }

    fn tag(mut self, t: Tag) -> Self {
        self.0.push(t);
        self
    }

    fn append(mut self, other: Parts) -> Self {
        for t in other.0 {
            self = match t {
                Tag::Bytes(b) => self.bytes(&b),
                t => self.tag(t),
            };
        }
        self
    }

    fn static_bytes(&self) -> Vec<u8> {
        self.0
            .iter()
            .flat_map(|t| match t {
                Tag::Bytes(b) => b.clone(),
                _ => Vec::new(),
            })
            .collect()
    }

    fn into_chain(self) -> Chain {
        let mut c = Chain::new();
        for t in self.0 {
            c.push(t);
        }
        c
    }
}

/// One attribute: type, length, value, then zero padding to a 4-byte boundary
/// (§14). The length counts the value without the padding.
fn attribute(ty: u16, value: Parts) -> Parts {
    let len = value.wire_len();
    let pad = (4 - len % 4) % 4;
    Parts::default()
        .bytes(&ty.to_be_bytes())
        .bytes(&(len as u16).to_be_bytes())
        .append(value)
        .bytes(&vec![0; pad as usize])
}

/// `n` random bytes: `<r>` when the reader may use it, fixed bytes when not.
fn random(rng: &mut impl Rng, opts: &MimicOptions, n: u32) -> Parts {
    if opts.tag_r {
        Parts::default().tag(Tag::Random(n))
    } else {
        let mut b = vec![0u8; n as usize];
        rng.fill(&mut b);
        Parts::default().bytes(&b)
    }
}

/// `n` random letters, the same way.
fn random_letters(rng: &mut impl Rng, opts: &MimicOptions, n: u32) -> Parts {
    const ABC: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if opts.tag_rc {
        Parts::default().tag(Tag::RandomLetters(n))
    } else {
        let text: Vec<u8> = (0..n)
            .map(|_| ABC[rng.range(0, ABC.len() as u32 - 1) as usize])
            .collect();
        Parts::default().bytes(&text)
    }
}

/// CRC-32 (ISO 3309, the one §14.7 names).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                0xedb8_8320 ^ (crc >> 1)
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Header, attributes, and a FINGERPRINT when one can be told the truth.
///
/// The header length counts the attributes, FINGERPRINT included. A
/// FINGERPRINT is the CRC of every byte before it, and a byte a tag only
/// produces at send time cannot be in a CRC computed now. A wrong FINGERPRINT
/// is a worse tell than none (anything that checks it rejects the message,
/// while plenty of real clients leave it out), so it goes in only when the
/// whole message is static, which is what switching the random tags off buys.
fn message(rng: &mut impl Rng, opts: &MimicOptions, ty: u16, attrs: Parts) -> Chain {
    // 96 random bits a real client draws per request; `<r 12>` draws them per
    // send, which is the same thing.
    let tid = random(rng, opts, 12);
    let fingerprint = attrs.is_static() && tid.is_static();
    let length = attrs.wire_len() + if fingerprint { 8 } else { 0 };

    let msg = Parts::default()
        .bytes(&ty.to_be_bytes())
        .bytes(&(length as u16).to_be_bytes())
        .bytes(&MAGIC_COOKIE)
        .append(tid)
        .append(attrs);
    let msg = if fingerprint {
        let crc = crc32(&msg.static_bytes()) ^ FINGERPRINT_XOR;
        let value = Parts::default().bytes(&crc.to_be_bytes());
        msg.append(attribute(attr::FINGERPRINT, value))
    } else {
        msg
    };
    msg.into_chain()
}

/// REQUESTED-TRANSPORT: UDP, protocol 17, then three reserved bytes.
fn udp_transport() -> Parts {
    attribute(
        attr::REQUESTED_TRANSPORT,
        Parts::default().bytes(&[0x11, 0, 0, 0]),
    )
}

/// A Unix time a day or so ahead, for the TURN REST username.
fn expiry(rng: &mut impl Rng) -> u64 {
    // A browser's `Date.now()` is not available on every target this crate
    // builds for; the floor is a recent date, so the name stays plausible.
    #[cfg(not(target_arch = "wasm32"))]
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    #[cfg(target_arch = "wasm32")]
    let now = 0u64;
    now.max(1_790_000_000) + u64::from(rng.range(3_600, 86_400))
}

/// One STUN packet of the flow.
pub(super) fn build(
    rng: &mut impl Rng,
    opts: &MimicOptions,
    host: &str,
    variant: StunVariant,
) -> Chain {
    match variant {
        // While gathering server-reflexive candidates: the header and nothing
        // else. Twenty bytes.
        StunVariant::Binding => message(rng, opts, BINDING_REQUEST, Parts::default()),
        // The first TURN Allocate (RFC 8656 §7.1): only the transport it wants.
        StunVariant::Allocate => message(rng, opts, ALLOCATE_REQUEST, udp_transport()),
        // The Allocate retried with long-term credentials (RFC 8489 §9.2). The
        // username has the TURN REST API shape coturn and hosted relays use,
        // `<expiry>:<user>`; the realm is the host, as relays set it. Nonce and
        // HMAC are opaque, so random bytes are exactly right.
        StunVariant::AllocateAuth => {
            let user = if opts.tag_rd {
                Parts::default().tag(Tag::RandomDigits(10))
            } else {
                Parts::default().bytes(expiry(rng).to_string().as_bytes())
            }
            .bytes(b":")
            .append(random_letters(rng, opts, 8));
            let attrs = udp_transport()
                .append(attribute(attr::USERNAME, user))
                .append(attribute(
                    attr::REALM,
                    Parts::default().bytes(host.as_bytes()),
                ))
                .append(attribute(attr::NONCE, random_letters(rng, opts, 16)))
                .append(attribute(attr::MESSAGE_INTEGRITY, random(rng, opts, 20)));
            message(rng, opts, ALLOCATE_REQUEST, attrs)
        }
        // An ICE connectivity check (RFC 8445 §7.1.1) in libwebrtc's attribute
        // order. USERNAME is `remote:local`; Chromium draws four characters for
        // each ufrag, Firefox eight. PRIORITY is a peer-reflexive candidate's
        // (§5.1.2.1): type preference 110, a local preference, and 256 minus
        // component 1. The controlling side nominates with USE-CANDIDATE.
        StunVariant::IceCheck => {
            let chromium = opts.browser.is_none_or(|b| b.is_chromium());
            let ufrag = if chromium { 4 } else { 8 };
            let username = random_letters(rng, opts, ufrag)
                .bytes(b":")
                .append(random_letters(rng, opts, ufrag));
            let local_preference = rng.range(0x1e00, 0xffff);
            let priority = (110u32 << 24) | (local_preference << 8) | 255;

            let mut attrs = attribute(attr::USERNAME, username)
                .append(attribute(attr::ICE_CONTROLLING, random(rng, opts, 8)));
            if rng.range(0, 1) == 1 {
                attrs = attrs.append(attribute(attr::USE_CANDIDATE, Parts::default()));
            }
            let attrs = attrs
                .append(attribute(
                    attr::PRIORITY,
                    Parts::default().bytes(&priority.to_be_bytes()),
                ))
                .append(attribute(attr::MESSAGE_INTEGRITY, random(rng, opts, 20)));
            message(rng, opts, BINDING_REQUEST, attrs)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::SeededRng;

    fn quiet() -> MimicOptions {
        MimicOptions {
            tag_r: false,
            tag_rc: false,
            tag_rd: false,
            ..Default::default()
        }
    }

    /// Walk a STUN message: (type, attribute types in order).
    fn walk(pkt: &[u8]) -> (u16, Vec<u16>) {
        let ty = u16::from_be_bytes([pkt[0], pkt[1]]);
        let length = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
        assert_eq!(&pkt[4..8], &MAGIC_COOKIE);
        assert_eq!(length, pkt.len() - 20, "header length is the attributes");
        assert_eq!(length % 4, 0, "attributes are 4-aligned");
        let mut at = 20;
        let mut types = Vec::new();
        while at < pkt.len() {
            let t = u16::from_be_bytes([pkt[at], pkt[at + 1]]);
            let len = usize::from(u16::from_be_bytes([pkt[at + 2], pkt[at + 3]]));
            types.push(t);
            at += 4 + len.div_ceil(4) * 4;
        }
        assert_eq!(at, pkt.len(), "attributes end where the message does");
        (ty, types)
    }

    #[test]
    fn the_crc_is_iso_3309() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn every_variant_frames_as_stun() {
        for opts in [MimicOptions::default(), quiet()] {
            for v in STUN_FLOW {
                for seed in 0..80u64 {
                    let mut rng = SeededRng::new(seed);
                    let pkt =
                        build(&mut rng, &opts, "stun.example.org", v).materialize(&mut rng, 1, 2);
                    let (ty, attrs) = walk(&pkt);
                    match v {
                        StunVariant::Binding => {
                            assert!(attrs.iter().all(|a| *a == attr::FINGERPRINT))
                        }
                        StunVariant::Allocate | StunVariant::AllocateAuth => {
                            assert_eq!(ty, ALLOCATE_REQUEST);
                            assert_eq!(attrs[0], attr::REQUESTED_TRANSPORT);
                        }
                        StunVariant::IceCheck => {
                            assert_eq!(ty, BINDING_REQUEST);
                            assert_eq!(attrs[0], attr::USERNAME);
                            assert!(attrs.contains(&attr::PRIORITY));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn a_fingerprint_appears_only_when_it_can_be_true_and_then_it_is() {
        for v in STUN_FLOW {
            let mut rng = SeededRng::new(4);
            let pkt = build(&mut rng, &quiet(), "turn.example.org", v).materialize(&mut rng, 0, 0);
            let (_, attrs) = walk(&pkt);
            assert_eq!(attrs.last(), Some(&attr::FINGERPRINT), "{v:?}");
            let body = &pkt[..pkt.len() - 8];
            let declared = u32::from_be_bytes(pkt[pkt.len() - 4..].try_into().unwrap());
            assert_eq!(declared, crc32(body) ^ FINGERPRINT_XOR, "{v:?}");

            let mut rng = SeededRng::new(4);
            let pkt = build(&mut rng, &MimicOptions::default(), "turn.example.org", v)
                .materialize(&mut rng, 0, 0);
            assert!(
                !walk(&pkt).1.contains(&attr::FINGERPRINT),
                "{v:?} with send-time bytes"
            );
        }
    }

    #[test]
    fn the_authenticated_allocate_names_its_realm() {
        let mut rng = SeededRng::new(9);
        let pkt = build(
            &mut rng,
            &quiet(),
            "turn.example.org",
            StunVariant::AllocateAuth,
        )
        .materialize(&mut rng, 0, 0);
        assert!(pkt.windows(16).any(|w| w == b"turn.example.org"));
    }
}
