//! The I1–I5 chain DSL — parser, renderer and materialiser.
//!
//! An I-value is a packet template: a flat sequence of tags, no separators and
//! no literal text between them. The tag set, as documented by AmneziaWG
//! Architect's FAQ entry `i1-i5` and as used by every profile generator:
//!
//! | tag        | contributes                                    |
//! |------------|------------------------------------------------|
//! | `<b 0x…>`  | the literal bytes spelled out in hex           |
//! | `<t>`      | a 32-bit timestamp in network byte order       |
//! | `<c>`      | a 32-bit packet counter                        |
//! | `<r N>`    | N cryptographically random bytes               |
//! | `<rc N>`   | N random Latin letters                         |
//! | `<rd N>`   | N random decimal digits                        |
//!
//! Not every daemon generation parses all of them, and the sets are not nested —
//! see [`crate::versions::AwgVersion::chain_tags`]. This module parses the union
//! so that a chain from any generation can be read back and inspected; deciding
//! what may be *emitted* is the version's job.
//!
//! `<rc>` and `<rd>` are *not* interchangeable with `<r>`: they exist so a chain
//! can put something in the shape of an SNI hostname or a SIP branch parameter
//! where a real protocol would, and a DPI box that reads those fields as text
//! sees text.
//!
//! [`Chain::parse`] refuses `<d>`, `<ds>` and `<dz>`. amneziawg-go v3.0.1 parses
//! them, but its send path only ever runs the chains with an empty payload, so
//! the tags that transform packet data receive nothing — they are groundwork for
//! AmneziaWG 4.0. Accepting them here would mean handing out a config whose
//! first packet is shorter than it looks.

use crate::rng::Rng;
use crate::{Error, Result};

/// Largest count a single `<r>` / `<rc>` / `<rd>` tag may carry.
///
/// Anything longer has to be split across several tags — see
/// [`Chain::push_padding`], which is what every profile uses.
pub const MAX_TAG_COUNT: u32 = 1000;

/// `<c>` and `<t>` are both 32-bit fields, so each one costs four bytes on the
/// wire regardless of what it expands to.
pub const COUNTER_BYTES: u32 = 4;
pub const TIMESTAMP_BYTES: u32 = 4;

/// Which flavour of filler a padding run is made of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PadKind {
    /// `<r>` — arbitrary bytes.
    Bytes,
    /// `<rc>` — Latin letters.
    Letters,
    /// `<rd>` — decimal digits.
    Digits,
}

/// A tag stripped of its payload — i.e. the word the daemon's parser looks up.
///
/// The vocabularies differ per AmneziaWG generation (see
/// [`crate::versions::AwgVersion::chain_tags`]), and a vocabulary is a set of
/// names, not of sizes. Keeping the name separate from the payload means the
/// version gate can be a plain set-membership test instead of a `match` that has
/// to invent a count for every arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagKind {
    Bytes,
    Random,
    RandomLetters,
    RandomDigits,
    Counter,
    Timestamp,
}

impl TagKind {
    /// The tag as it is spelled in a chain, for messages.
    pub fn as_str(&self) -> &'static str {
        match self {
            TagKind::Bytes => "<b 0x…>",
            TagKind::Random => "<r N>",
            TagKind::RandomLetters => "<rc N>",
            TagKind::RandomDigits => "<rd N>",
            TagKind::Counter => "<c>",
            TagKind::Timestamp => "<t>",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tag {
    /// `<b 0x…>` — literal bytes.
    Bytes(Vec<u8>),
    /// `<r N>` — N random bytes.
    Random(u32),
    /// `<rc N>` — N random Latin letters.
    RandomLetters(u32),
    /// `<rd N>` — N random decimal digits.
    RandomDigits(u32),
    /// `<c>` — 32-bit packet counter.
    Counter,
    /// `<t>` — 32-bit timestamp, network byte order.
    Timestamp,
}

impl Tag {
    pub fn kind(&self) -> TagKind {
        match self {
            Tag::Bytes(_) => TagKind::Bytes,
            Tag::Random(_) => TagKind::Random,
            Tag::RandomLetters(_) => TagKind::RandomLetters,
            Tag::RandomDigits(_) => TagKind::RandomDigits,
            Tag::Counter => TagKind::Counter,
            Tag::Timestamp => TagKind::Timestamp,
        }
    }

    /// How many bytes this tag puts on the wire.
    pub fn wire_len(&self) -> u32 {
        match self {
            Tag::Bytes(b) => b.len() as u32,
            Tag::Random(n) | Tag::RandomLetters(n) | Tag::RandomDigits(n) => *n,
            Tag::Counter => COUNTER_BYTES,
            Tag::Timestamp => TIMESTAMP_BYTES,
        }
    }

    fn render_into(&self, out: &mut String) {
        use std::fmt::Write as _;
        match self {
            Tag::Bytes(b) => {
                out.push_str("<b 0x");
                for byte in b {
                    // `write!` to a String cannot fail; the result is discarded
                    // deliberately rather than unwrapped.
                    let _ = write!(out, "{byte:02x}");
                }
                out.push('>');
            }
            Tag::Random(n) => {
                let _ = write!(out, "<r {n}>");
            }
            Tag::RandomLetters(n) => {
                let _ = write!(out, "<rc {n}>");
            }
            Tag::RandomDigits(n) => {
                let _ = write!(out, "<rd {n}>");
            }
            Tag::Counter => out.push_str("<c>"),
            Tag::Timestamp => out.push_str("<t>"),
        }
    }

    /// The bytes a client would actually send for this tag.
    ///
    /// Only the size of this is checked against the MTU, but producing the real
    /// content is what keeps the `<rc>`/`<rd>` distinction honest: a test can
    /// assert the letters really are letters instead of trusting the name.
    pub fn materialize(&self, rng: &mut impl Rng, counter: u32, timestamp: u32, out: &mut Vec<u8>) {
        const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        match self {
            Tag::Bytes(b) => out.extend_from_slice(b),
            Tag::Random(n) => {
                let at = out.len();
                out.resize(at + *n as usize, 0);
                rng.fill(&mut out[at..]);
            }
            Tag::RandomLetters(n) => {
                for _ in 0..*n {
                    out.push(LETTERS[rng.range(0, LETTERS.len() as u32 - 1) as usize]);
                }
            }
            Tag::RandomDigits(n) => {
                for _ in 0..*n {
                    out.push(b'0' + rng.range(0, 9) as u8);
                }
            }
            Tag::Counter => out.extend_from_slice(&counter.to_be_bytes()),
            Tag::Timestamp => out.extend_from_slice(&timestamp.to_be_bytes()),
        }
    }
}

/// One I-value: an ordered list of tags.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Chain(Vec<Tag>);

impl Chain {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn tags(&self) -> &[Tag] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn push(&mut self, tag: Tag) -> &mut Self {
        self.0.push(tag);
        self
    }

    /// Append `tag` only when `enabled`, so the profiles read as the TS ones do.
    pub fn push_if(&mut self, enabled: bool, tag: Tag) -> &mut Self {
        if enabled {
            self.0.push(tag);
        }
        self
    }

    /// Append `n` bytes of filler, split across as many tags as the per-tag
    /// limit requires. `n == 0` appends nothing.
    pub fn push_padding(&mut self, mut n: u32, kind: PadKind) -> &mut Self {
        let make = |count| match kind {
            PadKind::Bytes => Tag::Random(count),
            PadKind::Letters => Tag::RandomLetters(count),
            PadKind::Digits => Tag::RandomDigits(count),
        };
        if n == 0 {
            return self;
        }
        while n > MAX_TAG_COUNT {
            self.0.push(make(MAX_TAG_COUNT));
            n -= MAX_TAG_COUNT;
        }
        self.0.push(make(n));
        self
    }

    /// Total bytes on the wire.
    pub fn wire_len(&self) -> u32 {
        self.0.iter().map(Tag::wire_len).sum()
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        for tag in &self.0 {
            tag.render_into(&mut out);
        }
        out
    }

    /// One packet's worth of bytes, as a client would emit it.
    pub fn materialize(&self, rng: &mut impl Rng, counter: u32, timestamp: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.wire_len() as usize);
        for tag in &self.0 {
            tag.materialize(rng, counter, timestamp, &mut out);
        }
        out
    }

    /// Parse a chain. An empty string is an empty chain — that is how an unused
    /// I-slot is spelled in a `.conf`.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let mut out = Vec::new();
        let bytes = s.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i].is_ascii_whitespace() {
                // Whitespace *between* tags is not something any generator
                // emits, and tolerating it would let two different strings
                // render identically.
                return Err(chain_err(format!(
                    "unexpected whitespace between tags at offset {i}"
                )));
            }
            if bytes[i] != b'<' {
                return Err(chain_err(format!(
                    "expected a tag at offset {i}, found {:?} — chains carry no literal text",
                    s[i..].chars().next().unwrap_or('?')
                )));
            }
            let Some(rel) = s[i..].find('>') else {
                return Err(chain_err(format!(
                    "unterminated tag starting at offset {i}"
                )));
            };
            let body = &s[i + 1..i + rel];
            if body.contains('<') {
                return Err(chain_err(format!(
                    "nested `<` inside the tag at offset {i}"
                )));
            }
            out.push(parse_tag(body)?);
            i += rel + 1;
        }
        Ok(Self(out))
    }
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.render())
    }
}

impl std::str::FromStr for Chain {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

fn chain_err(msg: impl Into<String>) -> Error {
    Error::Chain(msg.into())
}

fn parse_tag(body: &str) -> Result<Tag> {
    let body = body.trim();
    if body.is_empty() {
        return Err(chain_err("empty tag `<>`"));
    }
    let (name, arg) = match body.find(char::is_whitespace) {
        Some(i) => (&body[..i], body[i..].trim()),
        None => (body, ""),
    };

    let count = |arg: &str| -> Result<u32> {
        if arg.is_empty() {
            return Err(chain_err(format!("`<{name}>` needs a byte count")));
        }
        let n: u32 = arg
            .parse()
            .map_err(|_| chain_err(format!("`<{name} {arg}>` — {arg:?} is not a byte count")))?;
        if n > MAX_TAG_COUNT {
            return Err(chain_err(format!(
                "`<{name} {n}>` exceeds the {MAX_TAG_COUNT}-byte limit for one tag; split it"
            )));
        }
        Ok(n)
    };

    let no_arg = |tag: Tag| -> Result<Tag> {
        if arg.is_empty() {
            Ok(tag)
        } else {
            Err(chain_err(format!(
                "`<{name}>` takes no argument, got {arg:?}"
            )))
        }
    };

    match name {
        "b" => {
            let hex = arg
                .strip_prefix("0x")
                .or_else(|| arg.strip_prefix("0X"))
                .ok_or_else(|| chain_err("`<b …>` needs its bytes prefixed with `0x`"))?;
            if hex.is_empty() {
                return Err(chain_err("`<b 0x>` carries no bytes"));
            }
            if !hex.len().is_multiple_of(2) {
                // A half byte cannot reach the wire; upstream pads it and warns,
                // which turns a typo into a packet nobody meant to send.
                return Err(chain_err(format!(
                    "`<b 0x{hex}>` has an odd number of hex digits ({})",
                    hex.len()
                )));
            }
            let mut bytes = Vec::with_capacity(hex.len() / 2);
            for pair in hex.as_bytes().chunks(2) {
                let s = std::str::from_utf8(pair).map_err(|_| chain_err("`<b …>` is not hex"))?;
                bytes.push(
                    u8::from_str_radix(s, 16)
                        .map_err(|_| chain_err(format!("`<b …>` contains non-hex {s:?}")))?,
                );
            }
            Ok(Tag::Bytes(bytes))
        }
        "r" => Ok(Tag::Random(count(arg)?)),
        "rc" => Ok(Tag::RandomLetters(count(arg)?)),
        "rd" => Ok(Tag::RandomDigits(count(arg)?)),
        "c" => no_arg(Tag::Counter),
        "t" => no_arg(Tag::Timestamp),
        "d" | "ds" | "dz" => Err(chain_err(format!(
            "`<{name}>` parses in amneziawg-go v3.0.1 but is never reached: the send path runs \
             the I-chains with an empty payload, so the data-transforming tags get nothing. \
             It is groundwork for AmneziaWG 4.0, not a usable tag today"
        ))),
        other => Err(chain_err(format!("unknown tag `<{other}>`"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::SeededRng;

    const CANONICAL: &[&str] = &[
        "",
        "<c>",
        "<t>",
        "<r 1000>",
        "<rc 24>",
        "<rd 8>",
        "<b 0xc000000001>",
        "<b 0xc000000001><rc 18><c><t><r 1000><r 233>",
        "<rd 4><b 0xdeadbeef><rc 12><r 40><t><c>",
        "<b 0x00><b 0xff><b 0x0102030405060708090a0b0c0d0e0f>",
    ];

    #[test]
    fn every_tag_type_survives_a_render_parse_render_round_trip() {
        for s in CANONICAL {
            let parsed = Chain::parse(s).unwrap_or_else(|e| panic!("{s:?} should parse: {e}"));
            assert_eq!(&parsed.render(), s, "round trip changed {s:?}");
            // ...and parsing the rendering again must land on the same value,
            // which a renderer that silently normalised would fail.
            assert_eq!(Chain::parse(&parsed.render()).unwrap(), parsed);
        }
    }

    #[test]
    fn parsing_recovers_the_tag_values_not_just_the_text() {
        let c = Chain::parse("<b 0xdead><r 5><rc 6><rd 7><c><t>").unwrap();
        assert_eq!(
            c.tags(),
            &[
                Tag::Bytes(vec![0xde, 0xad]),
                Tag::Random(5),
                Tag::RandomLetters(6),
                Tag::RandomDigits(7),
                Tag::Counter,
                Tag::Timestamp,
            ]
        );
        // 2 + 5 + 6 + 7 + 4 + 4
        assert_eq!(c.wire_len(), 28);
    }

    #[test]
    fn uppercase_hex_and_inner_spacing_are_accepted_and_normalised() {
        let c = Chain::parse("<b 0XDEADBEEF><r   12>").unwrap();
        assert_eq!(c.render(), "<b 0xdeadbeef><r 12>");
    }

    #[test]
    fn malformed_chains_are_rejected_with_the_reason() {
        for (input, expect) in [
            ("<>", "empty tag"),
            ("<q 5>", "unknown tag"),
            ("<b deadbeef>", "prefixed with `0x`"),
            ("<b 0xdea>", "odd number of hex digits"),
            ("<b 0x>", "carries no bytes"),
            ("<b 0xzz>", "non-hex"),
            ("<r>", "needs a byte count"),
            ("<r abc>", "is not a byte count"),
            ("<r 1001>", "exceeds the 1000-byte limit"),
            ("<c 4>", "takes no argument"),
            ("<t 1>", "takes no argument"),
            ("<b 0xff", "unterminated tag"),
            ("junk<c>", "expected a tag"),
            ("<c>trailing", "expected a tag"),
            ("<c> <t>", "unexpected whitespace"),
            ("<<c>>", "nested `<`"),
        ] {
            let err = Chain::parse(input).expect_err(&format!("{input:?} must be refused"));
            let msg = err.to_string();
            assert!(
                msg.contains(expect),
                "{input:?} gave {msg:?}, wanted {expect:?}"
            );
        }
    }

    #[test]
    fn the_awg4_groundwork_tags_are_refused_by_name() {
        // They parse in v3.0.1 and do nothing. Emitting or accepting one would
        // produce a config that looks correct and sends a shorter packet.
        for t in ["<d>", "<ds 4>", "<dz 8>"] {
            let msg = Chain::parse(t).unwrap_err().to_string();
            assert!(msg.contains("AmneziaWG 4.0"), "{t} gave {msg}");
        }
    }

    #[test]
    fn padding_is_split_at_the_per_tag_limit() {
        let mut c = Chain::new();
        c.push_padding(2500, PadKind::Bytes);
        assert_eq!(c.render(), "<r 1000><r 1000><r 500>");
        assert_eq!(c.wire_len(), 2500);

        // Exactly at the limit stays a single tag, and the split never emits a
        // zero-length one.
        let mut c = Chain::new();
        c.push_padding(1000, PadKind::Letters);
        assert_eq!(c.render(), "<rc 1000>");
        let mut c = Chain::new();
        c.push_padding(1001, PadKind::Digits);
        assert_eq!(c.render(), "<rd 1000><rd 1>");
        let mut c = Chain::new();
        c.push_padding(0, PadKind::Bytes);
        assert!(c.is_empty());
    }

    #[test]
    fn materialising_honours_what_each_tag_promises() {
        let mut rng = SeededRng::new(9);
        let c = Chain::parse("<b 0xcafe><rc 20><rd 20><c><t><r 16>").unwrap();
        let bytes = c.materialize(&mut rng, 0x01020304, 0x6543_2100);
        assert_eq!(bytes.len(), c.wire_len() as usize);
        assert_eq!(&bytes[0..2], &[0xca, 0xfe]);
        assert!(
            bytes[2..22].iter().all(|b| b.is_ascii_alphabetic()),
            "<rc> must be letters"
        );
        assert!(
            bytes[22..42].iter().all(|b| b.is_ascii_digit()),
            "<rd> must be digits"
        );
        assert_eq!(
            &bytes[42..46],
            &[0x01, 0x02, 0x03, 0x04],
            "<c> is big-endian"
        );
        assert_eq!(
            &bytes[46..50],
            &[0x65, 0x43, 0x21, 0x00],
            "<t> is big-endian"
        );
    }

    #[test]
    fn an_empty_i_slot_is_a_valid_empty_chain() {
        assert!(Chain::parse("").unwrap().is_empty());
        assert!(Chain::parse("   ").unwrap().is_empty());
        assert_eq!(Chain::new().render(), "");
        assert_eq!(Chain::new().wire_len(), 0);
    }
}
