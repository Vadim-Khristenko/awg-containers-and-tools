//! Where to send money, if it helped.
//!
//! The same set the Any Tech ARCHITECT site shows, kept here so the tool does
//! not send people to a web page to find out how to support the thing they are
//! already running.
//!
//! **These constants are transcribed, never composed.** A wrong character in a
//! crypto address does not bounce — it sends someone's money to nobody, or to a
//! stranger, and there is no undoing it. So nothing here is built from parts at
//! runtime, and the tests below check what can be checked mechanically: the
//! Bitcoin address by its bech32 checksum, which is exactly the property that
//! catches a single-character slip that a length check would wave through.
//!
//! If these change in Architect, copy them across whole. Do not retype them.

/// One coin, and the address to send it to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoWallet {
    pub id: &'static str,
    pub name: &'static str,
    pub ticker: &'static str,
    /// Spelled out, because sending on the wrong network is unrecoverable.
    pub network_en: &'static str,
    pub network_ru: &'static str,
    pub address: &'static str,
}

pub const CRYPTO_WALLETS: [CryptoWallet; 6] = [
    CryptoWallet {
        id: "btc",
        name: "Bitcoin",
        ticker: "BTC",
        network_en: "Bitcoin · Native SegWit",
        network_ru: "Bitcoin · Native SegWit",
        address: "bc1qwvfpdhjuzelw8s9vxcfjj6fatnq3cltf0d48jy",
    },
    CryptoWallet {
        id: "eth",
        name: "Ethereum",
        ticker: "ETH",
        network_en: "Ethereum · ERC-20",
        network_ru: "Ethereum · ERC-20",
        address: "0x277195Ff068756F09683FAB523b2cdDf8Ef35B44",
    },
    CryptoWallet {
        id: "ton",
        name: "Toncoin",
        ticker: "TON",
        network_en: "The Open Network",
        network_ru: "The Open Network",
        address: "UQBVdcwKqy8lx_2plsf2YPbcBJdYbPtnKbddmFWZntqiAEME",
    },
    CryptoWallet {
        id: "usdt-ton",
        name: "Tether USD",
        ticker: "USDT",
        network_en: "JETTON · TON",
        network_ru: "JETTON · TON",
        address: "UQCaNScHxNbJsCi5Wc47rJqNpJPiDASUlMJ1nRwxq-hXSGoQ",
    },
    CryptoWallet {
        id: "trx",
        name: "Tron",
        ticker: "TRX",
        network_en: "Tron · TRC-20",
        network_ru: "Tron · TRC-20",
        address: "TC8dYqkDYQkuCKe7A6PWXUgDRB8Rr2Xd9f",
    },
    CryptoWallet {
        id: "sol",
        name: "Solana",
        ticker: "SOL",
        network_en: "Solana",
        network_ru: "Solana",
        address: "4i2uWx82jhgVorPQyM2y47X2YvRgCVNNWPfNmVrGcCaE",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FiatMethod {
    pub id: &'static str,
    pub label: &'static str,
    pub note_en: &'static str,
    pub note_ru: &'static str,
    pub url: &'static str,
}

pub const FIAT_METHODS: [FiatMethod; 3] = [
    FiatMethod {
        id: "yoomoney",
        label: "YooMoney",
        note_en: "One-off payment",
        note_ru: "Разовый перевод",
        url: "https://yoomoney.ru/fundraise/1GA2JV51324.260304",
    },
    FiatMethod {
        id: "patreon",
        label: "Patreon",
        note_en: "Recurring support",
        note_ru: "Регулярная поддержка",
        url: "https://patreon.com/VAI_PROG",
    },
    FiatMethod {
        id: "dalink",
        label: "DaLink",
        note_en: "Donation link",
        note_ru: "Донат-ссылка",
        url: "https://dalink.to/vai_prog",
    },
];

pub const PORTFOLIO_URL: &str = "https://vai-rice.space";
pub const ARCHITECT_URL: &str = "https://architect.vai-rice.space";
pub const SOURCES_URL: &str = "https://github.com/Vadim-Khristenko/awg-containers-and-tools";

// ─────────────────────────────────────────────────────────────────── bech32

const BECH32_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ u32::from(*v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// Verify a bech32 or bech32m address, checksum included.
///
/// Worth the thirty lines: this is the check that catches one wrong character.
/// A length-and-charset test accepts a typo happily, and the money is gone.
pub fn bech32_is_valid(addr: &str) -> bool {
    let lower = addr.to_ascii_lowercase();
    // Mixed case is invalid in bech32; comparing both ways catches it.
    if addr != lower && addr != addr.to_ascii_uppercase() {
        return false;
    }
    let Some(sep) = lower.rfind('1') else {
        return false;
    };
    let (hrp, data) = (&lower[..sep], &lower[sep + 1..]);
    if hrp.is_empty() || data.len() < 6 {
        return false;
    }

    let mut values: Vec<u8> = Vec::with_capacity(hrp.len() * 2 + 1 + data.len());
    values.extend(hrp.bytes().map(|c| c >> 5));
    values.push(0);
    values.extend(hrp.bytes().map(|c| c & 31));
    for c in data.bytes() {
        match BECH32_CHARSET.iter().position(|x| *x == c) {
            Some(i) => values.push(i as u8),
            None => return false,
        }
    }
    // 1 is bech32 (segwit v0), 0x2bc830a3 is bech32m (v1+).
    matches!(bech32_polymod(&values), 1 | 0x2bc8_30a3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bitcoin_address_passes_its_own_checksum() {
        let btc = CRYPTO_WALLETS
            .iter()
            .find(|w| w.id == "btc")
            .expect("no bitcoin wallet");
        assert!(
            bech32_is_valid(btc.address),
            "the bitcoin address fails its bech32 checksum: {}",
            btc.address
        );
    }

    #[test]
    fn the_checksum_actually_rejects_a_single_wrong_character() {
        // Without this, the test above would pass against a broken verifier and
        // prove nothing at all.
        let btc = "bc1qwvfpdhjuzelw8s9vxcfjj6fatnq3cltf0d48jy";
        assert!(bech32_is_valid(btc));
        for i in 4..btc.len() {
            let mut broken: Vec<u8> = btc.bytes().collect();
            broken[i] = if broken[i] == b'q' { b'p' } else { b'q' };
            let broken = String::from_utf8(broken).unwrap();
            assert!(
                !bech32_is_valid(&broken),
                "a one-character change went unnoticed at {i}: {broken}"
            );
        }
    }

    #[test]
    fn every_address_has_the_shape_its_network_uses() {
        for w in &CRYPTO_WALLETS {
            assert!(!w.address.is_empty(), "{} has no address", w.id);
            match w.id {
                "btc" => assert!(w.address.starts_with("bc1")),
                // 0x plus twenty bytes.
                "eth" => {
                    assert!(w.address.starts_with("0x"));
                    assert_eq!(w.address.len(), 42);
                    assert!(w.address[2..].chars().all(|c| c.is_ascii_hexdigit()));
                }
                // TON user-friendly form: 48 base64url characters.
                "ton" | "usdt-ton" => {
                    assert_eq!(w.address.len(), 48, "{}", w.id);
                    assert!(w.address.starts_with("UQ") || w.address.starts_with("EQ"));
                }
                "trx" => {
                    assert!(w.address.starts_with('T'));
                    assert_eq!(w.address.len(), 34);
                }
                "sol" => assert!((32..=44).contains(&w.address.len())),
                other => panic!("unknown wallet id {other}: add its shape check"),
            }
            assert!(
                !w.address.contains(char::is_whitespace),
                "{} has whitespace in it, which a copy-paste will carry along",
                w.id
            );
        }
    }

    #[test]
    fn no_two_wallets_share_an_id_or_an_address() {
        for (i, a) in CRYPTO_WALLETS.iter().enumerate() {
            for b in &CRYPTO_WALLETS[i + 1..] {
                assert_ne!(a.id, b.id);
                assert_ne!(a.address, b.address, "duplicated address on {}", a.id);
            }
        }
    }

    #[test]
    fn every_link_is_https() {
        // A donation page reached over http is a donation page someone else can
        // rewrite in transit.
        for m in &FIAT_METHODS {
            assert!(m.url.starts_with("https://"), "{}: {}", m.id, m.url);
        }
        for u in [PORTFOLIO_URL, ARCHITECT_URL, SOURCES_URL] {
            assert!(u.starts_with("https://"), "{u}");
        }
    }

    #[test]
    fn both_languages_are_filled_in_everywhere() {
        for w in &CRYPTO_WALLETS {
            assert!(
                !w.network_en.is_empty() && !w.network_ru.is_empty(),
                "{}",
                w.id
            );
        }
        for m in &FIAT_METHODS {
            assert!(!m.note_en.is_empty() && !m.note_ru.is_empty(), "{}", m.id);
        }
    }
}
