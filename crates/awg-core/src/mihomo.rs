//! The same parameters as a mihomo (Clash.Meta) proxy entry.
//!
//! mihomo speaks YAML, nests the obfuscation under `amnezia-wg-option` and
//! names fields its own way. Read off MetaCubeX/mihomo
//! `adapter/outbound/wireguard.go` (Alpha):
//!
//! * H1-H4 and every 3.x timer are strings there, so ranges pass through as
//!   `"lo-hi"`.
//! * `version: 3` selects the v3 implementation; any other value runs the
//!   legacy one, and the 3.x options (the header key, the padding, the timers
//!   and the 3.1 switches) are honoured only under it. So 3.0 and 3.1 both
//!   carry it. Ported from Architect `mihomoFormat.ts`, which wrote it for
//!   3.0 alone.
//! * `ip` is required; `allowed-ips` is not, mihomo derives 0.0.0.0/0 and ::/0.
//!
//! Without a peer's own values the entry carries `YOUR_*` placeholders rather
//! than commented-out fields: a field that is there but obviously fake gets
//! filled, a commented one gets forgotten.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

use crate::check::ConfFile;
use crate::versions::VersionedParams;

/// What a generator cannot know: the peer's own addressing and keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MihomoPeer {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub ip: String,
    pub private_key: String,
    pub public_key: String,
    pub pre_shared_key: Option<String>,
}

impl MihomoPeer {
    /// The placeholders a bare parameter set is rendered with.
    pub fn placeholders() -> Self {
        Self {
            name: "AmneziaWG".into(),
            server: "YOUR_ENDPOINT_HOST".into(),
            port: 51820,
            ip: "YOUR_TUNNEL_IPV4".into(),
            private_key: "YOUR_PRIVATE_KEY".into(),
            public_key: "YOUR_SERVER_PUBLIC_KEY".into(),
            pre_shared_key: None,
        }
    }

    /// A client `.conf`'s own values, where it has them.
    pub fn from_conf(conf: &ConfFile, name: &str) -> Self {
        let mut p = Self::placeholders();
        p.name = name.to_string();
        if let Some(v) = conf.get("PrivateKey") {
            p.private_key = v.to_string();
        }
        if let Some(addr) = conf.get("Address") {
            // The IPv4 one, without its prefix.
            if let Some(v4) = addr.split(',').map(str::trim).find(|a| a.contains('.')) {
                p.ip = v4.split('/').next().unwrap_or(v4).to_string();
            }
        }
        if let Some(peer) = conf.peers().next() {
            let get = |k: &str| {
                peer.entries
                    .iter()
                    .find(|(key, _)| key == k)
                    .map(|(_, v)| v.clone())
            };
            if let Some(v) = get("PublicKey") {
                p.public_key = v;
            }
            p.pre_shared_key = get("PresharedKey");
            if let Some(ep) = get("Endpoint")
                && let Some((host, port)) = ep.rsplit_once(':')
            {
                p.server = host.trim_matches(['[', ']']).to_string();
                p.port = port.parse().unwrap_or(p.port);
            }
        }
        p
    }
}

/// Double-quoted YAML scalar: safe for ranges, `<b …>` tags and keys.
fn q(v: &str) -> String {
    format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Render a parameter set as a mihomo proxy block.
pub fn render(params: &VersionedParams, peer: &MihomoPeer) -> String {
    let v = params.version;
    let mut out = vec![format!("# AmneziaWG {v} for mihomo (Clash.Meta)")];
    if peer.private_key.starts_with("YOUR_") {
        out.push("# Replace every YOUR_* value with your own key material.".into());
    }
    if v.supports_awg3() {
        out.push("# AWG 3.x needs a recent mihomo build (Alpha or a nightly).".into());
    }
    out.push("proxies:".into());
    out.push(format!("  - name: {}", q(&peer.name)));
    out.push("    type: wireguard".into());
    out.push(format!("    server: {}", peer.server));
    out.push(format!("    port: {}", peer.port));
    out.push(format!("    ip: {}", peer.ip));
    out.push(format!("    private-key: {}", q(&peer.private_key)));
    out.push(format!("    public-key: {}", q(&peer.public_key)));
    if let Some(psk) = &peer.pre_shared_key {
        out.push(format!("    pre-shared-key: {}", q(psk)));
    }
    out.push("    udp: true".into());
    out.push("    amnezia-wg-option:".into());
    if v.supports_awg3() {
        out.push("      version: 3".into());
    }

    let b = &params.base;
    out.push(format!("      jc: {}", b.jc));
    out.push(format!("      jmin: {}", b.jmin));
    out.push(format!("      jmax: {}", b.jmax));
    out.push(format!("      s1: {}", b.s[0]));
    out.push(format!("      s2: {}", b.s[1]));
    if v.supports_s3_s4() {
        out.push(format!("      s3: {}", b.s[2]));
        out.push(format!("      s4: {}", b.s[3]));
    }
    for i in 0..4 {
        let h = params.h_range(i).to_string();
        out.push(format!("      h{}: {}", i + 1, q(&h)));
    }
    if let Some(chains) = &params.chains {
        for (i, c) in chains.iter().enumerate() {
            if !c.is_empty() {
                out.push(format!("      i{}: {}", i + 1, q(c)));
            }
        }
    }
    if let Some(p) = &params.awg3
        && v.supports_awg3()
    {
        if let Some(key) = p.header_protection_key {
            out.push(format!(
                "      header-protection-key: {}",
                q(&B64.encode(key))
            ));
        }
        let ranges = [
            ("content-padding-addition", p.content_padding_addition),
            ("rekey-after-time", p.rekey_after_time),
            ("rekey-timeout", p.rekey_timeout),
            ("reject-after-time", p.reject_after_time),
            ("keepalive-timeout", p.keepalive_timeout),
            ("max-handshake-attempts", p.max_handshake_attempts),
        ];
        for (field, value) in ranges {
            if let Some(r) = value {
                out.push(format!("      {field}: {}", q(&r.to_string())));
            }
        }
        if v.supports_feature_flags() {
            if p.random_trailers {
                out.push("      random-trailers: true".into());
            }
            if p.disable_cookies {
                out.push("      disable-cookies: true".into());
            }
        }
    }
    out.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::SeededRng;
    use crate::versions::{AwgVersion, GenOptions, generate};

    fn yaml(v: AwgVersion) -> (VersionedParams, String) {
        let p = generate(&mut SeededRng::new(4), &GenOptions::for_version(v)).unwrap();
        let y = render(&p, &MihomoPeer::placeholders());
        (p, y)
    }

    #[test]
    fn every_3_x_entry_selects_the_v3_implementation() {
        for v in AwgVersion::ALL {
            let (_, y) = yaml(v);
            assert_eq!(y.contains("      version: 3\n"), v.supports_awg3(), "{v}");
        }
        let (_, y) = yaml(AwgVersion::V3_1);
        assert!(y.contains("random-trailers: true"));
        assert!(y.contains("header-protection-key: "));
    }

    #[test]
    fn the_shape_follows_the_version() {
        let (p, y) = yaml(AwgVersion::V1_0);
        assert!(!y.contains("      s3:") && !y.contains("      i1:"));
        assert!(y.contains(&format!("jc: {}", p.base.jc)));
        let (p, y) = yaml(AwgVersion::V2_0);
        assert!(y.contains(&format!("      h1: \"{}\"", p.h_range(0))));
        assert!(y.contains("      s4:") && y.contains("      i1: \"<"));
        assert!(!y.contains("version: 3") && !y.contains("header-protection-key"));
    }

    #[test]
    fn a_client_conf_fills_in_its_own_values() {
        let conf = ConfFile::parse(
            "[Interface]\nPrivateKey = yNMDBJ4Vd3nZuJ2FZ1ChNTvHNQg1KgLpOaOtQC8LSXY=\n\
             Address = 10.8.1.2/32, fd00::2/128\n\n[Peer]\n\
             PublicKey = 0RSyG3nCXLBLGvNGqIzfhAqxV5s+RBgs1cq5AhCUcng=\n\
             PresharedKey = dGVzdHBza3Rlc3Rwc2t0ZXN0cHNrdGVzdHBza3Rlc3Q=\n\
             Endpoint = [2001:db8::1]:443\n",
        );
        let p = MihomoPeer::from_conf(&conf, "home");
        assert_eq!(p.ip, "10.8.1.2");
        assert_eq!(p.server, "2001:db8::1");
        assert_eq!(p.port, 443);
        assert!(p.pre_shared_key.is_some());
        let (params, _) = yaml(AwgVersion::V3_0);
        let y = render(&params, &p);
        assert!(!y.contains("YOUR_"));
        assert!(y.contains("  - name: \"home\""));
    }
}
