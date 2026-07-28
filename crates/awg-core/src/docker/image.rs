//! Is this image one of ours, and which protocol generation is it.
//!
//! Everything here is about the image *reference* — the string docker prints in
//! the `IMAGE` column. Matching on it rather than on a container name is what
//! makes a container someone started by hand, or renamed afterwards, still
//! recognisable as the same deployment.

use crate::versions::AwgVersion;

/// The repository names this project publishes, without registry or namespace.
///
/// The major number is spelled without its dot because a Docker path segment
/// containing one reads as a registry host — see `containers/build.sh`.
pub const AWG_REPOSITORIES: [&str; 5] = [
    "amnezia-wg-1",
    "amnezia-wg-15",
    "amnezia-wg-2",
    "amnezia-wg-3",
    "amnezia-wg-dns",
];

/// The label every image in this project carries, holding the protocol
/// generation. The fallback for an image retagged to something private.
pub const PROTOCOL_LABEL: &str = "space.vai-rice.awg.protocol";

/// Which protocol generation an image is for. The resolver has no protocol of
/// its own, hence the separate variant rather than a fifth [`AwgVersion`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Generation {
    Awg(AwgVersion),
    Dns,
}

impl Generation {
    pub fn as_str(self) -> &'static str {
        match self {
            Generation::Awg(v) => v.as_str(),
            Generation::Dns => "dns",
        }
    }

    /// The protocol generation, or `None` for the resolver.
    pub fn awg(self) -> Option<AwgVersion> {
        match self {
            Generation::Awg(v) => Some(v),
            Generation::Dns => None,
        }
    }

    /// From a bare repository name, e.g. `amnezia-wg-15`.
    pub fn from_repository(repo: &str) -> Option<Self> {
        match repo {
            "amnezia-wg-1" => Some(Generation::Awg(AwgVersion::V1_0)),
            "amnezia-wg-15" => Some(Generation::Awg(AwgVersion::V1_5)),
            "amnezia-wg-2" => Some(Generation::Awg(AwgVersion::V2_0)),
            "amnezia-wg-3" => Some(Generation::Awg(AwgVersion::V3_0)),
            "amnezia-wg-dns" => Some(Generation::Dns),
            _ => None,
        }
    }

    /// From the value of [`PROTOCOL_LABEL`], e.g. `3.0`.
    pub fn from_label(value: &str) -> Option<Self> {
        let v = value.trim();
        if v.eq_ignore_ascii_case("dns") {
            return Some(Generation::Dns);
        }
        AwgVersion::parse(v).map(Generation::Awg)
    }
}

impl std::fmt::Display for Generation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A docker image reference, taken apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef {
    /// Exactly what docker reported, unmodified.
    pub raw: String,
    /// `ghcr.io`, `localhost:5000`, or `None` for an implicit Docker Hub.
    pub registry: Option<String>,
    /// `vaiprog`, or `None` for an implicit `library`.
    pub namespace: Option<String>,
    pub repository: String,
    /// `latest` when the reference carried no tag.
    pub tag: String,
    /// Present only for a `repo@sha256:...` reference.
    pub digest: Option<String>,
}

impl ImageRef {
    /// Ours if the repository is one of [`AWG_REPOSITORIES`], whatever registry
    /// or namespace it was pulled from.
    pub fn is_awg(&self) -> bool {
        AWG_REPOSITORIES.contains(&self.repository.as_str())
    }

    pub fn generation(&self) -> Option<Generation> {
        Generation::from_repository(&self.repository)
    }

    /// `namespace/repository` as Docker Hub's API spells it, or `None` when the
    /// image does not come from Hub and so has no Hub tag to compare against.
    pub fn hub_repository(&self) -> Option<String> {
        match self.registry.as_deref() {
            None | Some("docker.io") | Some("registry-1.docker.io") | Some("index.docker.io") => {
                Some(format!(
                    "{}/{}",
                    self.namespace.as_deref().unwrap_or("library"),
                    self.repository
                ))
            }
            Some(_) => None,
        }
    }
}

/// Split a reference into registry, namespace, repository, tag and digest.
///
/// The awkward part is telling `vaiprog/amnezia-wg-3` from
/// `localhost:5000/amnezia-wg-3`: docker's own rule is that the first path
/// segment is a registry when it contains a dot or a colon, or is exactly
/// `localhost`. Anything else is a namespace on Docker Hub.
pub fn parse_image_ref(reference: &str) -> Option<ImageRef> {
    let raw = reference.trim();
    if raw.is_empty() {
        return None;
    }

    let (without_digest, digest) = match raw.split_once('@') {
        Some((head, d)) => (head, Some(d.to_string())),
        None => (raw, None),
    };

    // A colon after the last slash is a tag; before it, it is a registry port.
    let last_slash = without_digest.rfind('/');
    let tag_split = without_digest.rfind(':').filter(|i| match last_slash {
        Some(s) => *i > s,
        None => true,
    });
    let (path, tag) = match tag_split {
        Some(i) => (&without_digest[..i], without_digest[i + 1..].to_string()),
        None => (without_digest, "latest".to_string()),
    };

    let mut parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    let repository = parts.pop()?.to_string();

    let first_is_registry = parts
        .first()
        .is_some_and(|f| f.contains('.') || f.contains(':') || *f == "localhost");
    let registry = if first_is_registry {
        Some(parts.remove(0).to_string())
    } else {
        None
    };

    Some(ImageRef {
        raw: raw.to_string(),
        registry,
        namespace: if parts.is_empty() {
            None
        } else {
            Some(parts.join("/"))
        },
        repository,
        tag,
        digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hub_reference_splits_into_namespace_repository_and_tag() {
        let r = parse_image_ref("vaiprog/amnezia-wg-3:latest").unwrap();
        assert_eq!(r.registry, None);
        assert_eq!(r.namespace.as_deref(), Some("vaiprog"));
        assert_eq!(r.repository, "amnezia-wg-3");
        assert_eq!(r.tag, "latest");
        assert!(r.is_awg());
        assert_eq!(r.generation(), Some(Generation::Awg(AwgVersion::V3_0)));
        assert_eq!(r.hub_repository().as_deref(), Some("vaiprog/amnezia-wg-3"));
        // No tag means latest.
        assert_eq!(
            parse_image_ref("vaiprog/amnezia-wg-2").unwrap().tag,
            "latest"
        );
    }

    #[test]
    fn a_registry_is_told_from_a_namespace_the_way_docker_tells_them_apart() {
        let r = parse_image_ref("ghcr.io/vadim/amnezia-wg-15:v2").unwrap();
        assert_eq!(r.registry.as_deref(), Some("ghcr.io"));
        assert_eq!(r.namespace.as_deref(), Some("vadim"));
        assert_eq!(r.repository, "amnezia-wg-15");
        assert_eq!(r.tag, "v2");
        assert_eq!(r.generation(), Some(Generation::Awg(AwgVersion::V1_5)));
        // Not on Hub, so there is no Hub tag to compare a digest against.
        assert_eq!(r.hub_repository(), None);

        // A port is the other thing that makes a segment a registry.
        let r = parse_image_ref("localhost:5000/amnezia-wg-1:latest").unwrap();
        assert_eq!(r.registry.as_deref(), Some("localhost:5000"));
        assert_eq!(r.namespace, None);
        assert_eq!(r.tag, "latest");
        assert_eq!(r.generation(), Some(Generation::Awg(AwgVersion::V1_0)));

        // A colon before the last slash is a port, not a tag.
        let r = parse_image_ref("reg.example:5000/team/amnezia-wg-3").unwrap();
        assert_eq!(r.tag, "latest");
        assert_eq!(r.repository, "amnezia-wg-3");
    }

    #[test]
    fn a_digest_reference_keeps_its_digest() {
        let r = parse_image_ref("vaiprog/amnezia-wg-dns@sha256:abcd").unwrap();
        assert_eq!(r.digest.as_deref(), Some("sha256:abcd"));
        assert_eq!(r.repository, "amnezia-wg-dns");
        assert_eq!(r.generation(), Some(Generation::Dns));
        assert_eq!(r.generation().unwrap().awg(), None, "dns has no protocol");
    }

    #[test]
    fn something_else_entirely_is_not_ours() {
        assert!(!parse_image_ref("nginx:latest").unwrap().is_awg());
        assert!(!parse_image_ref("library/alpine").unwrap().is_awg());
        // A repository whose name only looks like one of ours.
        assert!(
            !parse_image_ref("someone/amnezia-wg-4:latest")
                .unwrap()
                .is_awg()
        );
        assert!(!parse_image_ref("someone/my-amnezia-wg-3").unwrap().is_awg());
        assert!(parse_image_ref("").is_none());
        assert!(parse_image_ref("   ").is_none());
    }

    #[test]
    fn every_published_repository_maps_to_a_generation_and_back() {
        for repo in AWG_REPOSITORIES {
            let g = Generation::from_repository(repo)
                .unwrap_or_else(|| panic!("{repo} has no generation"));
            assert_eq!(Generation::from_label(g.as_str()), Some(g));
        }
        assert_eq!(Generation::from_repository("amnezia-wg-9"), None);
        assert_eq!(Generation::from_label("nonsense"), None);
        assert_eq!(Generation::Awg(AwgVersion::V1_5).to_string(), "1.5");
        assert_eq!(Generation::Dns.to_string(), "dns");
    }
}
