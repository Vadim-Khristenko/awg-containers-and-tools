//! Is a host's image behind what the registry serves.
//!
//! Comparing tags would answer nothing: `latest` moves, so the same tag can be
//! months stale. The digest is the only thing that identifies the bytes, and it
//! is what is compared here.

use super::clock::parse_rfc3339;
use crate::{Error, Result};

/// A tag as Docker Hub describes it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HubTag {
    pub name: String,
    /// The manifest (or index) digest the tag currently points at.
    pub digest: Option<String>,
    pub last_updated: Option<String>,
    pub full_size: Option<u64>,
    /// `(architecture, digest)` for each platform under the index.
    pub arch_digests: Vec<(String, String)>,
}

pub fn hub_tag_url(hub_repository: &str, tag: &str) -> String {
    format!("https://hub.docker.com/v2/repositories/{hub_repository}/tags/{tag}")
}

pub fn parse_hub_tag(json: &str) -> Result<HubTag> {
    let v: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| Error::Config(format!("the Docker Hub reply was not JSON: {e}")))?;
    if let Some(msg) = v.get("message").and_then(|x| x.as_str())
        && v.get("name").is_none()
    {
        return Err(Error::Config(format!("Docker Hub said: {msg}")));
    }
    Ok(HubTag {
        name: v
            .get("name")
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string(),
        digest: v.get("digest").and_then(|x| x.as_str()).map(str::to_string),
        last_updated: v
            .get("last_updated")
            .and_then(|x| x.as_str())
            .map(str::to_string),
        full_size: v.get("full_size").and_then(serde_json::Value::as_u64),
        arch_digests: v
            .get("images")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|i| {
                        Some((
                            i.get("architecture")?.as_str()?.to_string(),
                            i.get("digest")?.as_str()?.to_string(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// An image as a host has it.
///
/// Built by [`crate::docker::parse_image_inspect`]; the type lives here so this
/// module never has to know about docker or SSH.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalImage {
    pub reference: String,
    /// `namespace/repository`, or `None` when the image does not come from
    /// Docker Hub and so has nothing here to be compared against.
    pub hub_repository: Option<String>,
    pub tag: String,
    /// `repo@sha256:...` entries as `docker image inspect` reports them.
    pub repo_digests: Vec<String>,
    /// When the image was created on this host.
    pub created: Option<String>,
    /// `org.opencontainers.image.created` — when the image was *built*, which
    /// for a locally built image is the only honest age.
    pub label_created: Option<String>,
}

impl LocalImage {
    /// The digest recorded for this repository, if any.
    ///
    /// An image built on the host and never pushed has one too — it is simply
    /// not a digest any registry knows, which is why a difference is not by
    /// itself proof of being stale.
    pub fn digest(&self) -> Option<&str> {
        let repo = self.hub_repository.as_deref();
        self.repo_digests
            .iter()
            .find(|d| repo.is_none_or(|r| d.starts_with(r)))
            .and_then(|d| d.split_once('@'))
            .map(|(_, digest)| digest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageUpdate {
    UpToDate {
        reference: String,
        digest: String,
        remote_pushed: Option<String>,
    },
    /// The registry serves a different digest for this tag than the host runs.
    ///
    /// That covers both "the tag moved and this host is stale" and "this image
    /// was built locally and never pushed"; `remote_is_newer` tells them apart
    /// when both timestamps are readable, and is `None` when they are not.
    Differs {
        reference: String,
        local_digest: Option<String>,
        remote_digest: String,
        remote_pushed: Option<String>,
        local_built: Option<String>,
        remote_is_newer: Option<bool>,
    },
    Unknown {
        reference: String,
        reason: String,
    },
}

impl ImageUpdate {
    pub fn summary(&self) -> String {
        match self {
            ImageUpdate::UpToDate { reference, .. } => {
                format!("{reference} is the digest the registry currently serves")
            }
            ImageUpdate::Differs {
                reference,
                remote_digest,
                remote_pushed,
                remote_is_newer,
                ..
            } => {
                let verdict = match remote_is_newer {
                    Some(true) => "the registry has a newer image",
                    Some(false) => "this host's image is newer than the registry's",
                    None => "the two differ and the dates do not say which is newer",
                };
                format!(
                    "{reference}: {verdict} — registry {remote_digest}, pushed {}",
                    remote_pushed.as_deref().unwrap_or("at an unknown time")
                )
            }
            ImageUpdate::Unknown { reference, reason } => {
                format!("{reference}: cannot tell — {reason}")
            }
        }
    }
}

/// Compare what a host runs against what a registry serves. Pure.
pub fn compare_image_digest(local: &LocalImage, remote: &HubTag) -> ImageUpdate {
    let Some(remote_digest) = remote.digest.clone() else {
        return ImageUpdate::Unknown {
            reference: local.reference.clone(),
            reason: "the registry did not report a digest for this tag".into(),
        };
    };
    let local_digest = local.digest().map(str::to_string);
    let Some(mine) = local_digest.clone() else {
        return ImageUpdate::Unknown {
            reference: local.reference.clone(),
            reason: "the host's image has no repository digest — it was built locally and never \
                     pushed or pulled, so there is nothing to compare"
                .into(),
        };
    };

    if mine == remote_digest {
        return ImageUpdate::UpToDate {
            reference: local.reference.clone(),
            digest: mine,
            remote_pushed: remote.last_updated.clone(),
        };
    }

    let local_built = local
        .label_created
        .clone()
        .or_else(|| local.created.clone());
    let remote_is_newer = match (
        local_built.as_deref().and_then(parse_rfc3339),
        remote.last_updated.as_deref().and_then(parse_rfc3339),
    ) {
        (Some(l), Some(r)) => Some(r > l),
        _ => None,
    };

    ImageUpdate::Differs {
        reference: local.reference.clone(),
        local_digest,
        remote_digest,
        remote_pushed: remote.last_updated.clone(),
        local_built,
        remote_is_newer,
    }
}

/// Is a host's image out of date? Never fails — see the module note in
/// [`super`].
#[cfg(not(target_arch = "wasm32"))]
pub fn check_image_update(local: &LocalImage) -> ImageUpdate {
    let Some(repo) = local.hub_repository.clone() else {
        return ImageUpdate::Unknown {
            reference: local.reference.clone(),
            reason: "the image does not come from Docker Hub, and no other registry is queried"
                .into(),
        };
    };
    let body = match super::http::http_get(&hub_tag_url(&repo, &local.tag)) {
        Ok(b) => b,
        Err(e) => {
            return ImageUpdate::Unknown {
                reference: local.reference.clone(),
                reason: e.to_string(),
            };
        }
    };
    match parse_hub_tag(&body) {
        Ok(t) => compare_image_digest(local, &t),
        Err(e) => ImageUpdate::Unknown {
            reference: local.reference.clone(),
            reason: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real reply for `vaiprog/amnezia-wg-3:latest`, trimmed.
    const HUB: &str = r#"{
      "images": [
        {"architecture":"amd64","digest":"sha256:2204c5bb","os":"linux","status":"active","last_pushed":"2026-07-28T18:27:11.316536288Z"},
        {"architecture":"arm64","digest":"sha256:19d90c5c","os":"linux","status":"active","last_pushed":"2026-07-28T18:27:11.826052897Z"}
      ],
      "last_updated": "2026-07-28T18:27:14.917129Z",
      "name": "latest",
      "full_size": 9856622,
      "digest": "sha256:d2b1159bd14de25b4e39e53ba593047f17812c371f2646bf30742dbd88fb5af8"
    }"#;

    fn local(digest: &str, built: &str) -> LocalImage {
        LocalImage {
            reference: "vaiprog/amnezia-wg-3:latest".into(),
            hub_repository: Some("vaiprog/amnezia-wg-3".into()),
            tag: "latest".into(),
            repo_digests: vec![format!("vaiprog/amnezia-wg-3@{digest}")],
            created: Some(built.to_string()),
            label_created: Some(built.to_string()),
        }
    }

    #[test]
    fn a_hub_tag_is_read_without_a_network() {
        let t = parse_hub_tag(HUB).unwrap();
        assert_eq!(t.name, "latest");
        assert_eq!(
            t.digest.as_deref(),
            Some("sha256:d2b1159bd14de25b4e39e53ba593047f17812c371f2646bf30742dbd88fb5af8")
        );
        assert_eq!(
            t.last_updated.as_deref(),
            Some("2026-07-28T18:27:14.917129Z")
        );
        assert_eq!(t.full_size, Some(9856622));
        assert_eq!(t.arch_digests.len(), 2);
        assert_eq!(t.arch_digests[0].0, "amd64");
        assert!(parse_hub_tag(r#"{"message":"object not found"}"#).is_err());
        assert!(parse_hub_tag("<html>").is_err());
    }

    #[test]
    fn the_same_tag_with_the_same_digest_is_up_to_date() {
        let t = parse_hub_tag(HUB).unwrap();
        let l = local(t.digest.as_deref().unwrap(), "2026-07-28T17:37:23Z");
        match compare_image_digest(&l, &t) {
            ImageUpdate::UpToDate { digest, .. } => {
                assert_eq!(Some(digest.as_str()), t.digest.as_deref());
            }
            other => panic!("expected up to date, got {other:?}"),
        }
    }

    #[test]
    fn a_tag_that_moved_is_reported_with_the_registrys_digest_and_date() {
        let t = parse_hub_tag(HUB).unwrap();
        // Same tag, different bytes — which a tag comparison cannot see at all.
        let l = local("sha256:0000000000", "2026-07-01T00:00:00Z");
        match compare_image_digest(&l, &t) {
            ImageUpdate::Differs {
                remote_digest,
                remote_pushed,
                remote_is_newer,
                local_digest,
                ..
            } => {
                assert_eq!(Some(remote_digest.as_str()), t.digest.as_deref());
                assert_eq!(
                    remote_pushed.as_deref(),
                    Some("2026-07-28T18:27:14.917129Z")
                );
                assert_eq!(remote_is_newer, Some(true));
                assert_eq!(local_digest.as_deref(), Some("sha256:0000000000"));
            }
            other => panic!("expected a difference, got {other:?}"),
        }
    }

    #[test]
    fn an_image_built_after_the_registry_push_is_not_called_stale() {
        let t = parse_hub_tag(HUB).unwrap();
        let l = local("sha256:localbuild", "2026-07-29T09:00:00Z");
        match compare_image_digest(&l, &t) {
            ImageUpdate::Differs {
                remote_is_newer, ..
            } => assert_eq!(remote_is_newer, Some(false)),
            other => panic!("expected a difference, got {other:?}"),
        }
        assert!(
            compare_image_digest(&l, &t)
                .summary()
                .contains("newer than the registry")
        );
    }

    #[test]
    fn with_no_dates_to_compare_the_verdict_does_not_claim_a_direction() {
        let t = parse_hub_tag(HUB).unwrap();
        let mut l = local("sha256:other", "2026-07-01T00:00:00Z");
        l.created = None;
        l.label_created = None;
        match compare_image_digest(&l, &t) {
            ImageUpdate::Differs {
                remote_is_newer, ..
            } => assert_eq!(remote_is_newer, None),
            other => panic!("expected a difference, got {other:?}"),
        }
    }

    #[test]
    fn an_image_with_no_digest_or_no_hub_repository_is_unknown_and_says_why() {
        let t = parse_hub_tag(HUB).unwrap();
        let mut l = local("sha256:x", "2026-07-28T00:00:00Z");
        l.repo_digests.clear();
        match compare_image_digest(&l, &t) {
            ImageUpdate::Unknown { reason, .. } => assert!(reason.contains("built locally")),
            other => panic!("expected unknown, got {other:?}"),
        }

        let mut t2 = t.clone();
        t2.digest = None;
        match compare_image_digest(&local("sha256:x", "2026-07-28T00:00:00Z"), &t2) {
            ImageUpdate::Unknown { reason, .. } => assert!(reason.contains("did not report")),
            other => panic!("expected unknown, got {other:?}"),
        }
    }

    #[test]
    fn the_digest_is_picked_out_of_the_repo_digest_list_by_repository() {
        let l = LocalImage {
            reference: "vaiprog/amnezia-wg-3:latest".into(),
            hub_repository: Some("vaiprog/amnezia-wg-3".into()),
            tag: "latest".into(),
            repo_digests: vec![
                "someone-else/amnezia-wg-3@sha256:aaa".into(),
                "vaiprog/amnezia-wg-3@sha256:bbb".into(),
            ],
            created: None,
            label_created: None,
        };
        assert_eq!(l.digest(), Some("sha256:bbb"));
        assert_eq!(LocalImage::default().digest(), None);
    }

    #[test]
    fn the_hub_url_is_built_from_the_repository_and_the_tag() {
        assert_eq!(
            hub_tag_url("vaiprog/amnezia-wg-15", "latest"),
            "https://hub.docker.com/v2/repositories/vaiprog/amnezia-wg-15/tags/latest"
        );
    }
}
