//! Is the compiled binary behind the newest published release.

use super::version::SemVer;
use crate::{Error, Result};

pub const RELEASES_URL: &str =
    "https://api.github.com/repos/Vadim-Khristenko/awg-containers-and-tools/releases/latest";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub tag: String,
    /// `None` when the tag is not a version at all.
    pub version: Option<SemVer>,
    pub name: Option<String>,
    pub html_url: Option<String>,
    pub published_at: Option<String>,
    pub prerelease: bool,
    pub draft: bool,
}

/// Parse GitHub's `releases/latest` payload.
pub fn parse_release(json: &str) -> Result<Release> {
    let v: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| Error::Config(format!("the release feed was not JSON: {e}")))?;
    // The API answers errors with the same content type, and a missing tag is
    // exactly what that looks like.
    let tag = v
        .get("tag_name")
        .and_then(|x| x.as_str())
        .ok_or_else(|| {
            let msg = v
                .get("message")
                .and_then(|x| x.as_str())
                .unwrap_or("no tag_name in the response");
            Error::Config(format!("the release feed carried no release: {msg}"))
        })?
        .to_string();

    let text = |key: &str| v.get(key).and_then(|x| x.as_str()).map(str::to_string);
    let flag = |key: &str| {
        v.get(key)
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    };

    Ok(Release {
        version: SemVer::parse(&tag),
        tag,
        name: text("name"),
        html_url: text("html_url"),
        published_at: text("published_at"),
        prerelease: flag("prerelease"),
        draft: flag("draft"),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolUpdate {
    UpToDate {
        current: String,
    },
    Newer {
        current: String,
        latest: String,
        url: Option<String>,
        published: Option<String>,
    },
    /// This build is ahead of the newest published release — normal when
    /// running from a working tree.
    Ahead {
        current: String,
        latest: String,
    },
    Unknown {
        reason: String,
    },
}

impl ToolUpdate {
    /// True only for [`ToolUpdate::Newer`]. An unknown result must never be
    /// treated as "update available".
    pub fn is_update_available(&self) -> bool {
        matches!(self, ToolUpdate::Newer { .. })
    }

    pub fn summary(&self) -> String {
        match self {
            ToolUpdate::UpToDate { current } => format!("awg-tool {current} is the latest release"),
            ToolUpdate::Newer {
                current,
                latest,
                published,
                url,
            } => format!(
                "awg-tool {latest} is out ({}); this is {current}{}",
                published.as_deref().unwrap_or("date unknown"),
                url.as_deref()
                    .map(|u| format!(" — {u}"))
                    .unwrap_or_default()
            ),
            ToolUpdate::Ahead { current, latest } => {
                format!("awg-tool {current} is ahead of the newest release ({latest})")
            }
            ToolUpdate::Unknown { reason } => format!("update check did not complete: {reason}"),
        }
    }
}

/// Compare a compiled version against a release. Pure.
pub fn compare_tool_version(current: &str, release: &Release) -> ToolUpdate {
    let Some(mine) = SemVer::parse(current) else {
        return ToolUpdate::Unknown {
            reason: format!("the compiled version {current:?} is not a semantic version"),
        };
    };
    let Some(theirs) = release.version.clone() else {
        return ToolUpdate::Unknown {
            reason: format!(
                "the release tag {:?} is not a semantic version",
                release.tag
            ),
        };
    };
    match mine.cmp(&theirs) {
        std::cmp::Ordering::Less => ToolUpdate::Newer {
            current: mine.to_string(),
            latest: theirs.to_string(),
            url: release.html_url.clone(),
            published: release.published_at.clone(),
        },
        std::cmp::Ordering::Equal => ToolUpdate::UpToDate {
            current: mine.to_string(),
        },
        std::cmp::Ordering::Greater => ToolUpdate::Ahead {
            current: mine.to_string(),
            latest: theirs.to_string(),
        },
    }
}

/// Is this build out of date? Never fails — see the module note in
/// [`super`].
#[cfg(not(target_arch = "wasm32"))]
pub fn check_tool_update() -> ToolUpdate {
    check_tool_update_at(RELEASES_URL, super::version::CURRENT_VERSION)
}

/// [`check_tool_update`] against a specific URL and version, for pointing at a
/// fork.
#[cfg(not(target_arch = "wasm32"))]
pub fn check_tool_update_at(url: &str, current: &str) -> ToolUpdate {
    let body = match super::http::http_get(url) {
        Ok(b) => b,
        Err(e) => {
            return ToolUpdate::Unknown {
                reason: e.to_string(),
            };
        }
    };
    match parse_release(&body) {
        Ok(r) => compare_tool_version(current, &r),
        Err(e) => ToolUpdate::Unknown {
            reason: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELEASE: &str = r#"{
      "html_url": "https://github.com/Vadim-Khristenko/awg-containers-and-tools/releases/tag/v0.1.0",
      "tag_name": "v0.1.0",
      "name": "v0.1.0",
      "draft": false,
      "prerelease": false,
      "published_at": "2026-07-28T18:40:00Z"
    }"#;

    #[test]
    fn the_release_feed_is_read_without_a_network() {
        let r = parse_release(RELEASE).unwrap();
        assert_eq!(r.tag, "v0.1.0");
        assert_eq!(r.version, SemVer::parse("0.1.0"));
        assert!(!r.prerelease);
        assert!(!r.draft);
        assert_eq!(r.published_at.as_deref(), Some("2026-07-28T18:40:00Z"));
        assert!(r.html_url.unwrap().ends_with("v0.1.0"));
    }

    #[test]
    fn a_release_feed_that_is_an_error_is_an_error_and_not_a_version() {
        let e = parse_release(r#"{"message":"Not Found","documentation_url":"..."}"#).unwrap_err();
        assert!(e.to_string().contains("Not Found"));
        assert!(parse_release("not json at all").is_err());
        assert!(parse_release("{}").is_err());
    }

    #[test]
    fn comparing_the_compiled_version_against_a_release_gives_the_three_answers() {
        let r = parse_release(RELEASE).unwrap();
        assert_eq!(
            compare_tool_version("0.1.0", &r),
            ToolUpdate::UpToDate {
                current: "0.1.0".into()
            }
        );
        match compare_tool_version("0.0.9", &r) {
            ToolUpdate::Newer {
                latest, published, ..
            } => {
                assert_eq!(latest, "0.1.0");
                assert_eq!(published.as_deref(), Some("2026-07-28T18:40:00Z"));
            }
            other => panic!("expected an update, got {other:?}"),
        }
        assert!(matches!(
            compare_tool_version("0.2.0", &r),
            ToolUpdate::Ahead { .. }
        ));
    }

    #[test]
    fn the_case_a_string_comparison_gets_backwards() {
        let nine = parse_release(&RELEASE.replace("v0.1.0", "v0.1.9")).unwrap();
        assert!(
            !compare_tool_version("0.1.10", &nine).is_update_available(),
            "0.1.10 is newer than 0.1.9"
        );
        assert!(!compare_tool_version("0.1.9", &nine).is_update_available());
        assert!(compare_tool_version("0.1.8", &nine).is_update_available());
    }

    #[test]
    fn an_unreadable_version_is_unknown_rather_than_an_update() {
        let weird = parse_release(&RELEASE.replace("v0.1.0", "nightly")).unwrap();
        let u = compare_tool_version("0.1.0", &weird);
        assert!(matches!(u, ToolUpdate::Unknown { .. }));
        assert!(!u.is_update_available(), "unknown must never mean 'update'");

        let u = compare_tool_version("not-a-version", &parse_release(RELEASE).unwrap());
        assert!(matches!(u, ToolUpdate::Unknown { .. }));
        assert!(u.summary().contains("did not complete"));
    }

    #[test]
    fn every_verdict_renders_to_something_worth_showing() {
        let r = parse_release(RELEASE).unwrap();
        assert!(
            compare_tool_version("0.1.0", &r)
                .summary()
                .contains("latest")
        );
        assert!(
            compare_tool_version("0.0.1", &r)
                .summary()
                .contains("0.1.0")
        );
        assert!(
            compare_tool_version("9.0.0", &r)
                .summary()
                .contains("ahead")
        );
    }
}
