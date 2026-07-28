//! Is this tool out of date, and are the images on a server out of date.
//!
//! Where to look:
//!
//! | module       | question it answers                                     |
//! |--------------|---------------------------------------------------------|
//! | [`version`]  | which of two versions is newer                          |
//! | [`clock`]    | which of two timestamps is earlier                      |
//! | [`http`]     | fetching a URL — the only socket this crate opens        |
//! | [`github`]   | is the compiled binary behind the newest release        |
//! | [`registry`] | is a host's image behind what Docker Hub serves         |
//!
//! Two rules shape all of it.
//!
//! **All network access in this crate lives under this module.** Everything else
//! in `awg-core` is a pure function over text and stays that way, so the rest of
//! the crate remains testable with no network at all. The parsing and comparison
//! functions take strings, and the tests feed them fixed ones.
//!
//! **An update check must never be able to break anything.** The user asked to
//! deploy a server, not to talk to GitHub. So [`check_tool_update`] and
//! [`check_image_update`] return an `Unknown` variant carrying the reason rather
//! than an error, and nothing here can propagate a failure into the caller's own
//! work.
//!
//! Versions are compared as semver, never as text: `0.1.10` is newer than
//! `0.1.9`, which a string comparison gets backwards. Images are compared by
//! digest, never by tag: `latest` moves, so the same tag can be months stale.

pub mod clock;
pub mod github;
pub mod registry;
pub mod version;

#[cfg(not(target_arch = "wasm32"))]
pub mod http;

pub use clock::parse_rfc3339;
pub use github::{RELEASES_URL, Release, ToolUpdate, compare_tool_version, parse_release};
pub use registry::{
    HubTag, ImageUpdate, LocalImage, compare_image_digest, hub_tag_url, parse_hub_tag,
};
pub use version::{CURRENT_VERSION, PreField, SemVer};

#[cfg(not(target_arch = "wasm32"))]
pub use github::{check_tool_update, check_tool_update_at};
#[cfg(not(target_arch = "wasm32"))]
pub use http::{HTTP_TIMEOUT_SECS, http_get};
#[cfg(not(target_arch = "wasm32"))]
pub use registry::check_image_update;
