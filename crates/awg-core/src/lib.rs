//! Protocol rules for AmneziaWG, as a library.
//!
//! The point of this crate is that there is exactly one implementation of the
//! rules. The CLI links it, the containers ship that CLI, and the web generator
//! at architect.vai-rice.space compiles it to WASM — so a parameter set that is
//! valid in one place is valid in all of them.

pub mod awg3;
pub mod deploy;
pub mod mimic;
pub mod platform;
pub mod profile;
pub mod render;
pub mod rng;
pub mod support;
pub mod update;
pub mod versions;
pub mod vpn;

// WASM has no sockets and no OpenSSL to link; there the crate simply has no
// transport rather than one that compiles and cannot work. The same goes for
// `docker`, which is nothing but commands sent down that transport.
#[cfg(not(target_arch = "wasm32"))]
pub mod docker;
#[cfg(not(target_arch = "wasm32"))]
pub mod ssh;

use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum Error {
    /// A protocol invariant would be violated. These are the failures that are
    /// silent at runtime — a tunnel that dies minutes later, or a cipher whose
    /// nonce quietly stops being random — so they are refused up front.
    #[error("protocol invariant violated: {0}")]
    Invariant(String),

    #[error("invalid key material: {0}")]
    Key(String),

    /// An I1–I5 chain could not be parsed. Separate from `Config` because the
    /// fault is always inside one string and the message says where.
    #[error("chain syntax: {0}")]
    Chain(String),

    /// Reading or writing the on-disk profile store went wrong, or what was on
    /// disk was not something we are willing to load.
    #[error("configuration: {0}")]
    Config(String),

    #[error("ssh: {0}")]
    Ssh(String),

    /// Nothing in `known_hosts` mentions this host. The fingerprint travels with
    /// the error because the only correct next step is to show it to a human;
    /// this tool deploys VPNs, and a silently accepted key is a silently
    /// accepted man in the middle.
    #[error("unknown host key for {host} — fingerprint {fingerprint}")]
    UnknownHostKey { host: String, fingerprint: String },

    /// `known_hosts` has a *different* key for this host. Either the server was
    /// rebuilt or someone is answering for it; both need a human, and neither
    /// is something to retry through.
    #[error("host key mismatch for {host} — server presented {fingerprint}")]
    HostKeyMismatch { host: String, fingerprint: String },
}

pub type Result<T> = std::result::Result<T, Error>;
