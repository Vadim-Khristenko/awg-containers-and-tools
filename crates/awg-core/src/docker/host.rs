//! How a command reaches the target, and whether it has to be escalated.
//!
//! There is one SSH transport in this crate — [`crate::ssh`] — and this is a
//! thin wrapper over it, not a second one. It exists for the same reason
//! `deploy::remote::Remote` does: whether docker answers without sudo is a
//! property of the host, learned once by the survey, and not something to
//! rediscover on every command.

use crate::deploy::survey::Survey;
use crate::ssh::{Session, exec, exec_sudo};
use crate::{Error, Result};

/// A session, plus what is known about privileges on the other end.
pub struct Host<'a> {
    session: &'a Session,
    sudo_password: Option<&'a str>,
    is_root: bool,
    docker_needs_sudo: bool,
}

impl<'a> Host<'a> {
    pub fn new(session: &'a Session, sudo_password: Option<&'a str>) -> Self {
        Self {
            session,
            sudo_password,
            is_root: false,
            docker_needs_sudo: false,
        }
    }

    /// Adopt what a [`Survey`] already learned.
    pub fn with_survey(mut self, s: &Survey) -> Self {
        self.is_root = s.is_root;
        self.docker_needs_sudo = s.docker.needs_sudo();
        self
    }

    pub fn with_root(mut self, is_root: bool) -> Self {
        self.is_root = is_root;
        self
    }

    pub fn with_docker_sudo(mut self, needs_sudo: bool) -> Self {
        self.docker_needs_sudo = needs_sudo;
        self
    }

    /// As the login user.
    pub fn run(&self, cmd: &str) -> Result<(String, String, i32)> {
        exec(self.session, cmd)
    }

    /// As root — directly when we already are, since a minimal image may not
    /// have sudo installed at all.
    pub fn run_root(&self, cmd: &str) -> Result<(String, String, i32)> {
        if self.is_root {
            exec(self.session, cmd)
        } else {
            exec_sudo(self.session, cmd, self.sudo_password)
        }
    }

    /// A docker command, escalated only if the survey said it has to be.
    pub fn run_docker(&self, cmd: &str) -> Result<(String, String, i32)> {
        if self.docker_needs_sudo || self.is_root {
            self.run_root(cmd)
        } else {
            self.run(cmd)
        }
    }
}

/// Command-name hygiene.
///
/// Container and interface names are interpolated into a shell command, so
/// anything outside docker's own character set is refused rather than quoted
/// and hoped for. Docker itself allows `[a-zA-Z0-9][a-zA-Z0-9_.-]*`, and an
/// interface name is narrower still.
pub(crate) fn safe_name(name: &str) -> Result<&str> {
    let n = name.trim();
    if n.is_empty()
        || !n
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
    {
        return Err(Error::Config(format!(
            "{n:?} is not a usable container or interface name"
        )));
    }
    Ok(n)
}

/// The same, for an image reference, which additionally allows `/`, `:` and `@`.
pub(crate) fn safe_image(reference: &str) -> Result<&str> {
    let n = reference.trim();
    if n.is_empty()
        || !n
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '/' | ':' | '@'))
    {
        return Err(Error::Config(format!(
            "{n:?} is not a usable image reference"
        )));
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_that_could_break_out_of_a_command_are_refused() {
        for bad in [
            "awg; rm -rf /",
            "$(whoami)",
            "a`b`",
            "awg0 && id",
            "",
            "   ",
            "a|b",
            "a'b",
        ] {
            assert!(safe_name(bad).is_err(), "{bad:?} was accepted");
        }
        for good in ["awg-server", "awg0", "my.container_1", "a"] {
            assert_eq!(safe_name(good).unwrap(), good);
        }
        // Leading and trailing space is trimmed rather than rejected.
        assert_eq!(safe_name("  awg0 ").unwrap(), "awg0");
    }

    #[test]
    fn an_image_reference_may_carry_a_registry_a_tag_and_a_digest() {
        for good in [
            "vaiprog/amnezia-wg-3:latest",
            "ghcr.io/x/y:v1",
            "localhost:5000/z",
            "vaiprog/amnezia-wg-3@sha256:abcd",
        ] {
            assert_eq!(safe_image(good).unwrap(), good);
        }
        for bad in ["a`b`", "x; id", "", "a b"] {
            assert!(safe_image(bad).is_err(), "{bad:?} was accepted");
        }
    }
}
