//! How a command reaches the target, and whether it has to be escalated.
//!
//! One SSH transport — [`crate::ssh`] — and a local one for the machine this
//! process runs on, which is where the docker CLI usually is. Both answer the
//! same three questions, so every caller above this file is transport-blind.

use std::process::{Command, Stdio};

use crate::deploy::survey::Survey;
use crate::ssh::{Session, exec, exec_sudo, single_quote, sudo_command};
use crate::{Error, Result};

enum Backend<'a> {
    /// A shell on someone else's machine.
    Ssh(&'a Session),
    /// This machine.
    Local,
}

/// A target, plus what is known about privileges on it.
pub struct Host<'a> {
    backend: Backend<'a>,
    sudo_password: Option<&'a str>,
    is_root: bool,
    docker_needs_sudo: bool,
}

impl<'a> Host<'a> {
    pub fn new(session: &'a Session, sudo_password: Option<&'a str>) -> Self {
        Self {
            backend: Backend::Ssh(session),
            sudo_password,
            is_root: false,
            docker_needs_sudo: false,
        }
    }

    /// This machine, where the docker CLI is reachable without sudo on anything
    /// but a Linux box whose socket is root-owned.
    pub fn local() -> Self {
        Self {
            backend: Backend::Local,
            sudo_password: None,
            is_root: false,
            docker_needs_sudo: false,
        }
    }

    pub fn is_local(&self) -> bool {
        matches!(self.backend, Backend::Local)
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
        match self.backend {
            Backend::Ssh(s) => exec(s, cmd),
            Backend::Local => run_local(cmd, None),
        }
    }

    /// As root — directly when we already are, since a minimal image may not
    /// have sudo installed at all.
    pub fn run_root(&self, cmd: &str) -> Result<(String, String, i32)> {
        match self.backend {
            Backend::Ssh(s) if self.is_root => exec(s, cmd),
            Backend::Ssh(s) => exec_sudo(s, cmd, self.sudo_password),
            Backend::Local if self.is_root => run_local(cmd, None),
            Backend::Local => run_local(cmd, Some(self.sudo_password.unwrap_or_default())),
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

/// Run a command in a shell on this machine.
///
/// A non-zero exit code is data, not an error, exactly as over SSH. `sudo` is
/// the password when one is known: `-n` when it is not, so a missing password
/// fails immediately instead of waiting for a prompt nobody can see.
fn run_local(cmd: &str, sudo: Option<&str>) -> Result<(String, String, i32)> {
    let full = match sudo {
        None => cmd.to_string(),
        Some("") => format!("sudo -n sh -c {}", single_quote(cmd)),
        Some(_) => sudo_command(cmd),
    };

    let (program, flag) = if cfg!(windows) {
        ("cmd", "/C")
    } else {
        ("sh", "-c")
    };
    let mut child = Command::new(program)
        .arg(flag)
        .arg(&full)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Config(format!("could not run `{full}`: {e}")))?;

    if let Some(pw) = sudo.filter(|p| !p.is_empty()) {
        use std::io::Write as _;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(pw.as_bytes())
                .and_then(|()| stdin.write_all(b"\n"))
                .map_err(|e| Error::Config(format!("could not send the sudo password: {e}")))?;
        }
    }
    // sudo reads stdin to EOF; dropping it is what ends the read.
    drop(child.stdin.take());

    let out = child
        .wait_with_output()
        .map_err(|e| Error::Config(format!("`{full}` did not finish: {e}")))?;
    // The Windows docker CLI puts CRLF on everything, and every parser above
    // this file was written against what SSH returns.
    let text = |b: &[u8]| String::from_utf8_lossy(b).replace("\r\n", "\n");
    Ok((
        text(&out.stdout),
        text(&out.stderr),
        out.status.code().unwrap_or(-1),
    ))
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
    fn a_local_command_runs_and_reports_its_exit_code() {
        let (out, _, code) = Host::local().run("echo awg-tool").unwrap();
        assert_eq!(out.trim(), "awg-tool");
        assert_eq!(code, 0);

        // A non-zero exit is data, not an error — the same contract as SSH.
        let (_, _, code) = Host::local().run("exit 3").unwrap();
        assert_eq!(code, 3);
        assert!(Host::local().is_local());
    }

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
