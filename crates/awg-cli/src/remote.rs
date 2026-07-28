//! Getting from "the user named a server" to "an open session".
//!
//! Shared by the command-line and the UI so both resolve a target the same way:
//! a saved profile by name, or a host given on the command line. The secret, if
//! one is needed at all, is asked for here and lives only in this call.

use awg_core::profile::{self, Auth, Profile};
use awg_core::ssh::{self, Session};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};

use crate::i18n::{Key as K, Lang, t};

/// Deliberately not `Debug`. It carries a password or passphrase in memory, and
/// a derived `Debug` is how that ends up in a panic message, a log line or a
/// bug report. Tests below assert on the error side rather than unwrapping the
/// success side for the same reason.
pub struct Target {
    pub profile: Profile,
    /// What SSH needs: a login password, or a passphrase for the key.
    pub secret: Option<String>,
    /// What `sudo -S` needs. Not the same thing as `secret`: logging in with a
    /// key means the passphrase, if any, unlocks the key and has nothing to do
    /// with the account's password. Conflating them is how `--sudo` with key
    /// auth fails with "no password was provided" and no way to supply one.
    pub sudo_password: Option<String>,
}

/// Everything a caller needs to reach a host, worked out from the flags.
///
/// `--server` and an explicit `--host` are alternatives, not a merge: half a
/// saved profile overridden by half a command line is the kind of thing that
/// connects somewhere the user did not mean.
///
/// The saved-connection flag is `--server` rather than `--profile` because
/// `--profile` already means a mimicry profile on `gen`, and one flag with two
/// meanings is a bug waiting for someone to be in a hurry.
pub fn resolve(args: &[String], lang: Lang) -> Result<Target, String> {
    let flag = |n: &str| {
        args.iter()
            .position(|a| a == n)
            .and_then(|i| args.get(i + 1).cloned())
    };

    let profile = match (flag("--server"), flag("--host")) {
        (Some(_), Some(_)) => {
            return Err(t(lang, K::ErrProfileAndHost).into());
        }
        (Some(name), None) => {
            let dir = profile::default_config_dir().map_err(|e| e.to_string())?;
            profile::get_by_name(&dir, &name)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("{}: {name}", t(lang, K::ErrNoSuchProfile)))?
        }
        (None, Some(host)) => {
            let user = flag("--user").unwrap_or_else(|| "root".into());
            let mut p = Profile::new("(ad hoc)", host, user);
            if let Some(port) = flag("--port").and_then(|v| v.parse().ok()) {
                p.port = port;
            }
            p.auth = match flag("--key") {
                Some(path) => Auth::Key { path: path.into() },
                None if args.iter().any(|a| a == "--password") => Auth::Password,
                None => Auth::Agent,
            };
            p.sudo_required = args.iter().any(|a| a == "--sudo");
            p
        }
        (None, None) => {
            // Exactly one saved profile is not ambiguous, so do not make the
            // user name it. More than one, and guessing would be worse than
            // asking.
            let dir = profile::default_config_dir().map_err(|e| e.to_string())?;
            let all = profile::load_all(&dir).map_err(|e| e.to_string())?;
            match all.len() {
                1 => all.into_iter().next().unwrap(),
                0 => return Err(t(lang, K::ErrNoProfiles).into()),
                _ => {
                    let names: Vec<&str> = all.iter().map(|p| p.name.as_str()).collect();
                    return Err(format!(
                        "{}: {}",
                        t(lang, K::ErrPickProfile),
                        names.join(", ")
                    ));
                }
            }
        }
    };

    let secret = if profile.auth.needs_secret() {
        let dir = profile::default_config_dir().map_err(|e| e.to_string())?;
        match profile::load_password(&dir, &profile.name).map_err(|e| e.to_string())? {
            Some(s) => Some(s),
            None => Some(
                prompt_secret(&format!(
                    "{} {}@{}: ",
                    t(lang, K::PromptSecret),
                    profile.user,
                    profile.host
                ))
                .map_err(|e| e.to_string())?,
            ),
        }
    } else {
        None
    };

    // Logging in as root, or with docker reachable directly, needs none of
    // this — so nothing is asked for.
    let sudo_password = if profile.sudo_required && profile.user != "root" {
        match &profile.auth {
            // Signed in with a password: the account password is almost always
            // the same one sudo wants, and asking twice for the same string is
            // its own kind of user-hostile.
            Auth::Password => secret.clone(),
            _ => Some(
                prompt_secret(&format!("{} {}: ", t(lang, K::PromptSudo), profile.user))
                    .map_err(|e| e.to_string())?,
            ),
        }
    } else {
        None
    };

    Ok(Target {
        profile,
        secret,
        sudo_password,
    })
}

/// Connect, asking about an unrecognised host the way ssh does.
///
/// The core refuses an unknown host outright, which is correct and also
/// unusable on its own: without somewhere to say yes, nobody could ever reach a
/// new server. So the fingerprint is shown and confirmed here, and only then
/// written to `known_hosts`.
///
/// A *mismatch* is never offered that way. An unknown host is a host you have
/// not met; a changed key on a host you have met is either a rebuild or someone
/// standing in the middle, and a prompt that treats those the same trains people
/// to click through the one that matters.
pub fn connect(target: &Target, lang: Lang) -> Result<Session, String> {
    match ssh::connect(&target.profile, target.secret.as_deref()) {
        Ok(s) => Ok(s),
        Err(awg_core::Error::UnknownHostKey { host, fingerprint }) => {
            let key = ssh::fetch_host_key(&target.profile).map_err(|e| e.to_string())?;
            eprintln!("{} {host}:", t(lang, K::MsgUnknownHost));
            eprintln!("  {} {}", key.key_type, fingerprint);
            eprintln!("  {}", t(lang, K::MsgVerifyFingerprint));
            if !confirm(t(lang, K::AskTrustHost)) {
                return Err(t(lang, K::MsgNotTrusted).into());
            }
            let path = ssh::default_known_hosts_path().map_err(|e| e.to_string())?;
            ssh::accept_new_host_key(&path, &target.profile.host, target.profile.port, &key.blob)
                .map_err(|e| e.to_string())?;
            ssh::connect(&target.profile, target.secret.as_deref()).map_err(|e| e.to_string())
        }
        Err(e @ awg_core::Error::HostKeyMismatch { .. }) => {
            Err(format!("{e}\n{}", t(lang, K::MsgMismatchAdvice)))
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Ask a yes/no question on the terminal. Defaults to no: every caller is about
/// to change something on a machine that is not this one.
pub fn confirm(question: &str) -> bool {
    use std::io::Write;
    eprint!("{question} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Read a line without echoing it.
///
/// Written by hand rather than pulled in as a crate: it is twenty lines against
/// another dependency in a tool that ships inside minimal containers. Raw mode
/// is disabled on every exit path, including the interrupt, because a terminal
/// left without echo after a failed password is a nasty thing to hand someone.
fn prompt_secret(label: &str) -> std::io::Result<String> {
    eprint!("{label}");
    use std::io::Write;
    std::io::stderr().flush()?;

    enable_raw_mode()?;
    let mut out = String::new();
    let result = loop {
        match event::read() {
            Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => match k.code {
                KeyCode::Enter => break Ok(()),
                KeyCode::Backspace => {
                    out.pop();
                }
                KeyCode::Esc => {
                    out.clear();
                    break Ok(());
                }
                KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                    out.clear();
                    break Err(std::io::Error::other("interrupted"));
                }
                KeyCode::Char(c) => out.push(c),
                _ => {}
            },
            Ok(_) => {}
            Err(e) => break Err(e),
        }
    };
    disable_raw_mode()?;
    eprintln!();
    result.map(|()| out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// `Target` has no `Debug` on purpose, so `unwrap`/`unwrap_err` are not
    /// available here.
    fn ok(v: &[&str]) -> Target {
        match resolve(&args(v), Lang::En) {
            Ok(t) => t,
            Err(e) => panic!("expected a target, got: {e}"),
        }
    }

    fn err(v: &[&str]) -> String {
        match resolve(&args(v), Lang::En) {
            Ok(_) => panic!("expected an error"),
            Err(e) => e,
        }
    }

    #[test]
    fn a_host_on_the_command_line_needs_no_saved_profile() {
        let t = ok(&["--host", "vpn.example.com", "--user", "ada"]);
        assert_eq!(t.profile.host, "vpn.example.com");
        assert_eq!(t.profile.user, "ada");
        assert_eq!(t.profile.port, 22);
        assert!(matches!(t.profile.auth, Auth::Agent));
        assert!(t.secret.is_none(), "agent auth must not ask for anything");
    }

    #[test]
    fn a_key_path_selects_key_auth_and_still_asks_for_nothing() {
        let t = ok(&["--host", "h", "--key", "/home/ada/.ssh/id_ed25519"]);
        assert!(matches!(t.profile.auth, Auth::Key { .. }));
        assert!(t.secret.is_none());
    }

    #[test]
    fn a_profile_and_a_host_together_are_refused_rather_than_merged() {
        // Silently preferring one of them is how you end up logged into the
        // wrong machine while believing you are on the right one.
        assert!(!err(&["--server", "home", "--host", "somewhere"]).is_empty());
    }

    #[test]
    fn a_port_is_taken_from_the_command_line_when_given() {
        assert_eq!(ok(&["--host", "h", "--port", "2222"]).profile.port, 2222);
    }

    #[test]
    fn a_nonsense_port_falls_back_to_the_default_instead_of_failing() {
        assert_eq!(
            ok(&["--host", "h", "--port", "not-a-number"]).profile.port,
            22
        );
    }
}
