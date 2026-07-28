//! Connection profiles — where a server is and how to get onto it.
//!
//! Two files, deliberately. `profiles.json` is the half you can copy between
//! machines, paste into an issue or check into a dotfiles repo without thinking
//! about it; `secrets.json` is the half you cannot, and it only ever exists
//! because the caller asked for it in so many words. Nothing that unlocks
//! anything is written to the first file, ever.
//!
//! Every entry point takes the config directory as an argument rather than
//! reaching for `$HOME` itself — [`default_config_dir`] resolves the real one.
//! That is what lets the tests below run against a scratch directory instead of
//! the user's actual configuration.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

use crate::{Error, Result};

pub const PROFILES_FILE: &str = "profiles.json";
pub const SECRETS_FILE: &str = "secrets.json";

/// The port `ssh` itself assumes.
pub const DEFAULT_PORT: u16 = 22;

#[cfg(unix)]
const DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

/// How to prove who we are to the server.
///
/// [`Auth::KeyWithPassphrase`] carries the key path and nothing else, and that
/// absence is the feature. A passphrase exists so that a copied key file is
/// useless on its own; a field for it here would be serialised into the same
/// directory as everything else and hand back precisely what it was protecting
/// against. It is asked for at connect time and kept in memory only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Auth {
    Password,
    Key { path: PathBuf },
    KeyWithPassphrase { path: PathBuf },
    Agent,
}

impl Auth {
    /// Whether [`crate::ssh::connect`] needs a secret handed to it for this
    /// method — a password to send, or a passphrase to open the key with.
    pub fn needs_secret(&self) -> bool {
        matches!(self, Self::Password | Self::KeyWithPassphrase { .. })
    }

    /// Short label for menus and logs.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Key { .. } => "key",
            Self::KeyWithPassphrase { .. } => "key + passphrase",
            Self::Agent => "agent",
        }
    }
}

/// One saved server.
///
/// `deny_unknown_fields` is not tidiness: it means a `profiles.json` that has
/// grown a `password` or `passphrase` key — because some other tool wrote it,
/// or because someone edited it by hand — is refused loudly instead of loaded
/// with the extra field quietly dropped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub user: String,
    pub auth: Auth,
    #[serde(default)]
    pub sudo_required: bool,
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

impl Profile {
    /// A profile that needs no secret at all: agent auth on the default port.
    pub fn new(name: impl Into<String>, host: impl Into<String>, user: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port: DEFAULT_PORT,
            user: user.into(),
            auth: Auth::Agent,
            sudo_required: false,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileFile {
    #[serde(default)]
    profiles: Vec<Profile>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretFile {
    #[serde(default)]
    passwords: BTreeMap<String, String>,
}

/// `$XDG_CONFIG_HOME/awg-tool`, falling back to `~/.config/awg-tool`.
pub fn default_config_dir() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(xdg).join("awg-tool"));
    }
    // Windows sets neither of those. It has APPDATA, which is where an
    // application's own settings belong, so use it rather than inventing a
    // dot-directory in the user's profile.
    if cfg!(windows)
        && let Some(appdata) = std::env::var_os("APPDATA").filter(|v| !v.is_empty())
    {
        return Ok(PathBuf::from(appdata).join("awg-tool"));
    }
    let home = home_dir().ok_or_else(|| {
        Error::Config(
            "no home directory: none of XDG_CONFIG_HOME, APPDATA, HOME or USERPROFILE is set"
                .into(),
        )
    })?;
    Ok(home.join(".config").join("awg-tool"))
}

/// The user's home, on either kind of system.
///
/// `HOME` is not set on Windows outside of a POSIX shell, which is why the
/// first version of this refused to run there at all — with an error naming
/// two variables that Windows has never had.
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var_os("USERPROFILE").filter(|v| !v.is_empty()))
        .map(PathBuf::from)
}

pub fn profiles_path(base: &Path) -> PathBuf {
    base.join(PROFILES_FILE)
}

pub fn secrets_path(base: &Path) -> PathBuf {
    base.join(SECRETS_FILE)
}

/// Create the config directory if it is not there, and make sure it is private
/// either way.
///
/// The `set_permissions` is not redundant with `create_dir_all`: creation goes
/// through the umask, so a permissive umask would otherwise leave a
/// world-readable directory holding `secrets.json`.
pub fn ensure_config_dir(base: &Path) -> Result<()> {
    if !base.is_dir() {
        fs::create_dir_all(base).map_err(|e| io_err(base, "create", e))?;
    }
    #[cfg(unix)]
    fs::set_permissions(base, fs::Permissions::from_mode(DIR_MODE))
        .map_err(|e| io_err(base, "set permissions on", e))?;
    Ok(())
}

/// Every saved profile, oldest first. A missing file is the normal state before
/// the first save, so it reads as an empty list rather than an error.
pub fn load_all(base: &Path) -> Result<Vec<Profile>> {
    let path = profiles_path(base);
    let Some(text) = read_opt(&path)? else {
        return Ok(Vec::new());
    };
    let file: ProfileFile = serde_json::from_str(&text)
        .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
    Ok(file.profiles)
}

pub fn get_by_name(base: &Path, name: &str) -> Result<Option<Profile>> {
    Ok(load_all(base)?.into_iter().find(|p| p.name == name))
}

/// Insert or replace `profile`, keyed by name.
///
/// `password` and `save_password` are two arguments rather than one
/// `Option<&str>` because handing over a password so this call can use it is a
/// different act from agreeing to keep it on disk, and only the second one
/// should ever write a file. `save_password = false` also drops any password
/// stored earlier under this name, so turning the option off actually forgets.
pub fn save(
    base: &Path,
    profile: &Profile,
    password: Option<&str>,
    save_password: bool,
) -> Result<()> {
    if profile.name.trim().is_empty() {
        return Err(Error::Config("a profile needs a name".into()));
    }
    // Checked before anything is written, so a contradictory call leaves the
    // store exactly as it was.
    if save_password && password.is_none() {
        return Err(Error::Config(
            "save_password was requested but no password was supplied".into(),
        ));
    }

    ensure_config_dir(base)?;
    let mut all = load_all(base)?;
    match all.iter_mut().find(|p| p.name == profile.name) {
        Some(slot) => *slot = profile.clone(),
        None => all.push(profile.clone()),
    }
    write_profiles(base, &all)?;

    match (save_password, password) {
        (true, Some(pw)) => store_password(base, &profile.name, pw)?,
        _ => {
            forget_password(base, &profile.name)?;
        }
    }
    Ok(())
}

/// Delete a profile, reporting whether one of that name existed.
///
/// Its stored password goes with it: a secret that outlives the only thing
/// referring to it is a secret nobody will ever think to clean up.
pub fn remove(base: &Path, name: &str) -> Result<bool> {
    let mut all = load_all(base)?;
    let before = all.len();
    all.retain(|p| p.name != name);
    let removed = all.len() != before;
    if removed {
        ensure_config_dir(base)?;
        write_profiles(base, &all)?;
    }
    forget_password(base, name)?;
    Ok(removed)
}

/// The password saved for `name`, if one ever was.
pub fn load_password(base: &Path, name: &str) -> Result<Option<String>> {
    Ok(load_secrets(base)?.passwords.remove(name))
}

/// Write a password to `secrets.json`, 0600, never to `profiles.json`.
///
/// One password per profile covers both the SSH login and `sudo`, which is how
/// it works on the servers this drives; splitting them would mean two prompts
/// for the same string.
pub fn store_password(base: &Path, name: &str, password: &str) -> Result<()> {
    ensure_config_dir(base)?;
    let mut secrets = load_secrets(base)?;
    secrets
        .passwords
        .insert(name.to_string(), password.to_string());
    write_secrets(base, &secrets)
}

/// Drop a saved password, reporting whether there was one.
pub fn forget_password(base: &Path, name: &str) -> Result<bool> {
    let mut secrets = load_secrets(base)?;
    if secrets.passwords.remove(name).is_none() {
        return Ok(false);
    }
    ensure_config_dir(base)?;
    write_secrets(base, &secrets)?;
    Ok(true)
}

fn load_secrets(base: &Path) -> Result<SecretFile> {
    let path = secrets_path(base);
    let Some(text) = read_opt(&path)? else {
        return Ok(SecretFile::default());
    };
    serde_json::from_str(&text).map_err(|e| Error::Config(format!("{}: {e}", path.display())))
}

fn write_profiles(base: &Path, profiles: &[Profile]) -> Result<()> {
    let file = ProfileFile {
        profiles: profiles.to_vec(),
    };
    let json = serde_json::to_vec_pretty(&file)
        .map_err(|e| Error::Config(format!("serialising profiles: {e}")))?;
    write_private(&profiles_path(base), &json)
}

fn write_secrets(base: &Path, secrets: &SecretFile) -> Result<()> {
    let json = serde_json::to_vec_pretty(secrets)
        .map_err(|e| Error::Config(format!("serialising secrets: {e}")))?;
    write_private(&secrets_path(base), &json)
}

/// Write a file that ends up 0600 whether or not it was already there.
///
/// Both halves are needed: `OpenOptions::mode` only applies to a file this call
/// creates, and `set_permissions` only helps because it runs after the open —
/// so a file that already existed with looser permissions is tightened, and a
/// new one is never briefly readable.
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(FILE_MODE);

    let mut f = opts.open(path).map_err(|e| io_err(path, "open", e))?;
    #[cfg(unix)]
    f.set_permissions(fs::Permissions::from_mode(FILE_MODE))
        .map_err(|e| io_err(path, "set permissions on", e))?;
    f.write_all(data).map_err(|e| io_err(path, "write", e))?;
    f.flush().map_err(|e| io_err(path, "flush", e))
}

fn read_opt(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_err(path, "read", e)),
    }
}

fn io_err(path: &Path, what: &str, e: std::io::Error) -> Error {
    Error::Config(format!("could not {what} {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Where settings and known_hosts live has to resolve on the machine the
    /// test is running on, whichever that is.
    ///
    /// This is the test that was missing. The first version looked only at
    /// XDG_CONFIG_HOME and HOME — neither of which Windows sets — so every
    /// command that touched a profile died there with an error naming two
    /// variables that platform has never had. It passed CI the whole time,
    /// because CI is Linux.
    #[test]
    fn the_config_directory_resolves_on_this_platform() {
        let dir = default_config_dir().expect("no config directory on this platform");
        assert!(dir.is_absolute(), "not absolute: {}", dir.display());
        assert!(dir.ends_with("awg-tool"), "{}", dir.display());

        let kh = crate::ssh::default_known_hosts_path().expect("no known_hosts path");
        assert!(kh.ends_with("known_hosts"), "{}", kh.display());
    }

    #[test]
    fn a_home_is_found_under_either_platforms_variable() {
        assert!(
            home_dir().is_some(),
            "no home from HOME or USERPROFILE — one of them is always set"
        );
    }

    /// A scratch directory that is deliberately *not* created up front, so the
    /// missing-directory path is what the tests exercise by default. Nothing
    /// here touches the real `$HOME`.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            static SEQ: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "awg-profile-{tag}-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&p);
            Self(p)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sample() -> Profile {
        Profile {
            name: "prod".into(),
            host: "vpn.example.org".into(),
            port: 2222,
            user: "deploy".into(),
            auth: Auth::KeyWithPassphrase {
                path: "/home/u/.ssh/id_ed25519".into(),
            },
            sudo_required: true,
        }
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// An externally tagged enum puts the *variant name* where an object key
    /// goes. A discriminator is not somewhere a value can hide, so the scans
    /// below look past it rather than tripping over `key_with_passphrase`.
    const VARIANT_TAGS: [&str; 2] = ["key", "key_with_passphrase"];

    /// Every object key anywhere in `v` that is a field rather than a variant
    /// tag, however deep.
    fn all_keys(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, inner) in m {
                    if !VARIANT_TAGS.contains(&k.as_str()) {
                        out.push(k.clone());
                    }
                    all_keys(inner, out);
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|i| all_keys(i, out)),
            _ => {}
        }
    }

    #[test]
    fn a_saved_profile_comes_back_unchanged() {
        let s = Scratch::new("roundtrip");
        let p = sample();
        save(s.path(), &p, None, false).unwrap();
        assert_eq!(load_all(s.path()).unwrap(), vec![p.clone()]);
        assert_eq!(get_by_name(s.path(), "prod").unwrap(), Some(p));
    }

    #[test]
    fn every_auth_variant_survives_the_round_trip() {
        let s = Scratch::new("variants");
        let auths = [
            Auth::Password,
            Auth::Key {
                path: "/k/id_rsa".into(),
            },
            Auth::KeyWithPassphrase {
                path: "/k/id_ed25519".into(),
            },
            Auth::Agent,
        ];
        for (i, a) in auths.iter().enumerate() {
            let mut p = Profile::new(format!("p{i}"), "h", "u");
            p.auth = a.clone();
            save(s.path(), &p, None, false).unwrap();
        }
        let back = load_all(s.path()).unwrap();
        assert_eq!(back.len(), 4);
        for (a, p) in auths.iter().zip(&back) {
            assert_eq!(&p.auth, a);
        }
    }

    #[test]
    fn the_config_directory_is_created_private_when_it_is_missing() {
        let s = Scratch::new("mkdir");
        assert!(!s.path().exists());
        save(s.path(), &sample(), None, false).unwrap();
        assert!(s.path().is_dir());
        #[cfg(unix)]
        assert_eq!(mode_of(s.path()), 0o700);
    }

    #[test]
    fn a_password_is_written_only_when_save_password_is_true() {
        let s = Scratch::new("optin");
        save(s.path(), &sample(), Some("hunter2"), false).unwrap();
        assert!(!secrets_path(s.path()).exists());
        assert_eq!(load_password(s.path(), "prod").unwrap(), None);

        save(s.path(), &sample(), Some("hunter2"), true).unwrap();
        assert_eq!(
            load_password(s.path(), "prod").unwrap().as_deref(),
            Some("hunter2")
        );
    }

    #[test]
    fn asking_to_save_a_password_without_one_is_refused_and_changes_nothing() {
        let s = Scratch::new("nopw");
        assert!(save(s.path(), &sample(), None, true).is_err());
        assert!(load_all(s.path()).unwrap().is_empty());
        assert!(!secrets_path(s.path()).exists());
    }

    #[test]
    fn a_password_never_appears_in_profiles_json() {
        let s = Scratch::new("nopwfile");
        save(s.path(), &sample(), Some("s3cret-pw"), true).unwrap();

        let text = fs::read_to_string(profiles_path(s.path())).unwrap();
        assert!(!text.contains("s3cret-pw"));

        let mut keys = Vec::new();
        all_keys(&serde_json::from_str(&text).unwrap(), &mut keys);
        for k in &keys {
            let k = k.to_ascii_lowercase();
            assert!(
                !k.contains("password") && !k.contains("passphrase") && !k.contains("secret"),
                "profiles.json grew a {k} field"
            );
        }
        // ...and it did go somewhere, so the test is not passing vacuously.
        assert!(
            fs::read_to_string(secrets_path(s.path()))
                .unwrap()
                .contains("s3cret-pw")
        );
    }

    #[cfg(unix)]
    #[test]
    fn secrets_json_is_readable_only_by_its_owner() {
        let s = Scratch::new("mode");
        save(s.path(), &sample(), Some("pw"), true).unwrap();
        assert_eq!(mode_of(&secrets_path(s.path())), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn a_pre_existing_world_readable_secrets_file_is_tightened_on_write() {
        let s = Scratch::new("tighten");
        ensure_config_dir(s.path()).unwrap();
        fs::write(secrets_path(s.path()), b"{}").unwrap();
        fs::set_permissions(secrets_path(s.path()), fs::Permissions::from_mode(0o644)).unwrap();

        store_password(s.path(), "prod", "pw").unwrap();
        assert_eq!(mode_of(&secrets_path(s.path())), 0o600);
    }

    #[test]
    fn a_key_passphrase_has_no_field_to_be_stored_in() {
        // The serialised form of the one variant that involves a passphrase is
        // the key path and nothing else; there is no field to put it in.
        let v = serde_json::to_value(Auth::KeyWithPassphrase {
            path: "/k/id_ed25519".into(),
        })
        .unwrap();
        let inner = v.get("key_with_passphrase").expect("externally tagged");
        let fields: Vec<&String> = inner.as_object().unwrap().keys().collect();
        assert_eq!(fields, vec!["path"]);

        let mut keys = Vec::new();
        all_keys(&serde_json::to_value(sample()).unwrap(), &mut keys);
        assert!(!keys.iter().any(|k| k.to_ascii_lowercase().contains("pass")));
    }

    #[test]
    fn a_profiles_file_carrying_a_passphrase_is_refused_rather_than_ignored() {
        let s = Scratch::new("denied");
        ensure_config_dir(s.path()).unwrap();
        // Exactly what a well-meaning "improvement" elsewhere would write.
        fs::write(
            profiles_path(s.path()),
            br#"{"profiles":[{"name":"p","host":"h","port":22,"user":"u",
                 "auth":{"key_with_passphrase":{"path":"/k","passphrase":"letmein"}},
                 "sudo_required":false}]}"#,
        )
        .unwrap();
        let err = load_all(s.path()).unwrap_err();
        assert!(matches!(err, Error::Config(_)), "got {err:?}");
    }

    #[test]
    fn a_profiles_file_carrying_a_password_is_refused_rather_than_ignored() {
        let s = Scratch::new("denied2");
        ensure_config_dir(s.path()).unwrap();
        fs::write(
            profiles_path(s.path()),
            br#"{"profiles":[{"name":"p","host":"h","user":"u","auth":"agent",
                 "password":"letmein"}]}"#,
        )
        .unwrap();
        assert!(load_all(s.path()).is_err());
    }

    #[test]
    fn removing_a_profile_takes_its_saved_password_with_it() {
        let s = Scratch::new("remove");
        save(s.path(), &sample(), Some("pw"), true).unwrap();
        assert!(remove(s.path(), "prod").unwrap());
        assert!(load_all(s.path()).unwrap().is_empty());
        assert_eq!(load_password(s.path(), "prod").unwrap(), None);
        assert!(
            !fs::read_to_string(secrets_path(s.path()))
                .unwrap()
                .contains("pw")
        );
    }

    #[test]
    fn removing_a_name_that_is_not_there_reports_so() {
        let s = Scratch::new("remove-miss");
        save(s.path(), &sample(), None, false).unwrap();
        assert!(!remove(s.path(), "staging").unwrap());
        assert_eq!(load_all(s.path()).unwrap().len(), 1);
    }

    #[test]
    fn get_by_name_returns_none_for_a_name_that_was_never_saved() {
        let s = Scratch::new("miss");
        save(s.path(), &sample(), None, false).unwrap();
        assert_eq!(get_by_name(s.path(), "nope").unwrap(), None);
    }

    #[test]
    fn a_fresh_machine_has_no_profiles_and_that_is_not_an_error() {
        let s = Scratch::new("fresh");
        assert!(load_all(s.path()).unwrap().is_empty());
        assert_eq!(get_by_name(s.path(), "anything").unwrap(), None);
        assert_eq!(load_password(s.path(), "anything").unwrap(), None);
        assert!(!remove(s.path(), "anything").unwrap());
    }

    #[test]
    fn saving_the_same_name_twice_replaces_instead_of_duplicating() {
        let s = Scratch::new("replace");
        save(s.path(), &sample(), None, false).unwrap();
        let mut edited = sample();
        edited.host = "moved.example.org".into();
        save(s.path(), &edited, None, false).unwrap();

        let all = load_all(s.path()).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].host, "moved.example.org");
    }

    #[test]
    fn turning_save_password_off_forgets_the_one_already_stored() {
        let s = Scratch::new("forget");
        save(s.path(), &sample(), Some("pw"), true).unwrap();
        save(s.path(), &sample(), Some("pw"), false).unwrap();
        assert_eq!(load_password(s.path(), "prod").unwrap(), None);
    }

    #[test]
    fn forget_password_reports_whether_there_was_one() {
        let s = Scratch::new("forget2");
        assert!(!forget_password(s.path(), "prod").unwrap());
        store_password(s.path(), "prod", "pw").unwrap();
        assert!(forget_password(s.path(), "prod").unwrap());
    }

    #[test]
    fn one_profiles_password_is_not_another_profiles_password() {
        let s = Scratch::new("two");
        let mut a = Profile::new("a", "ha", "u");
        a.auth = Auth::Password;
        let mut b = Profile::new("b", "hb", "u");
        b.auth = Auth::Password;
        save(s.path(), &a, Some("pw-a"), true).unwrap();
        save(s.path(), &b, Some("pw-b"), true).unwrap();

        assert_eq!(
            load_password(s.path(), "a").unwrap().as_deref(),
            Some("pw-a")
        );
        assert_eq!(
            load_password(s.path(), "b").unwrap().as_deref(),
            Some("pw-b")
        );
        remove(s.path(), "a").unwrap();
        assert_eq!(
            load_password(s.path(), "b").unwrap().as_deref(),
            Some("pw-b")
        );
    }

    #[test]
    fn an_omitted_port_reads_back_as_22() {
        let s = Scratch::new("port");
        ensure_config_dir(s.path()).unwrap();
        fs::write(
            profiles_path(s.path()),
            br#"{"profiles":[{"name":"p","host":"h","user":"u","auth":"agent"}]}"#,
        )
        .unwrap();
        let all = load_all(s.path()).unwrap();
        assert_eq!(all[0].port, DEFAULT_PORT);
        assert!(!all[0].sudo_required);
    }

    #[test]
    fn an_unnamed_profile_is_refused() {
        let s = Scratch::new("noname");
        let mut p = sample();
        p.name = "   ".into();
        assert!(save(s.path(), &p, None, false).is_err());
    }

    #[test]
    fn only_password_and_passphrase_auth_ask_for_a_secret() {
        assert!(Auth::Password.needs_secret());
        assert!(Auth::KeyWithPassphrase { path: "/k".into() }.needs_secret());
        assert!(!Auth::Key { path: "/k".into() }.needs_secret());
        assert!(!Auth::Agent.needs_secret());
    }
}
