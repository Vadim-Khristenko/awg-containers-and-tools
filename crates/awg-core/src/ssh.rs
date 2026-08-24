//! SSH transport: reach a [`Profile`], run a command, and never guess about a
//! host key.
//!
//! The unknown-host case is the whole reason this module is not four lines
//! around `ssh2`. This tool deploys VPNs — the one thing a user is trusting it
//! to get right is *which machine* the keys end up on. So an unrecognised host
//! key is an error ([`Error::UnknownHostKey`]) that carries the fingerprint, and
//! the only thing that ever writes to `known_hosts` is
//! [`accept_new_host_key`], which the caller reaches for after showing that
//! fingerprint to a human. The intended sequence is:
//!
//! ```text
//! connect(..)  ->  Err(UnknownHostKey { fingerprint, .. })
//!              ->  show the fingerprint, ask
//!              ->  fetch_host_key(..) + accept_new_host_key(..)
//!              ->  connect(..)  ->  Ok
//! ```
//!
//! Everything except the socket itself — host key matching, `known_hosts`
//! parsing, command construction, which secret goes where — is a pure function
//! over text, because that is the part that has to be right and the part a test
//! can actually reach without a server.

use std::fs;
use std::io::{Read as _, Write as _};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};

use crate::profile::{Auth, Profile};
use crate::{Error, Result};

pub use ssh2::Session;

/// A handshake that has not finished by now is not going to, and a hung deploy
/// is worse than a failed one.
const TIMEOUT: Duration = Duration::from_secs(20);

/// How long a *command* may take, which is a different question entirely.
///
/// Twenty seconds is right for a handshake and hopelessly wrong for the work:
/// `apt-get install docker.io` on a fresh machine runs for minutes, and pulling
/// an image over a thin link longer still. Leaving the connect timeout in force
/// for execution meant the very first useful thing the tool does — installing
/// what the target is missing — could never finish. It failed with "Timed out
/// waiting on socket" after twenty seconds, while apt carried on working on the
/// far side, so the machine was left half-changed with no record of it.
///
/// Still bounded, because a command that has hung for half an hour is hung.
const EXEC_TIMEOUT: Duration = Duration::from_secs(1800);

/// Run `f` with the session's timeout widened to suit a long command, and put
/// the connect timeout back afterwards however it returns.
fn with_exec_timeout<T>(sess: &Session, f: impl FnOnce() -> T) -> T {
    sess.set_timeout(EXEC_TIMEOUT.as_millis() as u32);
    let out = f();
    sess.set_timeout(TIMEOUT.as_millis() as u32);
    out
}

#[cfg(unix)]
const DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

// ---------------------------------------------------------------- known_hosts

/// What `known_hosts` has to say about a key the server just presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyStatus {
    Trusted,
    /// No line mentions this host at all — first contact.
    Unknown,
    /// The host is listed, with a different key.
    Mismatch,
    /// Listed under `@revoked`: known, and known to be bad.
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Marker {
    CertAuthority,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostField {
    /// Comma-separated patterns, possibly with `*`, `?` and leading `!`.
    Patterns(Vec<String>),
    /// The `|1|salt|hash` form written by `ssh-keygen -H`.
    Hashed { salt: Vec<u8>, hash: Vec<u8> },
}

/// One usable line of `known_hosts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownHost {
    marker: Option<Marker>,
    hosts: HostField,
    /// Algorithm name as written in the file, e.g. `ssh-ed25519`.
    pub key_type: String,
    /// The key in SSH wire format, i.e. the base64 column decoded.
    pub key: Vec<u8>,
}

impl KnownHost {
    /// Whether this line covers `host` on `port`.
    ///
    /// Both spellings are tried, which is what OpenSSH does: a bare name covers
    /// the host on any port, because entries written before port qualification
    /// existed look like that and calling those hosts unknown would re-ask a
    /// question the user already answered. `[name]:port` is the narrower form
    /// and only covers that port.
    fn matches(&self, host: &str, port: u16) -> bool {
        let host = host.to_ascii_lowercase();
        let candidates = [host.clone(), format!("[{host}]:{port}")];
        match &self.hosts {
            HostField::Hashed { salt, hash } => candidates
                .iter()
                .any(|c| sha1::hmac(salt, c.as_bytes()).as_slice() == hash.as_slice()),
            HostField::Patterns(pats) => {
                let mut hit = false;
                for pat in pats {
                    match pat.strip_prefix('!') {
                        // A negated pattern vetoes the whole line, whatever else
                        // on it matched.
                        Some(neg) => {
                            if candidates.iter().any(|c| glob_match(neg, c)) {
                                return false;
                            }
                        }
                        None => hit |= candidates.iter().any(|c| glob_match(pat, c)),
                    }
                }
                hit
            }
        }
    }
}

/// `*` and `?` only — `known_hosts` has no character classes.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_ascii_lowercase().chars().collect();
    let t: Vec<char> = text.to_ascii_lowercase().chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    // Position to resume from if the `*` we last saw turns out to be too greedy.
    let (mut star, mut resume) = (None, 0usize);

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            resume = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            resume += 1;
            ti = resume;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// Parse the text of a `known_hosts` file.
///
/// A line that cannot be understood is skipped rather than fatal: the effect of
/// dropping one is that its host reads as unknown, which stops and asks — the
/// safe direction. Refusing to parse the file at all would instead lock the user
/// out of every host in it.
pub fn parse_known_hosts(text: &str) -> Vec<KnownHost> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(first) = fields.next() else { continue };

        let (marker, host_field) = match first {
            "@cert-authority" => (Some(Marker::CertAuthority), fields.next()),
            "@revoked" => (Some(Marker::Revoked), fields.next()),
            _ => (None, Some(first)),
        };
        let (Some(host_field), Some(key_type), Some(key_b64)) =
            (host_field, fields.next(), fields.next())
        else {
            continue;
        };
        let Ok(key) = STANDARD.decode(key_b64) else {
            continue;
        };
        let Some(hosts) = parse_host_field(host_field) else {
            continue;
        };

        out.push(KnownHost {
            marker,
            hosts,
            key_type: key_type.to_string(),
            key,
        });
    }
    out
}

fn parse_host_field(field: &str) -> Option<HostField> {
    if let Some(rest) = field.strip_prefix("|1|") {
        let (salt, hash) = rest.split_once('|')?;
        return Some(HostField::Hashed {
            salt: STANDARD.decode(salt).ok()?,
            hash: STANDARD.decode(hash).ok()?,
        });
    }
    // `|` introduces a hash type; anything other than 1 is one we cannot check.
    if field.starts_with('|') {
        return None;
    }
    Some(HostField::Patterns(
        field.split(',').map(str::to_string).collect(),
    ))
}

/// `~/.ssh/known_hosts`.
pub fn default_known_hosts_path() -> Result<PathBuf> {
    // `~/.ssh/known_hosts` on both kinds of system: Windows OpenSSH uses
    // %USERPROFILE%\.ssh too, so the file is shared with whatever ssh client
    // the user already trusts hosts with.
    let home = crate::profile::home_dir().ok_or_else(|| {
        Error::Ssh("no home directory: neither HOME nor USERPROFILE is set".into())
    })?;
    Ok(home.join(".ssh").join("known_hosts"))
}

/// Read and parse `known_hosts`.
///
/// A file that is not there means nothing has been trusted yet, which is a
/// normal state and not an error — every host then comes back [`Unknown`] and
/// gets asked about.
///
/// [`Unknown`]: HostKeyStatus::Unknown
pub fn load_known_hosts(path: &Path) -> Result<Vec<KnownHost>> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(parse_known_hosts(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(Error::Ssh(format!(
            "could not read {}: {e}",
            path.display()
        ))),
    }
}

/// Decide whether `key` is the key already trusted for this host.
pub fn check_host_key(entries: &[KnownHost], host: &str, port: u16, key: &[u8]) -> HostKeyStatus {
    let relevant: Vec<&KnownHost> = entries.iter().filter(|e| e.matches(host, port)).collect();

    // Revocation is checked first so that a key listed both ways still loses.
    if relevant
        .iter()
        .any(|e| e.marker == Some(Marker::Revoked) && e.key == key)
    {
        return HostKeyStatus::Revoked;
    }

    // A `@cert-authority` line authorises certificates signed by that CA, not
    // bare host keys, so it neither trusts this key nor counts as knowing the
    // host — treating it as either would be a wrong answer in both directions.
    let plain: Vec<&&KnownHost> = relevant.iter().filter(|e| e.marker.is_none()).collect();

    if plain.iter().any(|e| e.key == key) {
        HostKeyStatus::Trusted
    } else if plain.is_empty() {
        HostKeyStatus::Unknown
    } else {
        HostKeyStatus::Mismatch
    }
}

/// The wire encoding of an SSH public key begins with its own algorithm name as
/// a length-prefixed string, so the type column of a `known_hosts` line can be
/// read out of the key itself instead of being passed alongside it and trusted
/// to match.
pub fn key_type_from_blob(key: &[u8]) -> Option<String> {
    let len = u32::from_be_bytes(key.get(..4)?.try_into().ok()?) as usize;
    // Longest real algorithm name is well under this; the bound stops a bogus
    // length from turning into a huge allocation.
    if len == 0 || len > 64 {
        return None;
    }
    let name = key.get(4..4 + len)?;
    if !name
        .iter()
        .all(|b| b.is_ascii_graphic() && *b != b' ' && *b != b'#')
    {
        return None;
    }
    Some(String::from_utf8_lossy(name).into_owned())
}

/// The spelling OpenSSH uses for a host in `known_hosts`.
fn host_spec(host: &str, port: u16) -> String {
    if port == crate::profile::DEFAULT_PORT {
        host.to_ascii_lowercase()
    } else {
        format!("[{}]:{port}", host.to_ascii_lowercase())
    }
}

/// Write a host key into `known_hosts`.
///
/// Deliberately not called from [`connect`]. Trusting a key is a decision a
/// person makes after looking at a fingerprint; nothing in this module makes it
/// on their behalf.
pub fn accept_new_host_key(path: &Path, host: &str, port: u16, key: &[u8]) -> Result<()> {
    let key_type = key_type_from_blob(key)
        .ok_or_else(|| Error::Ssh("host key is not in SSH wire format".into()))?;

    if let Some(dir) = path.parent()
        && !dir.as_os_str().is_empty()
        && !dir.is_dir()
    {
        fs::create_dir_all(dir)
            .map_err(|e| Error::Ssh(format!("could not create {}: {e}", dir.display())))?;
        // create_dir_all goes through the umask, so this is what actually
        // makes ~/.ssh private.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(dir, fs::Permissions::from_mode(DIR_MODE))
                .map_err(|e| Error::Ssh(format!("could not secure {}: {e}", dir.display())))?;
        }
    }

    let line = format!(
        "{} {key_type} {}\n",
        host_spec(host, port),
        STANDARD.encode(key)
    );

    let mut opts = fs::OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(FILE_MODE);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| Error::Ssh(format!("could not open {}: {e}", path.display())))?;
    f.write_all(line.as_bytes())
        .map_err(|e| Error::Ssh(format!("could not write {}: {e}", path.display())))
}

// ---------------------------------------------------------------------- auth

/// Check that the profile and the secret the caller supplied fit together.
///
/// Runs before a socket is opened so that "you did not give me a passphrase"
/// arrives immediately rather than as an authentication failure twenty seconds
/// and one TCP handshake later.
pub fn check_auth(profile: &Profile, secret: Option<&str>) -> Result<()> {
    let have_secret = secret.is_some_and(|s| !s.is_empty());
    match &profile.auth {
        Auth::Password if !have_secret => Err(Error::Ssh(format!(
            "{} uses password auth but no password was given",
            profile.name
        ))),
        Auth::KeyWithPassphrase { path } => {
            if !have_secret {
                return Err(Error::Ssh(format!(
                    "{} uses a passphrase-protected key but no passphrase was given",
                    profile.name
                )));
            }
            require_key_file(path)
        }
        Auth::Key { path } => require_key_file(path),
        _ => Ok(()),
    }
}

fn require_key_file(path: &Path) -> Result<()> {
    if path.is_file() {
        Ok(())
    } else {
        Err(Error::Ssh(format!("no key file at {}", path.display())))
    }
}

/// The passphrase `libssh2` gets for this profile.
///
/// `Some` only for [`Auth::KeyWithPassphrase`]: for every other method the
/// secret in hand is a login or `sudo` password, and feeding one to a key file
/// as if it were a passphrase turns a wrong-password error into an unreadable
/// -key error.
fn key_passphrase<'a>(auth: &Auth, secret: Option<&'a str>) -> Option<&'a str> {
    match auth {
        Auth::KeyWithPassphrase { .. } => secret.filter(|s| !s.is_empty()),
        _ => None,
    }
}

// ------------------------------------------------------------------- session

/// The host key a server presented, in the two forms a caller needs: one to
/// show a human, one to write down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKey {
    pub blob: Vec<u8>,
    pub key_type: String,
    /// `SHA256:...`, byte-for-byte what `ssh-keygen -lf` prints, so it can be
    /// compared against out-of-band output without conversion.
    pub fingerprint: String,
}

/// Open a session: TCP, handshake, host key check, authentication.
pub fn connect(profile: &Profile, secret: Option<&str>) -> Result<Session> {
    connect_with(profile, secret, &default_known_hosts_path()?)
}

/// [`connect`], against a specific `known_hosts` file.
pub fn connect_with(
    profile: &Profile,
    secret: Option<&str>,
    known_hosts: &Path,
) -> Result<Session> {
    check_auth(profile, secret)?;
    let sess = handshake(profile)?;

    let (key, fingerprint) = presented_key(&sess)?;
    match check_host_key(
        &load_known_hosts(known_hosts)?,
        &profile.host,
        profile.port,
        &key,
    ) {
        HostKeyStatus::Trusted => {}
        HostKeyStatus::Unknown => {
            return Err(Error::UnknownHostKey {
                host: profile.host.clone(),
                fingerprint,
            });
        }
        HostKeyStatus::Mismatch => {
            return Err(Error::HostKeyMismatch {
                host: profile.host.clone(),
                fingerprint,
            });
        }
        HostKeyStatus::Revoked => {
            return Err(Error::Ssh(format!(
                "the host key for {} is marked @revoked in {} — {fingerprint}",
                profile.host,
                known_hosts.display()
            )));
        }
    }

    authenticate(&sess, profile, secret)?;
    if !sess.authenticated() {
        return Err(Error::Ssh(format!(
            "server accepted no credentials for {}",
            profile.user
        )));
    }
    Ok(sess)
}

/// Handshake only, to read the host key of a server we do not trust yet.
///
/// No authentication happens here: nothing secret is sent to a machine whose
/// identity has not been confirmed.
pub fn fetch_host_key(profile: &Profile) -> Result<HostKey> {
    let sess = handshake(profile)?;
    let (blob, fingerprint) = presented_key(&sess)?;
    let key_type = key_type_from_blob(&blob)
        .ok_or_else(|| Error::Ssh("host key is not in SSH wire format".into()))?;
    Ok(HostKey {
        blob,
        key_type,
        fingerprint,
    })
}

fn handshake(profile: &Profile) -> Result<Session> {
    let addr = (profile.host.as_str(), profile.port)
        .to_socket_addrs()
        .map_err(|e| Error::Ssh(format!("cannot resolve {}: {e}", profile.host)))?
        .next()
        .ok_or_else(|| Error::Ssh(format!("{} resolved to no addresses", profile.host)))?;

    let tcp = TcpStream::connect_timeout(&addr, TIMEOUT)
        .map_err(|e| Error::Ssh(format!("cannot reach {addr}: {e}")))?;

    let mut sess = Session::new().map_err(|e| Error::Ssh(e.to_string()))?;
    // Applies to the SSH protocol reads, which is what actually hangs; the
    // TcpStream timeout above only covers the connect.
    sess.set_timeout(TIMEOUT.as_millis() as u32);
    sess.set_tcp_stream(tcp);
    sess.handshake()
        .map_err(|e| Error::Ssh(format!("handshake with {addr} failed: {e}")))?;
    Ok(sess)
}

fn presented_key(sess: &Session) -> Result<(Vec<u8>, String)> {
    let (key, _) = sess
        .host_key()
        .ok_or_else(|| Error::Ssh("server presented no host key".into()))?;
    let fingerprint = match sess.host_key_hash(ssh2::HashType::Sha256) {
        Some(h) => format!("SHA256:{}", STANDARD_NO_PAD.encode(h)),
        None => "SHA256:<unavailable>".into(),
    };
    Ok((key.to_vec(), fingerprint))
}

fn authenticate(sess: &Session, profile: &Profile, secret: Option<&str>) -> Result<()> {
    let user = &profile.user;
    let r = match &profile.auth {
        Auth::Password => sess.userauth_password(user, secret.unwrap_or_default()),
        Auth::Agent => sess.userauth_agent(user),
        Auth::Key { path } | Auth::KeyWithPassphrase { path } => {
            sess.userauth_pubkey_file(user, None, path, key_passphrase(&profile.auth, secret))
        }
    };
    r.map_err(|e| {
        Error::Ssh(format!(
            "{} auth as {user} failed: {e}",
            profile.auth.label()
        ))
    })
}

// ------------------------------------------------------------------ commands

/// Run a command, returning `(stdout, stderr, exit code)`.
///
/// A non-zero exit code is data, not an error: callers routinely probe with
/// commands that are expected to fail.
pub fn exec(sess: &Session, cmd: &str) -> Result<(String, String, i32)> {
    with_exec_timeout(sess, || {
        let mut ch = sess
            .channel_session()
            .map_err(|e| Error::Ssh(format!("could not open a channel: {e}")))?;
        ch.exec(cmd)
            .map_err(|e| Error::Ssh(format!("could not run `{cmd}`: {e}")))?;
        finish(ch, cmd)
    })
}

/// Run a command under `sudo`, feeding it the password over stdin.
pub fn exec_sudo(
    sess: &Session,
    cmd: &str,
    sudo_password: Option<&str>,
) -> Result<(String, String, i32)> {
    let wrapped = sudo_command(cmd);
    with_exec_timeout(sess, || {
        let mut ch = sess
            .channel_session()
            .map_err(|e| Error::Ssh(format!("could not open a channel: {e}")))?;
        ch.exec(&wrapped)
            .map_err(|e| Error::Ssh(format!("could not run `{wrapped}`: {e}")))?;

        if let Some(pw) = sudo_password {
            ch.write_all(pw.as_bytes())
                .and_then(|()| ch.write_all(b"\n"))
                .and_then(|()| ch.flush())
                .map_err(|e| Error::Ssh(format!("could not send the sudo password: {e}")))?;
        }
        // sudo reads stdin until EOF; without this it waits for input that is
        // never coming and the command hangs until the timeout.
        ch.send_eof()
            .map_err(|e| Error::Ssh(format!("could not close stdin: {e}")))?;

        finish(ch, &wrapped)
    })
}

/// Build the `sudo` invocation.
///
/// `-S` makes sudo take the password from stdin, and `-p ''` blanks the prompt
/// so that the caller's stderr holds the command's own output rather than a
/// stray `[sudo] password for ...`. `bash -c` is there because the commands this
/// runs contain pipes and redirects that `sudo` alone would hand to the target
/// binary as arguments.
pub fn sudo_command(cmd: &str) -> String {
    format!("sudo -S -p '' bash -c {}", single_quote(cmd))
}

/// POSIX single-quoting: inside single quotes nothing is special, so the quote
/// itself is the only thing to deal with — end the string, escape one quote,
/// start it again.
fn single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn finish(mut ch: ssh2::Channel, cmd: &str) -> Result<(String, String, i32)> {
    let mut out = String::new();
    let mut err = String::new();
    ch.read_to_string(&mut out)
        .map_err(|e| Error::Ssh(format!("reading stdout of `{cmd}`: {e}")))?;
    ch.stderr()
        .read_to_string(&mut err)
        .map_err(|e| Error::Ssh(format!("reading stderr of `{cmd}`: {e}")))?;
    ch.wait_close()
        .map_err(|e| Error::Ssh(format!("closing `{cmd}`: {e}")))?;
    let code = ch
        .exit_status()
        .map_err(|e| Error::Ssh(format!("exit status of `{cmd}`: {e}")))?;
    Ok((out, err, code))
}

/// SHA-1 and HMAC-SHA1, needed for exactly one thing: recognising the hashed
/// form of `known_hosts` (`|1|salt|hash`), which is HMAC-SHA1 of the host name.
///
/// Hand-written rather than pulling in a hash crate for sixty lines. The reason
/// to believe it is the published test vectors in the module tests, not the
/// code being short.
mod sha1 {
    const BLOCK: usize = 64;

    pub fn digest(data: &[u8]) -> [u8; 20] {
        let mut h: [u32; 5] = [
            0x6745_2301,
            0xEFCD_AB89,
            0x98BA_DCFE,
            0x1032_5476,
            0xC3D2_E1F0,
        ];

        let mut msg = data.to_vec();
        let bits = (data.len() as u64).wrapping_mul(8);
        msg.push(0x80);
        while msg.len() % BLOCK != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bits.to_be_bytes());

        for block in msg.as_chunks::<BLOCK>().0 {
            let mut w = [0u32; 80];
            for (i, c) in block.as_chunks::<4>().0.iter().enumerate() {
                w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
            }
            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }

            let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
            for (i, wi) in w.iter().enumerate() {
                let (f, k) = match i {
                    0..20 => ((b & c) | (!b & d), 0x5A82_7999u32),
                    20..40 => (b ^ c ^ d, 0x6ED9_EBA1),
                    40..60 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                    _ => (b ^ c ^ d, 0xCA62_C1D6),
                };
                let t = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(*wi);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = t;
            }

            for (slot, v) in h.iter_mut().zip([a, b, c, d, e]) {
                *slot = slot.wrapping_add(v);
            }
        }

        let mut out = [0u8; 20];
        for (i, v) in h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
        }
        out
    }

    pub fn hmac(key: &[u8], msg: &[u8]) -> [u8; 20] {
        let mut k = [0u8; BLOCK];
        if key.len() > BLOCK {
            k[..20].copy_from_slice(&digest(key));
        } else {
            k[..key.len()].copy_from_slice(key);
        }

        let mut inner = Vec::with_capacity(BLOCK + msg.len());
        inner.extend(k.iter().map(|b| b ^ 0x36));
        inner.extend_from_slice(msg);

        let mut outer = Vec::with_capacity(BLOCK + 20);
        outer.extend(k.iter().map(|b| b ^ 0x5c));
        outer.extend_from_slice(&digest(&inner));
        digest(&outer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// An ed25519 host key generated by `ssh-keygen`, together with the exact
    /// lines `ssh-keygen -H` produced from it. Hashing is checked against those
    /// fixtures rather than against this module's own HMAC, so a wrong HMAC
    /// cannot agree with itself and pass.
    const KEY_B64: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIBKsB9arF79uiPHpW+0b0HAo1GG6hnSxO95AoLrgy7c7";
    const HOST: &str = "vaidserver.example";
    const HASHED_22: &str = "|1|Tuhdc60COXvmdNmHuiJNznps35g=|FjTAy2D0pZAjP4xQ4UiwL9L9/6A=";
    const HASHED_2222: &str = "|1|eYS5DLKSOWpJu0avd5moomUXKWk=|CiZ0kIyubSB0CoIBT8FQV5gcWBg=";

    fn key() -> Vec<u8> {
        STANDARD.decode(KEY_B64).unwrap()
    }

    fn other_key() -> Vec<u8> {
        let mut k = key();
        *k.last_mut().unwrap() ^= 0xff;
        k
    }

    fn line(hosts: &str) -> String {
        format!("{hosts} ssh-ed25519 {KEY_B64}\n")
    }

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            static SEQ: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "awg-ssh-{tag}-{}-{}",
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

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // ---- the hash the hashed entries rely on

    #[test]
    fn sha1_matches_the_published_vectors() {
        assert_eq!(
            hex(&sha1::digest(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            hex(&sha1::digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&sha1::digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        // Crosses a block boundary and exercises the length padding.
        assert_eq!(
            hex(&sha1::digest(&[b'a'; 1000])),
            "291e9a6c66994949b57ba5e650361e98fc36b1ba"
        );
    }

    #[test]
    fn hmac_sha1_matches_rfc_2202() {
        assert_eq!(
            hex(&sha1::hmac(&[0x0b; 20], b"Hi There")),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
        assert_eq!(
            hex(&sha1::hmac(b"Jefe", b"what do ya want for nothing?")),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
        // A key longer than the 64-byte block, so it gets hashed down first.
        assert_eq!(
            hex(&sha1::hmac(
                &[0xaa; 80],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        );
    }

    // ---- parsing

    #[test]
    fn a_plain_entry_is_trusted_for_its_own_host() {
        let e = parse_known_hosts(&line(HOST));
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].key_type, "ssh-ed25519");
        assert_eq!(check_host_key(&e, HOST, 22, &key()), HostKeyStatus::Trusted);
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let text = format!("# a comment\n\n   \n{}", line(HOST));
        let e = parse_known_hosts(&text);
        assert_eq!(e.len(), 1);
    }

    #[test]
    fn a_line_that_cannot_be_parsed_does_not_take_the_file_with_it() {
        let text = format!(
            "broken.example ssh-ed25519 not!valid!base64\ntruncated.example\n{}",
            line(HOST)
        );
        let e = parse_known_hosts(&text);
        assert_eq!(e.len(), 1);
        assert_eq!(check_host_key(&e, HOST, 22, &key()), HostKeyStatus::Trusted);
        // The unparseable host is simply not known, which is the safe direction.
        assert_eq!(
            check_host_key(&e, "broken.example", 22, &key()),
            HostKeyStatus::Unknown
        );
    }

    #[test]
    fn an_unsupported_hash_type_is_ignored_rather_than_guessed_at() {
        let e = parse_known_hosts(&line("|9|c2FsdA==|aGFzaA=="));
        assert!(e.is_empty());
    }

    #[test]
    fn a_comma_separated_entry_covers_every_name_on_it() {
        let e = parse_known_hosts(&line("alpha.example,beta.example,203.0.113.7"));
        for h in ["alpha.example", "beta.example", "203.0.113.7"] {
            assert_eq!(
                check_host_key(&e, h, 22, &key()),
                HostKeyStatus::Trusted,
                "{h}"
            );
        }
        assert_eq!(
            check_host_key(&e, "gamma.example", 22, &key()),
            HostKeyStatus::Unknown
        );
    }

    #[test]
    fn wildcards_match_and_a_negation_vetoes_the_line() {
        let e = parse_known_hosts(&line("*.example,!secret.example"));
        assert_eq!(
            check_host_key(&e, "any.example", 22, &key()),
            HostKeyStatus::Trusted
        );
        assert_eq!(
            check_host_key(&e, "secret.example", 22, &key()),
            HostKeyStatus::Unknown
        );
        assert_eq!(
            check_host_key(&e, "any.other", 22, &key()),
            HostKeyStatus::Unknown
        );
    }

    #[test]
    fn question_marks_match_exactly_one_character() {
        let e = parse_known_hosts(&line("host?.example"));
        assert_eq!(
            check_host_key(&e, "host1.example", 22, &key()),
            HostKeyStatus::Trusted
        );
        assert_eq!(
            check_host_key(&e, "host12.example", 22, &key()),
            HostKeyStatus::Unknown
        );
    }

    #[test]
    fn host_names_are_matched_case_insensitively() {
        let e = parse_known_hosts(&line(HOST));
        assert_eq!(
            check_host_key(&e, "VaidServer.Example", 22, &key()),
            HostKeyStatus::Trusted
        );
    }

    #[test]
    fn a_non_default_port_is_found_in_bracket_form() {
        let e = parse_known_hosts(&line("[vaidserver.example]:2222"));
        assert_eq!(
            check_host_key(&e, HOST, 2222, &key()),
            HostKeyStatus::Trusted
        );
        assert_eq!(check_host_key(&e, HOST, 22, &key()), HostKeyStatus::Unknown);
    }

    // ---- hashed entries, against ssh-keygen -H output

    #[test]
    fn a_hashed_entry_matches_the_host_it_was_made_from() {
        let e = parse_known_hosts(&line(HASHED_22));
        assert_eq!(check_host_key(&e, HOST, 22, &key()), HostKeyStatus::Trusted);
    }

    #[test]
    fn a_hashed_entry_for_a_non_default_port_matches_the_bracket_form() {
        let e = parse_known_hosts(&line(HASHED_2222));
        assert_eq!(
            check_host_key(&e, HOST, 2222, &key()),
            HostKeyStatus::Trusted
        );
    }

    #[test]
    fn a_hashed_entry_does_not_match_a_different_host() {
        let e = parse_known_hosts(&line(HASHED_22));
        assert_eq!(
            check_host_key(&e, "elsewhere.example", 22, &key()),
            HostKeyStatus::Unknown
        );
        assert_eq!(
            check_host_key(&e, "vaidserver.example.org", 22, &key()),
            HostKeyStatus::Unknown
        );
    }

    #[test]
    fn a_key_written_down_for_the_default_port_still_counts_on_another_port() {
        // OpenSSH does the same: an entry predating port qualification is a bare
        // host name, and it would be wrong to start calling those hosts unknown
        // just because the connection is not on 22. The reverse does not hold —
        // see `a_non_default_port_is_found_in_bracket_form`.
        for e in [
            parse_known_hosts(&line(HOST)),
            parse_known_hosts(&line(HASHED_22)),
        ] {
            assert_eq!(
                check_host_key(&e, HOST, 2222, &key()),
                HostKeyStatus::Trusted
            );
        }
    }

    #[test]
    fn a_hashed_entry_still_notices_the_wrong_key() {
        let e = parse_known_hosts(&line(HASHED_22));
        assert_eq!(
            check_host_key(&e, HOST, 22, &other_key()),
            HostKeyStatus::Mismatch
        );
    }

    // ---- verdicts

    #[test]
    fn a_host_nobody_has_written_down_is_unknown_not_trusted() {
        let e = parse_known_hosts(&line("somewhere.else"));
        assert_eq!(check_host_key(&e, HOST, 22, &key()), HostKeyStatus::Unknown);
    }

    #[test]
    fn a_different_key_for_a_known_host_is_a_mismatch() {
        let e = parse_known_hosts(&line(HOST));
        assert_eq!(
            check_host_key(&e, HOST, 22, &other_key()),
            HostKeyStatus::Mismatch
        );
    }

    #[test]
    fn a_revoked_key_is_refused_even_though_it_is_written_down() {
        let text = format!("@revoked {}{}", line(HOST), line(HOST));
        let e = parse_known_hosts(&text);
        assert_eq!(check_host_key(&e, HOST, 22, &key()), HostKeyStatus::Revoked);
    }

    #[test]
    fn a_cert_authority_line_does_not_vouch_for_a_bare_host_key() {
        let e = parse_known_hosts(&format!("@cert-authority {}", line("*.example")));
        assert_eq!(check_host_key(&e, HOST, 22, &key()), HostKeyStatus::Unknown);
    }

    #[test]
    fn an_empty_store_trusts_nothing() {
        assert_eq!(
            check_host_key(&[], HOST, 22, &key()),
            HostKeyStatus::Unknown
        );
    }

    // ---- files

    #[test]
    fn a_missing_known_hosts_file_reads_as_nothing_trusted_yet() {
        let s = Scratch::new("missing");
        let path = s.path().join(".ssh").join("known_hosts");
        assert!(!path.exists());
        let e = load_known_hosts(&path).unwrap();
        assert!(e.is_empty());
        assert_eq!(check_host_key(&e, HOST, 22, &key()), HostKeyStatus::Unknown);
    }

    #[test]
    fn accepting_a_key_makes_the_host_trusted_next_time() {
        let s = Scratch::new("accept");
        let path = s.path().join(".ssh").join("known_hosts");
        assert_eq!(
            check_host_key(&load_known_hosts(&path).unwrap(), HOST, 22, &key()),
            HostKeyStatus::Unknown
        );

        accept_new_host_key(&path, HOST, 22, &key()).unwrap();
        assert_eq!(
            check_host_key(&load_known_hosts(&path).unwrap(), HOST, 22, &key()),
            HostKeyStatus::Trusted
        );
        // The type column comes from the key, not from a caller's claim.
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .starts_with(&format!("{HOST} ssh-ed25519 {KEY_B64}"))
        );
    }

    #[test]
    fn accepting_a_key_on_a_non_default_port_writes_the_bracket_form() {
        let s = Scratch::new("accept-port");
        let path = s.path().join("known_hosts");
        accept_new_host_key(&path, HOST, 2222, &key()).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("[vaidserver.example]:2222 "), "{text}");
        assert_eq!(
            check_host_key(&load_known_hosts(&path).unwrap(), HOST, 2222, &key()),
            HostKeyStatus::Trusted
        );
    }

    #[test]
    fn accepting_a_key_appends_and_leaves_earlier_hosts_alone() {
        let s = Scratch::new("append");
        let path = s.path().join("known_hosts");
        fs::create_dir_all(s.path()).unwrap();
        fs::write(&path, line("other.example")).unwrap();

        accept_new_host_key(&path, HOST, 22, &key()).unwrap();
        let e = load_known_hosts(&path).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(
            check_host_key(&e, "other.example", 22, &key()),
            HostKeyStatus::Trusted
        );
        assert_eq!(check_host_key(&e, HOST, 22, &key()), HostKeyStatus::Trusted);
    }

    #[cfg(unix)]
    #[test]
    fn accepting_a_key_creates_a_private_ssh_directory() {
        use std::os::unix::fs::PermissionsExt as _;
        let s = Scratch::new("perms");
        let dir = s.path().join(".ssh");
        accept_new_host_key(&dir.join("known_hosts"), HOST, 22, &key()).unwrap();

        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("known_hosts")), 0o600);
    }

    #[test]
    fn a_key_that_is_not_in_wire_format_is_refused_rather_than_written() {
        let s = Scratch::new("garbage");
        let path = s.path().join("known_hosts");
        assert!(accept_new_host_key(&path, HOST, 22, b"not a key").is_err());
        assert!(!path.exists());
    }

    // ---- key blobs

    #[test]
    fn the_algorithm_name_is_read_out_of_the_key_itself() {
        assert_eq!(key_type_from_blob(&key()).as_deref(), Some("ssh-ed25519"));
    }

    #[test]
    fn a_blob_that_is_not_a_key_yields_no_algorithm_name() {
        assert_eq!(key_type_from_blob(b""), None);
        assert_eq!(key_type_from_blob(b"\x00\x00\x00\x04ab"), None);
        assert_eq!(key_type_from_blob(&[0xff, 0xff, 0xff, 0xff, 0x41]), None);
        // A length that fits but names something with a space in it.
        assert_eq!(key_type_from_blob(b"\x00\x00\x00\x03a b"), None);
    }

    // ---- commands

    #[test]
    fn sudo_reads_the_password_from_stdin_with_no_prompt() {
        let c = sudo_command("id -u");
        assert!(c.starts_with("sudo -S -p '' bash -c "), "{c}");
        assert!(c.ends_with("'id -u'"), "{c}");
    }

    #[test]
    fn a_command_full_of_shell_metacharacters_survives_the_wrapper() {
        let c = sudo_command("echo $HOME > /tmp/x && cat /tmp/x | wc -l");
        assert_eq!(
            c,
            r"sudo -S -p '' bash -c 'echo $HOME > /tmp/x && cat /tmp/x | wc -l'"
        );
    }

    #[test]
    fn single_quotes_inside_a_command_are_escaped_not_dropped() {
        assert_eq!(single_quote("it's"), r"'it'\''s'");
        let c = sudo_command("awk '{print $1}' /etc/hostname");
        assert_eq!(
            c,
            r"sudo -S -p '' bash -c 'awk '\''{print $1}'\'' /etc/hostname'"
        );
        // Nothing outside the wrapper's own quoting is left unquoted.
        assert_eq!(c.matches('\'').count() % 2, 0);
    }

    // ---- auth selection

    fn profile_with(auth: Auth) -> Profile {
        let mut p = Profile::new("test", "vaidserver.example", "vai_prog");
        p.auth = auth;
        p
    }

    fn a_key_file(s: &Scratch) -> PathBuf {
        fs::create_dir_all(s.path()).unwrap();
        let p = s.path().join("id_ed25519");
        fs::write(&p, b"-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
        p
    }

    #[test]
    fn password_auth_without_a_password_is_refused_before_any_socket() {
        let p = profile_with(Auth::Password);
        assert!(check_auth(&p, None).is_err());
        assert!(check_auth(&p, Some("")).is_err());
        assert!(check_auth(&p, Some("pw")).is_ok());
    }

    #[test]
    fn key_auth_needs_the_key_file_to_actually_be_there() {
        let s = Scratch::new("keyfile");
        let missing = profile_with(Auth::Key {
            path: s.path().join("nope"),
        });
        assert!(check_auth(&missing, None).is_err());

        let present = profile_with(Auth::Key {
            path: a_key_file(&s),
        });
        assert!(check_auth(&present, None).is_ok());
    }

    #[test]
    fn a_passphrase_protected_key_needs_both_the_file_and_the_passphrase() {
        let s = Scratch::new("passphrase");
        let p = profile_with(Auth::KeyWithPassphrase {
            path: a_key_file(&s),
        });
        assert!(check_auth(&p, None).is_err());
        assert!(check_auth(&p, Some("")).is_err());
        assert!(check_auth(&p, Some("hunter2")).is_ok());
    }

    #[test]
    fn agent_auth_needs_nothing_at_all() {
        assert!(check_auth(&profile_with(Auth::Agent), None).is_ok());
    }

    #[test]
    fn only_a_passphrase_protected_key_is_handed_the_secret() {
        let secret = Some("hunter2");
        assert_eq!(
            key_passphrase(&Auth::KeyWithPassphrase { path: "/k".into() }, secret),
            Some("hunter2")
        );
        // A password meant for the login or for sudo must not be tried as a key
        // passphrase — the resulting error would point at the wrong thing.
        assert_eq!(
            key_passphrase(&Auth::Key { path: "/k".into() }, secret),
            None
        );
        assert_eq!(key_passphrase(&Auth::Password, secret), None);
        assert_eq!(key_passphrase(&Auth::Agent, secret), None);
        assert_eq!(
            key_passphrase(&Auth::KeyWithPassphrase { path: "/k".into() }, Some("")),
            None
        );
    }

    #[test]
    fn connect_rejects_a_bad_auth_combination_without_reaching_the_network() {
        // The host below is never resolved: check_auth fails first, which is the
        // point — the error names the missing password rather than the network.
        let s = Scratch::new("noconnect");
        let p = profile_with(Auth::Password);
        let Err(err) = connect_with(&p, None, &s.path().join("known_hosts")) else {
            panic!("a password profile with no password must not open a connection");
        };
        assert!(format!("{err}").contains("password"), "{err}");
    }
}
