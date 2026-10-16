//! A new obfuscation block for a running server.
//!
//! Rotation replaces everything both ends of a tunnel have to agree on (junk,
//! sizes, headers, chains, the 3.x keys) and leaves alone everything that is
//! the server's own: its key, its address, its port, its peers. Every client
//! then needs the same new block, which is why this is a deliberate act with a
//! dry run, a backup and a rollback rather than a setting.
//!
//! The rewrite has one definition, [`rotate_conf`]. On this machine the file
//! is rewritten with it directly. Over SSH the server's private key and its
//! peers' preshared keys must not travel, not even inside a command line that
//! `ps` on the server would show, so only the new block is sent and an awk
//! script doing the same rewrite runs next to the file; the result is read
//! back through the container and must match [`rotate_conf`] byte for byte, or
//! the backup goes back.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

use super::host::{Host, safe_name};
use super::{Container, health, inspect};
use crate::versions::{self, GenOptions, VersionedParams};
use crate::{Error, Result};

/// Every `[Interface]` key the two ends share, in `.conf` spelling.
const KEYS: [&str; 29] = [
    "Jc",
    "Jmin",
    "Jmax",
    "S1",
    "S2",
    "S3",
    "S4",
    "H1",
    "H2",
    "H3",
    "H4",
    "I1",
    "I2",
    "I3",
    "I4",
    "I5",
    "Itime",
    "J1",
    "J2",
    "J3",
    "HeaderProtectionKey",
    "ContentPaddingAddition",
    "RekeyAfterTime",
    "RekeyTimeout",
    "RejectAfterTime",
    "KeepaliveTimeout",
    "MaxHandshakeAttempts",
    "RandomTrailers",
    "DisableCookies",
];

pub fn is_obfuscation_key(key: &str) -> bool {
    KEYS.iter().any(|k| k.eq_ignore_ascii_case(key.trim()))
}

/// The comments [`VersionedParams::conf_lines`] writes into a block, which go
/// with it when it is replaced. Anybody else's comments stay.
fn is_block_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.strip_prefix('#')
        .map(|c| {
            let c = c.trim_start();
            c.starts_with("AmneziaWG ") || c.starts_with("I1-I5 ")
        })
        .unwrap_or(false)
}

fn key_of(line: &str) -> Option<&str> {
    let (k, _) = line.split_once('=')?;
    let k = k.trim();
    (!k.is_empty() && !k.starts_with('#')).then_some(k)
}

/// The config with its `[Interface]` obfuscation replaced by `block`.
///
/// The old keys and the block's own comments are dropped wherever they stood,
/// and the block goes at the end of the section, before any blank lines that
/// close it. Keep this and [`AWK_REWRITE`] the same algorithm: the SSH path
/// is checked against this one.
pub fn rotate_conf(conf: &str, block: &[String]) -> Result<String> {
    let mut out: Vec<String> = Vec::new();
    let mut held: Vec<String> = Vec::new();
    let (mut inside, mut done, mut seen) = (false, false, false);
    let flush = |out: &mut Vec<String>, held: &mut Vec<String>, inside: bool, done: &mut bool| {
        if inside && !*done {
            out.extend(block.iter().cloned());
            *done = true;
        }
        out.append(held);
    };
    for line in conf.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            flush(&mut out, &mut held, inside, &mut done);
            inside = t.eq_ignore_ascii_case("[interface]");
            seen |= inside;
            out.push(line.to_string());
            continue;
        }
        if inside && !done {
            if t.is_empty() {
                held.push(line.to_string());
                continue;
            }
            if is_block_comment(line) || key_of(line).is_some_and(is_obfuscation_key) {
                continue;
            }
        }
        out.append(&mut held);
        out.push(line.to_string());
    }
    flush(&mut out, &mut held, inside, &mut done);
    if !seen {
        return Err(Error::Config(
            "the config has no [Interface] section".into(),
        ));
    }
    let mut text = out.join("\n");
    text.push('\n');
    Ok(text)
}

/// The same rewrite for a POSIX awk, reading the new block from the file
/// named by `blk`.
pub const AWK_REWRITE: &str = r##"
function isob(k) {
    return tolower(k) ~ /^(jc|jmin|jmax|s[1-4]|h[1-4]|i[1-5]|itime|j[1-3]|headerprotectionkey|contentpaddingaddition|rekeyaftertime|rekeytimeout|rejectaftertime|keepalivetimeout|maxhandshakeattempts|randomtrailers|disablecookies)$/
}
function flush() {
    if (inside && !done) { while ((getline l < blk) > 0) print l; close(blk); done = 1 }
    for (i = 0; i < nheld; i++) print held[i]
    nheld = 0
}
{
    t = $0; sub(/^[ \t]+/, "", t); sub(/[ \t\r]+$/, "", t)
    if (substr(t, 1, 1) == "[") { flush(); inside = (tolower(t) == "[interface]"); print; next }
    if (inside && !done) {
        if (t == "") { held[nheld++] = $0; next }
        if (t ~ /^#[ \t]*(AmneziaWG |I1-I5 )/) next
        k = t
        if (index(k, "=") > 0 && substr(k, 1, 1) != "#") {
            sub(/[ \t]*=.*/, "", k)
            if (k != "" && isob(k)) next
        }
    }
    for (i = 0; i < nheld; i++) print held[i]
    nheld = 0
    print
}
END { flush() }
"##;

/// The obfuscation keys whose value differs between two configs, in
/// `.conf` spelling. Values are compared and never returned.
pub fn changed_keys(old: &str, new: &str) -> Vec<String> {
    let block = |conf: &str| -> Vec<(String, String)> {
        let mut inside = false;
        let mut out = Vec::new();
        for line in conf.lines() {
            let t = line.trim();
            if t.starts_with('[') {
                inside = t.eq_ignore_ascii_case("[interface]");
                continue;
            }
            if let (true, Some((k, v))) = (inside, t.split_once('='))
                && is_obfuscation_key(k)
            {
                out.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
            }
        }
        out
    };
    let (a, b) = (block(old), block(new));
    let mut keys: Vec<String> = Vec::new();
    for k in KEYS {
        let lk = k.to_ascii_lowercase();
        let va = a.iter().find(|(x, _)| *x == lk).map(|(_, v)| v);
        let vb = b.iter().find(|(x, _)| *x == lk).map(|(_, v)| v);
        if va != vb {
            keys.push(k.to_string());
        }
    }
    keys
}

/// A path that goes into a command: absolute, plain characters only.
fn safe_path(p: &str) -> Result<&str> {
    let ok = p.starts_with('/')
        && p.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'));
    if ok {
        Ok(p)
    } else {
        Err(Error::Config(format!(
            "{p:?} is not a path this tool will write to"
        )))
    }
}

/// A bind source as this machine names it: Docker Desktop reports what it
/// was given, which from Git Bash is `/c/...`, and from WSL
/// `/run/desktop/mnt/host/c/...`.
pub fn local_path(source: &str) -> String {
    if cfg!(windows) {
        let rest = source
            .strip_prefix("/run/desktop/mnt/host/")
            .or_else(|| source.strip_prefix('/'));
        if let Some(rest) = rest {
            let mut parts = rest.splitn(2, '/');
            if let (Some(drive), Some(tail)) = (parts.next(), parts.next())
                && drive.len() == 1
                && drive.chars().all(|c| c.is_ascii_alphabetic())
            {
                return format!("{}:/{tail}", drive.to_ascii_uppercase());
            }
        }
    }
    source.to_string()
}

/// Everything a rotation will do, worked out before anything is touched.
/// Not `Debug`: it holds the server's config, private key included.
pub struct RotationPlan {
    pub container: String,
    pub interface: String,
    /// The config inside the container.
    pub conf_path: String,
    /// The same file on the host.
    pub host_path: String,
    pub old_conf: String,
    pub new_conf: String,
    pub params: VersionedParams,
    pub changed: Vec<String>,
}

impl RotationPlan {
    /// What every client must put under `[Interface]` in place of its old
    /// obfuscation lines.
    pub fn client_block(&self) -> Vec<String> {
        self.params.conf_lines()
    }
}

/// Read the node's config and generate its replacement. Nothing is written.
pub fn plan(host: &Host, node: &Container, opts: &GenOptions) -> Result<RotationPlan> {
    let name = safe_name(&node.name)?.to_string();
    let version = node.generation.and_then(|g| g.awg()).ok_or_else(|| {
        Error::Config(format!(
            "{name} is not an AmneziaWG node, nothing to rotate"
        ))
    })?;
    if opts.version != version {
        return Err(Error::Config(format!(
            "{name} runs AWG {version}, and a {} block would not load there",
            opts.version
        )));
    }
    let ins = inspect(host, &name)?;
    let interface = ins.interface();
    let conf_path = ins
        .env
        .get("AWG_CONF")
        .cloned()
        .unwrap_or_else(|| format!("/etc/amnezia/awg/{interface}.conf"));
    safe_path(&conf_path)?;
    let host_path = ins.host_path_of(&conf_path).ok_or_else(|| {
        Error::Config(format!(
            "{conf_path} in {name} is not bind-mounted from the host, so there is no file to rewrite"
        ))
    })?;

    let (old_conf, err, code) = host.run_docker(&format!("docker exec {name} cat {conf_path}"))?;
    if code != 0 {
        return Err(Error::Config(format!(
            "reading {conf_path} in {name}: {}",
            err.trim()
        )));
    }
    let params = versions::generate(&mut crate::rng::SecureRng, opts)?;
    let new_conf = rotate_conf(&old_conf, &params.conf_lines())?;
    let report = crate::check::check(&new_conf, &Default::default());
    if let Some(f) = report
        .findings
        .iter()
        .find(|f| f.level == versions::Level::Error)
    {
        return Err(Error::Invariant(format!(
            "the rotated config would not load: {}: {}",
            f.field, f.message
        )));
    }
    let changed = changed_keys(&old_conf, &new_conf);
    Ok(RotationPlan {
        container: name,
        interface,
        conf_path,
        host_path,
        old_conf,
        new_conf,
        params,
        changed,
    })
}

/// How a rotation ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// The previous config, kept next to the file.
    pub backup: String,
    /// The node came back up with the new block.
    pub healthy: bool,
    /// It did not, and the previous config was put back.
    pub rolled_back: bool,
}

fn stamp() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .to_string()
}

/// The remote rewrite: back up, write the block to a private temp file,
/// rewrite next to the original and copy over it in place. In place, so a
/// file bind-mounted on its own keeps its inode and the container sees it.
pub fn remote_rewrite_command(host_path: &str, backup: &str, block: &[String]) -> Result<String> {
    let f = safe_path(host_path)?;
    let b = safe_path(backup)?;
    let mut text = block.join("\n");
    text.push('\n');
    let awk = AWK_REWRITE.replace('\'', "'\\''");
    Ok(format!(
        "set -e; umask 077; cp -p '{f}' '{b}'; \
         printf '%s' '{payload}' | base64 -d > '{f}.blk'; \
         awk -v blk='{f}.blk' '{awk}' '{f}' > '{f}.new'; \
         cat '{f}.new' > '{f}'; rm -f '{f}.new' '{f}.blk'",
        payload = B64.encode(text)
    ))
}

fn restore_remote_command(host_path: &str, backup: &str) -> Result<String> {
    let f = safe_path(host_path)?;
    let b = safe_path(backup)?;
    Ok(format!("cat '{b}' > '{f}'"))
}

/// As the login user first: a config in someone's home directory is theirs,
/// and sudo there would only ask for a password nobody gave. Root when that
/// is refused. The commands start over cleanly, so a second run is safe.
fn as_owner_then_root(host: &Host, cmd: &str) -> Result<(String, String, i32)> {
    let first = host.run(cmd)?;
    if first.2 == 0 {
        return Ok(first);
    }
    host.run_root(cmd)
}

fn write(host: &Host, plan: &RotationPlan, backup: &str) -> Result<()> {
    if host.is_local() {
        let path = local_path(&plan.host_path);
        std::fs::copy(&path, local_path(backup))
            .map_err(|e| Error::Config(format!("backing up {path}: {e}")))?;
        return std::fs::write(&path, &plan.new_conf)
            .map_err(|e| Error::Config(format!("writing {path}: {e}")));
    }
    let cmd = remote_rewrite_command(&plan.host_path, backup, &plan.client_block())?;
    let (_, err, code) = as_owner_then_root(host, &cmd)?;
    if code != 0 {
        return Err(Error::Config(format!(
            "rewriting {}: {}",
            plan.host_path,
            err.trim()
        )));
    }
    Ok(())
}

fn restore(host: &Host, plan: &RotationPlan, backup: &str) -> Result<()> {
    if host.is_local() {
        return std::fs::write(local_path(&plan.host_path), &plan.old_conf)
            .map_err(|e| Error::Config(format!("restoring {}: {e}", plan.host_path)));
    }
    let (_, err, code) =
        as_owner_then_root(host, &restore_remote_command(&plan.host_path, backup)?)?;
    if code != 0 {
        return Err(Error::Config(format!(
            "restoring {}: {}",
            plan.host_path,
            err.trim()
        )));
    }
    Ok(())
}

fn restart_and_wait(host: &Host, plan: &RotationPlan, seconds: u64) -> Result<bool> {
    let (_, err, code) = host.run_docker(&format!("docker restart {}", plan.container))?;
    if code != 0 {
        return Err(Error::Config(format!(
            "restarting {}: {}",
            plan.container,
            err.trim()
        )));
    }
    for _ in 0..seconds {
        std::thread::sleep(std::time::Duration::from_secs(1));
        if let Ok(h) = health(host, &plan.container, &plan.interface)
            && h.interface_up
            && h.uapi_ok
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Write the new config, restart the node and wait for it. When it does not
/// come back, the old config goes back and the node is restarted on it.
pub fn apply(host: &Host, plan: &RotationPlan) -> Result<Applied> {
    let backup = format!("{}.bak-{}", plan.host_path, stamp());
    write(host, plan, &backup)?;

    // Over SSH the file was rewritten by awk: what the container now reads
    // must be exactly what was planned, or the old one goes back untouched.
    let (seen, _, code) = host.run_docker(&format!(
        "docker exec {} cat {}",
        plan.container, plan.conf_path
    ))?;
    if code != 0 || seen.replace("\r\n", "\n") != plan.new_conf {
        restore(host, plan, &backup)?;
        return Err(Error::Invariant(format!(
            "the rewritten {} is not what was planned; the previous config is back",
            plan.host_path
        )));
    }

    if restart_and_wait(host, plan, 30)? {
        return Ok(Applied {
            backup,
            healthy: true,
            rolled_back: false,
        });
    }
    restore(host, plan, &backup)?;
    let back = restart_and_wait(host, plan, 30)?;
    Ok(Applied {
        backup,
        healthy: back,
        rolled_back: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER: &str = "\
[Interface]
PrivateKey = c2VydmVyLXByaXZhdGUta2V5LW5vdC1yZWFsLTEyMzQ=
Address = 10.8.1.1/24
ListenPort = 51820
# AmneziaWG 3.1
Jc = 4
jmin = 10
Jmax = 50
S1 = 20
# my own note
H1 = 1
I1 = <b 0x01>

[Peer]
PublicKey = cGVlci1wdWJsaWMta2V5LW5vdC1yZWFsLTEyMzQ1Ng==
PresharedKey = cHNrLW5vdC1yZWFsLTEyMzQ1Njc4OTAxMjM0NTY3OA==
AllowedIPs = 10.8.1.2/32
";

    fn block() -> Vec<String> {
        vec!["# AmneziaWG 3.1".into(), "Jc = 7".into(), "H1 = 5".into()]
    }

    #[test]
    fn only_the_shared_block_changes() {
        let out = rotate_conf(SERVER, &block()).unwrap();
        assert!(
            out.contains("PrivateKey = c2VydmVy"),
            "the server's key stays"
        );
        assert!(out.contains("ListenPort = 51820"));
        assert!(
            out.contains("# my own note"),
            "somebody's own comment stays"
        );
        assert!(out.contains("PresharedKey = cHNr"), "the peers stay");
        for gone in ["Jc = 4", "jmin = 10", "S1 = 20", "I1 = <b"] {
            assert!(!out.contains(gone), "{gone} survived");
        }
        // The block closes the section, before its blank line.
        assert!(
            out.contains("# my own note\n# AmneziaWG 3.1\nJc = 7\nH1 = 5\n\n[Peer]"),
            "{out}"
        );
        assert_eq!(out.matches("# AmneziaWG").count(), 1);
    }

    #[test]
    fn rotating_twice_is_the_same_as_once() {
        let once = rotate_conf(SERVER, &block()).unwrap();
        assert_eq!(rotate_conf(&once, &block()).unwrap(), once);
    }

    #[test]
    fn a_config_without_an_interface_is_refused() {
        assert!(rotate_conf("[Peer]\nPublicKey = x\n", &block()).is_err());
    }

    #[test]
    fn the_changes_are_named_and_never_shown() {
        let out = rotate_conf(SERVER, &block()).unwrap();
        let ch = changed_keys(SERVER, &out);
        assert_eq!(ch, ["Jc", "Jmin", "Jmax", "S1", "H1", "I1"]);
    }

    #[test]
    fn the_remote_command_carries_no_key() {
        let cmd = remote_rewrite_command(
            "/etc/amnezia/awg3/server.conf",
            "/etc/amnezia/awg3/server.conf.bak-1",
            &block(),
        )
        .unwrap();
        assert!(!cmd.contains("c2VydmVy") && !cmd.contains("cHNr"));
        assert!(cmd.contains("umask 077"));
        assert!(remote_rewrite_command("/etc/x'; id", "/b", &block()).is_err());
    }

    #[test]
    fn docker_desktop_sources_map_back_to_this_machine() {
        if cfg!(windows) {
            assert_eq!(
                local_path("/c/Users/x/server.conf"),
                "C:/Users/x/server.conf"
            );
            assert_eq!(
                local_path("/run/desktop/mnt/host/e/a/b.conf"),
                "E:/a/b.conf"
            );
            assert_eq!(local_path("C:\\a\\b.conf"), "C:\\a\\b.conf");
        } else {
            assert_eq!(local_path("/c/Users/x"), "/c/Users/x");
        }
    }

    /// The awk rewrite against the Rust one, where there is an awk to run.
    #[test]
    fn the_awk_rewrite_matches_the_reference() {
        let dir = std::env::temp_dir().join(format!("awg-rotate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (conf, blk) = (dir.join("server.conf"), dir.join("server.conf.blk"));
        std::fs::write(&conf, SERVER).unwrap();
        std::fs::write(&blk, block().join("\n") + "\n").unwrap();
        let out = std::process::Command::new("awk")
            .arg("-v")
            // awk -v reads escapes, so a Windows path goes in with forward
            // slashes; on a server the path is `/...` and safe_path refuses `\`.
            .arg(format!(
                "blk={}",
                blk.display().to_string().replace('\\', "/")
            ))
            .arg(AWK_REWRITE)
            .arg(&conf)
            .output();
        let _ = std::fs::remove_dir_all(&dir);
        let Ok(out) = out else {
            eprintln!("no awk here, skipped");
            return;
        };
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let awk = String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n");
        assert_eq!(awk, rotate_conf(SERVER, &block()).unwrap());
    }
}
