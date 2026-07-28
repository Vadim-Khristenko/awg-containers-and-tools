//! Commands that talk to a real server.
//!
//! Everything here is a thin shell over `awg_core::docker` and
//! `awg_core::update`: connect, ask the core a question, print the answer. The
//! judgement lives in the core so the UI and these commands cannot drift into
//! disagreeing about what a healthy node looks like.

use awg_core::deploy::remote as remote_deploy;
use awg_core::deploy::{prepare, survey};
use awg_core::docker::{self, Container, Host};
use awg_core::platform::Tool;
use awg_core::rng::SecureRng;
use awg_core::ssh;
use awg_core::update;

use crate::i18n::{Key as K, Lang, t};
use crate::remote;

fn fail(msg: String) -> ! {
    eprintln!("awg-tool: {msg}");
    std::process::exit(1)
}

/// An open session plus everything needed to rebuild a `Host` from it.
///
/// `Host` borrows the session, so it cannot be returned alongside it. The
/// sudo password travels here rather than being dropped: rebuilding the `Host`
/// without it is how privileged calls start failing halfway through a command
/// that began fine.
struct Connected {
    session: awg_core::ssh::Session,
    sudo: bool,
    sudo_password: Option<String>,
}

impl Connected {
    fn host(&self) -> Host<'_> {
        Host::new(&self.session, self.sudo_password.as_deref()).with_docker_sudo(self.sudo)
    }
}

/// Connect and hand back the session plus the containers we recognise.
fn survey(args: &[String], lang: Lang) -> (Connected, Vec<Container>) {
    let target = remote::resolve(args, lang).unwrap_or_else(|e| fail(e));
    eprintln!(
        "{} {}@{}…",
        t(lang, K::MsgConnecting),
        target.profile.user,
        target.profile.host
    );
    let session = remote::connect(&target, lang).unwrap_or_else(|e| fail(e));
    let c = Connected {
        session,
        sudo: target.profile.sudo_required,
        sudo_password: target.sudo_password.clone(),
    };
    let found = docker::find_awg_containers(&c.host()).unwrap_or_else(|e| fail(e.to_string()));
    (c, found)
}

fn ago(secs: Option<u64>, lang: Lang) -> String {
    match secs {
        None => t(lang, K::ValNever).into(),
        Some(s) if s < 60 => format!("{s}s"),
        Some(s) if s < 3600 => format!("{}m", s / 60),
        Some(s) if s < 86400 => format!("{}h", s / 3600),
        Some(s) => format!("{}d", s / 86400),
    }
}

pub fn cmd_status(args: &[String], lang: Lang) {
    let (conn, found) = survey(args, lang);
    let host = conn.host();

    if found.is_empty() {
        println!("{}", t(lang, K::MsgNoContainers));
        return;
    }

    for c in &found {
        let generation = c
            .generation
            .map(|g| g.as_str().to_string())
            .unwrap_or_else(|| "?".into());
        println!();
        println!("● {}  ({}  {})", c.name, generation, c.state.as_str());
        println!("  image   {}", c.image);
        if let Some(up) = &c.uptime {
            println!("  uptime  {up}");
        }
        let ports: Vec<String> = c.ports.iter().map(|p| p.to_string()).collect();
        if !ports.is_empty() {
            println!("  ports   {}", ports.join(", "));
        }

        if !c.state.is_running() {
            continue;
        }
        let iface = docker::inspect(&host, &c.name)
            .map(|i| i.interface())
            .unwrap_or_else(|_| "awg0".into());
        match docker::health(&host, &c.name, &iface) {
            Ok(h) => {
                println!(
                    "  {}  {} · {} {}/{}",
                    if h.interface_up && h.uapi_ok {
                        "✓"
                    } else {
                        "✕"
                    },
                    iface,
                    t(lang, K::LblPeers),
                    h.peers_ever_handshaked(),
                    h.peer_count()
                );
                println!(
                    "  {}  {}   ↓{} ↑{}",
                    t(lang, K::LblHandshake),
                    ago(h.newest_handshake_age(), lang),
                    human(h.rx_bytes()),
                    human(h.tx_bytes())
                );
                if let Some(e) = &h.uapi_error {
                    println!("  !  {e}");
                }
            }
            Err(e) => println!("  !  {e}"),
        }
    }
}

fn human(bytes: u64) -> String {
    // Up to exabytes, not because a tunnel will move one, but so an
    // implausible counter reads as an implausible number rather than as
    // "16777216.0T", which looks like a formatting bug and hides the real one.
    const U: [&str; 7] = ["B", "K", "M", "G", "T", "P", "E"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < U.len() {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes}{}", U[0])
    } else {
        format!("{v:.1}{}", U[i])
    }
}

pub fn cmd_logs(args: &[String], lang: Lang) {
    let lines: u32 = args
        .iter()
        .position(|a| a == "--lines")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);

    let (conn, found) = survey(args, lang);
    let host = conn.host();
    let wanted = positional(args);

    for c in pick(&found, wanted.as_deref(), lang) {
        println!("── {} ──", c.name);
        match docker::logs(&host, &c.name, lines) {
            // Already redacted by the core; nothing here needs to know which
            // fields were secret.
            Ok(text) => println!("{text}"),
            Err(e) => eprintln!("  ! {e}"),
        }
    }
}

pub fn cmd_doctor(args: &[String], lang: Lang) {
    let (conn, found) = survey(args, lang);
    let host = conn.host();
    let wanted = positional(args);

    let mut any = false;
    for c in pick(&found, wanted.as_deref(), lang) {
        any = true;
        println!();
        println!("── {} ──", c.name);
        match docker::diagnose_container(&host, c, None) {
            Ok(d) => {
                if d.healthy {
                    println!("  ✓ {}", t(lang, K::MsgNoFaults));
                }
                for f in &d.findings {
                    println!(
                        "  {} [{}] {}",
                        match f.confidence {
                            docker::Confidence::Confirmed => "✕",
                            docker::Confidence::Likely => "!",
                            docker::Confidence::Possible => "?",
                        },
                        f.confidence.as_str(),
                        f.what
                    );
                    for e in &f.evidence {
                        println!("      · {e}");
                    }
                    println!("      → {}", f.next_step);
                    for a in &f.alternatives {
                        println!("      ~ {a}");
                    }
                }
                // Printed even when findings exist: "we could not look at X"
                // changes how much the rest of the verdict is worth.
                for b in &d.blind_spots {
                    println!("  ? {b}");
                }
            }
            Err(e) => eprintln!("  ! {e}"),
        }
    }
    if !any {
        println!("{}", t(lang, K::MsgNoContainers));
    }
}

pub fn cmd_update(args: &[String], lang: Lang) {
    // The tool's own version needs no server, so it is answered first and
    // always — a network failure later must not swallow it.
    println!("{}", update::check_tool_update().summary());

    if !args
        .iter()
        .any(|a| a.starts_with("--server") || a == "--host")
    {
        return;
    }
    let (conn, found) = survey(args, lang);
    let host = conn.host();
    for c in &found {
        match docker::local_image(&host, &c.image) {
            Ok(local) => println!(
                "{}: {}",
                c.name,
                update::check_image_update(&local).summary()
            ),
            Err(e) => println!("{}: {e}", c.name),
        }
    }
}

// ───────────────────────────────────────────────────────────────── install

/// Everything `survey_from_probes` needs, collected over one session.
fn probe(session: &awg_core::ssh::Session, sudo: Option<&str>) -> survey::Probes {
    let run =
        |cmd: &str| ssh::exec(session, cmd).unwrap_or_else(|_| (String::new(), String::new(), 1));

    let (os_release, ..) = run("cat /etc/os-release 2>/dev/null");
    let (tool_probe, ..) = run(&survey::tool_probe_command(&Tool::REQUIRED));
    let (route, ..) = run("ip route 2>/dev/null");
    let (ip_forward, ..) = run("cat /proc/sys/net/ipv4/ip_forward 2>/dev/null");
    let (uid, ..) = run("id -u");

    let (.., docker_direct_code) = run("docker info >/dev/null 2>&1");
    // Only asked when the direct attempt failed: running a needless sudo is how
    // a survey trips a security alert on someone's server.
    let docker_sudo_code = if docker_direct_code == 0 {
        None
    } else {
        ssh::exec_sudo(session, "docker info >/dev/null 2>&1", sudo)
            .ok()
            .map(|(.., code)| code)
    };

    survey::Probes {
        os_release,
        tool_probe,
        route,
        ip_forward,
        uid,
        docker_direct_code,
        docker_sudo_code,
        // No outbound request from the target. The default route's source
        // address is usually right, and a machine that quietly calls an echo
        // service during a survey is a surprise nobody asked for.
        echo: None,
    }
}

/// Who is already sitting on the UDP port, if anyone.
fn port_holder(session: &awg_core::ssh::Session, port: u16) -> Option<String> {
    let (out, ..) = ssh::exec(
        session,
        &format!("ss -H -lunp 'sport = :{port}' 2>/dev/null"),
    )
    .ok()?;
    let line = out.lines().next()?.trim().to_string();
    (!line.is_empty()).then_some(line)
}

pub fn cmd_install(args: &[String], lang: Lang) {
    let target = remote::resolve(args, lang).unwrap_or_else(|e| fail(e));
    eprintln!(
        "{} {}@{}…",
        t(lang, K::MsgConnecting),
        target.profile.user,
        target.profile.host
    );
    let session = remote::connect(&target, lang).unwrap_or_else(|e| fail(e));
    // What `sudo -S` reads, which is not what SSH authenticated with. See
    // `remote::Target`.
    let secret = target.sudo_password.as_deref();

    // ── look before touching ──
    eprintln!("{}", t(lang, K::MsgSurveying));
    let s = survey::survey_from_probes(&probe(&session, secret));
    println!("  {:<12} {}", t(lang, K::LblSystem), s.distro.name);
    println!(
        "  {:<12} {}",
        t(lang, K::LblDocker),
        if s.docker.is_usable() {
            if s.docker.needs_sudo() { "sudo" } else { "ok" }
        } else {
            "—"
        }
    );
    if let Some(ip) = &s.public_ip {
        println!("  {:<12} {}", t(lang, K::LblAddress), ip.address);
    }

    match prepare::plan_preparation(&s.distro, &s.missing, None) {
        prepare::Preparation::Ready => {}
        prepare::Preparation::Install { cmd, packages } => {
            println!();
            println!("{}: {}", t(lang, K::MsgWillInstall), packages.join(", "));
            println!("  {cmd}");
            if !remote::confirm(t(lang, K::AskRunIt)) {
                fail(t(lang, K::MsgAborted).into());
            }
            let (_, err, code) =
                ssh::exec_sudo(&session, &cmd, secret).unwrap_or_else(|e| fail(e.to_string()));
            if code != 0 {
                fail(format!("{}: {}", t(lang, K::MsgInstallFailed), err.trim()));
            }
        }
        // NixOS and anything else that cannot be provisioned by running a
        // command: print the snippet and stop rather than pretending.
        prepare::Preparation::Manual { reason, hint }
        | prepare::Preparation::SourceFallback { reason, hint, .. } => {
            println!();
            println!("{reason}");
            println!();
            println!("{hint}");
            std::process::exit(1);
        }
    }

    // ── the port ──
    let mut opts = remote_deploy::DeployOptions::default();
    if let Some(p) = flag(args, "--listen-port").and_then(|v| v.parse::<u16>().ok()) {
        opts.network.listen_port = p;
    }
    if let Some(h) = flag(args, "--endpoint") {
        opts.network.endpoint_host = h;
    }
    if let Some(n) = flag(args, "--name") {
        opts.container.name = n;
    }
    if let Some(i) = flag(args, "--image") {
        opts.container.image = i;
    }
    opts.pull = args.iter().any(|a| a == "--pull");

    if let Some(holder) = port_holder(&session, opts.network.listen_port) {
        // Deliberately a refusal, not an offer to kill it. Something is
        // listening there for a reason, and picking another port costs one
        // flag; killing the wrong process costs a server.
        eprintln!(
            "{} {}/udp:",
            t(lang, K::MsgPortBusy),
            opts.network.listen_port
        );
        eprintln!("  {holder}");
        fail(t(lang, K::MsgPickAnotherPort).into());
    }

    // ── deploy ──
    eprintln!("{}", t(lang, K::MsgDeploying));
    let result = remote_deploy::deploy(&session, &s, &opts, &mut SecureRng, secret)
        .unwrap_or_else(|e| fail(e.to_string()));

    println!();
    for w in &result.warnings {
        println!("!  {w}");
    }
    println!("{}  {}", t(lang, K::LblEndpoint), result.endpoint);
    println!("{}  {}", t(lang, K::LblContainer), result.container);
    println!();
    println!("{}", result.client_conf);
    println!();
    println!("{}", result.vpn_link);
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

/// The first argument that is not a flag or a flag's value.
fn positional(args: &[String]) -> Option<String> {
    const TAKES_VALUE: [&str; 6] = ["--server", "--host", "--user", "--port", "--key", "--lines"];
    let mut skip = true; // args[0] is the command itself
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if skip {
            skip = false;
            continue;
        }
        if TAKES_VALUE.contains(&a.as_str()) {
            it.next();
        } else if !a.starts_with("--") {
            return Some(a.clone());
        }
    }
    None
}

/// All containers, or the one that was named.
fn pick<'a>(found: &'a [Container], name: Option<&str>, lang: Lang) -> Vec<&'a Container> {
    match name {
        None => found.iter().collect(),
        Some(n) => {
            let hit: Vec<&Container> = found.iter().filter(|c| c.name == n).collect();
            if hit.is_empty() {
                let names: Vec<&str> = found.iter().map(|c| c.name.as_str()).collect();
                eprintln!("awg-tool: {}: {n}", t(lang, K::ErrNoSuchContainer));
                if !names.is_empty() {
                    eprintln!("  {}: {}", t(lang, K::Available), names.join(", "));
                }
                std::process::exit(2);
            }
            hit
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_flags_value_is_never_mistaken_for_the_container_name() {
        // `logs --profile home` names no container; taking "home" would print
        // the wrong node's logs, or refuse to find one that exists.
        assert_eq!(positional(&a(&["logs", "--server", "home"])), None);
        assert_eq!(positional(&a(&["logs", "--lines", "50"])), None);
        assert_eq!(
            positional(&a(&["logs", "--server", "home", "awg-server"])),
            Some("awg-server".into())
        );
        assert_eq!(
            positional(&a(&["doctor", "awg-server", "--lines", "9"])),
            Some("awg-server".into())
        );
    }

    #[test]
    fn byte_counts_read_the_way_people_expect() {
        assert_eq!(human(0), "0B");
        assert_eq!(human(999), "999B");
        assert_eq!(human(1024), "1.0K");
        assert_eq!(human(1024 * 1024 * 3 / 2), "1.5M");
        assert_eq!(human(u64::MAX), "16.0E");
    }

    #[test]
    fn a_handshake_age_is_rendered_at_a_useful_scale() {
        assert_eq!(ago(None, Lang::En), "never");
        assert_eq!(ago(Some(5), Lang::En), "5s");
        assert_eq!(ago(Some(90), Lang::En), "1m");
        assert_eq!(ago(Some(7200), Lang::En), "2h");
        assert_eq!(ago(Some(90_000), Lang::En), "1d");
    }
}
