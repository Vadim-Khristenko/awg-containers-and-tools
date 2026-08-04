//! `awg-tool` — the command surface.
//!
//! Part of a joint release by Any Tech ARCHITECT and VAIEXIA.
//!
//! Arguments are parsed by hand rather than with clap: the binary ships inside
//! minimal containers, and the flag set is small enough that a dependency-free
//! parser is honest value rather than stubbornness.

mod i18n;
mod ops;
mod remote;
mod theme;
mod tui;

use awg_core::awg3::Intensity;
use awg_core::mimic::{BrowserProfile, MimicOptions, MimicProfile};
use awg_core::rng::SecureRng;
use awg_core::versions::{self, AwgVersion, GenOptions, Level};
use i18n::{Key as K, Lang, t};

const ARCHITECT_URL: &str = "https://architect.vai-rice.space";
const SOURCES_URL: &str = "https://github.com/Vadim-Khristenko/awg-containers-and-tools";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let lang = Lang::detect(flag_value(&args, "--lang").as_deref());

    match command_of(&args) {
        Some("gen") | Some("generate") => cmd_gen(&args, lang),
        Some("clients") => cmd_clients(lang),
        Some("profiles") => cmd_profiles(lang),
        Some("status") => ops::cmd_status(&args, lang),
        Some("logs") => ops::cmd_logs(&args, lang),
        Some("doctor") | Some("diagnose") => ops::cmd_doctor(&args, lang),
        Some("update") => ops::cmd_update(&args, lang),
        // `install` does the deploy; the UI is `tui`, or no arguments at all.
        Some("install") | Some("deploy") => ops::cmd_install(&args, lang),
        Some("tui") | Some("ui") => cmd_tui(lang),
        Some("donate") | Some("support") => cmd_donate(lang),
        Some("about") => cmd_about(lang),
        Some("help") | Some("-h") | Some("--help") => usage(lang),
        // No arguments opens the UI. Someone who runs a tool with no arguments
        // is looking for what it does, and a wall of flags is a worse answer
        // than a screen they can walk through. `--help` still prints the flags,
        // and a UI is only offered when there is a terminal to draw it on.
        None => {
            if is_interactive() {
                cmd_tui(lang)
            } else {
                usage(lang)
            }
        }
        Some(other) => {
            eprintln!("{}: {other}", t(lang, K::ErrUnknownCmd));
            usage(lang);
            std::process::exit(2);
        }
    }
}

/// Every flag that consumes the argument after it. Needed in exactly one place
/// — working out which word is the command — but wrong here means a flag's
/// value gets run as a subcommand.
const VALUE_FLAGS: [&str; 17] = [
    "--version",
    "--profile",
    "--client",
    "--intensity",
    "--mtu",
    "--host",
    "--browser",
    "--lang",
    "--server",
    "--user",
    "--port",
    "--key",
    "--lines",
    "--listen-port",
    "--endpoint",
    "--name",
    "--image",
];

/// The first word that is neither a flag nor a flag's value.
///
/// `awg-tool --host 10.0.0.5 status` is a natural thing to type, and reading
/// only `args[0]` answered it with "unknown command: --host". Both orderings
/// now work, and the flag's *value* is never mistaken for the command.
fn command_of(args: &[String]) -> Option<&str> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if VALUE_FLAGS.contains(&a.as_str()) {
            it.next();
        } else if !a.starts_with('-') {
            return Some(a.as_str());
        }
    }
    // Nothing but flags: `--help` is still a request for help, and a bare
    // invocation is still a request for the UI.
    args.iter()
        .find(|a| matches!(a.as_str(), "-h" | "--help" | "help"))
        .map(String::as_str)
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// Is there a real terminal on both ends?
///
/// The UI switches to the alternate screen and reads keys, so it needs a tty
/// for input as well as output. Piped into something — `awg-tool | tee`, a CI
/// step, a `command -v` probe — it must print instead of trying to draw, or it
/// fails with a bare "No such device or address" that explains nothing.
fn is_interactive() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

fn banner(lang: Lang) {
    println!("awg-tool {}", env!("CARGO_PKG_VERSION"));
    println!("{}", t(lang, K::Tagline));
    println!("{}", t(lang, K::JointRelease));
}

fn usage(lang: Lang) {
    banner(lang);
    println!();
    println!("{}:", t(lang, K::UsageHeader));
    println!("  awg-tool");
    println!("      {}", t(lang, K::CmdBare));
    println!("  awg-tool gen [--version 3.0] [--profile quic] [--client amneziavpn] [--uapi]");
    println!("      {}", t(lang, K::CmdGen));
    println!("  awg-tool clients");
    println!("      {}", t(lang, K::CmdClients));
    println!("  awg-tool profiles");
    println!("      {}", t(lang, K::CmdProfiles));
    println!("  awg-tool status [--server NAME | --host ADDR]");
    println!("      {}", t(lang, K::CmdStatus));
    println!("  awg-tool doctor [CONTAINER]");
    println!("      {}", t(lang, K::CmdDoctor));
    println!("  awg-tool logs [CONTAINER] [--lines 200]");
    println!("      {}", t(lang, K::CmdLogs));
    println!("  awg-tool update");
    println!("      {}", t(lang, K::CmdUpdate));
    println!("  awg-tool install");
    println!("      {}", t(lang, K::CmdInstall));
    println!("  awg-tool donate");
    println!("      {}", t(lang, K::CmdDonate));
    println!("  awg-tool about");
    println!("      {}", t(lang, K::CmdAbout));
    println!();
    println!("  --version 3.0        {}", t(lang, K::OptVersion));
    println!("  --profile quic       {}", t(lang, K::OptProfile));
    println!("  --client amneziavpn  {}", t(lang, K::OptClient));
    println!("  --uapi               {}", t(lang, K::OptUapi));
    println!("  --intensity medium   {}", t(lang, K::OptIntensity));
    println!("  --router             {}", t(lang, K::OptRouter));
    println!("  --mtu 1500           {}", t(lang, K::OptMtu));
    println!("  --host example.com   {}", t(lang, K::OptHost));
    println!("  --browser chrome     {}", t(lang, K::OptBrowser));
    println!("  --mimic-all          {}", t(lang, K::OptMimicAll));
    println!("  --tag-c              {}", t(lang, K::OptTagC));
    println!("  --lang en|ru         {}", t(lang, K::OptLang));
    println!();
    println!("{}:", t(lang, K::UsageServerFlags));
    println!("  --server home        {}", t(lang, K::OptProfileFlag));
    println!("  --host 10.0.0.5      {}", t(lang, K::OptHostFlag));
    println!("  --user root          {}", t(lang, K::OptUserFlag));
    println!("  --port 22            {}", t(lang, K::OptSshPort));
    println!("  --key ~/.ssh/id_ed25519  {}", t(lang, K::OptKeyFlag));
    println!("  --sudo               {}", t(lang, K::OptSudoFlag));
    println!("  --lines 200          {}", t(lang, K::OptLinesFlag));
    println!("  --listen-port 51820  {}", t(lang, K::OptListenPort));
    println!("  --endpoint 1.2.3.4   {}", t(lang, K::OptEndpoint));
    println!("  --pull               {}", t(lang, K::OptPull));
    println!();
    println!("{}", t(lang, K::Unofficial));
}

/// Report a bad flag value together with the values that would have worked —
/// a rejection with no list of alternatives just costs the user another run.
fn bail(lang: Lang, key: K, given: &str, valid: &[&str]) -> ! {
    eprintln!("{}: {given}", t(lang, key));
    eprintln!("  {}: {}", t(lang, K::Available), valid.join(", "));
    std::process::exit(2);
}

fn cmd_gen(args: &[String], lang: Lang) {
    let raw_version = flag_value(args, "--version").unwrap_or_else(|| "3.0".into());
    let Some(version) = AwgVersion::parse(&raw_version) else {
        let valid: Vec<&str> = AwgVersion::ALL.iter().map(|v| v.as_str()).collect();
        bail(lang, K::ErrUnknownVersion, &raw_version, &valid);
    };

    let profile = match flag_value(args, "--profile") {
        None => MimicProfile::QuicInitial,
        Some(raw) => match MimicProfile::parse(&raw) {
            Some(p) => p,
            None => {
                let valid: Vec<&str> = MimicProfile::ALL.iter().map(|p| p.id()).collect();
                bail(lang, K::ErrUnknownProfile, &raw, &valid);
            }
        },
    };

    let client = match flag_value(args, "--client") {
        None => versions::default_client(),
        Some(raw) => match versions::client(&raw) {
            Some(c) => c,
            None => {
                let valid: Vec<&str> = versions::CLIENTS.iter().map(|c| c.id).collect();
                bail(lang, K::ErrUnknownClient, &raw, &valid);
            }
        },
    };

    let browser = match flag_value(args, "--browser") {
        None => None,
        Some(raw) => match BrowserProfile::parse(&raw) {
            Some(b) => Some(b),
            None => {
                let valid: Vec<&str> = BrowserProfile::ALL.iter().map(|b| b.id()).collect();
                bail(lang, K::ErrUnknownBrowser, &raw, &valid);
            }
        },
    };

    let intensity = match flag_value(args, "--intensity").as_deref() {
        Some("low") => Intensity::Low,
        Some("high") => Intensity::High,
        _ => Intensity::Medium,
    };

    let mtu = match flag_value(args, "--mtu") {
        None => 1500,
        Some(raw) => match raw.parse::<u32>() {
            // Below the IPv4 minimum reassembly buffer there is no room for a
            // chain at all, and above 9000 nothing on the path will carry it.
            Ok(n) if (576..=9000).contains(&n) => n,
            _ => bail(lang, K::ErrBadMtu, &raw, &["576..9000"]),
        },
    };

    let router_mode = has_flag(args, "--router");
    let opts = GenOptions {
        version,
        profile,
        intensity,
        client,
        router_mode,
        mimic: MimicOptions {
            mtu,
            mimic_all: has_flag(args, "--mimic-all"),
            custom_host: flag_value(args, "--host"),
            // <c> stays opt-in: several amneziawg-go builds answer ErrorCode
            // 1000 and refuse the whole config.
            tag_c: has_flag(args, "--tag-c"),
            browser,
            router_mode,
            ..Default::default()
        },
        ..Default::default()
    };

    let params = match versions::generate(&mut SecureRng, &opts) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("awg-tool: {e}");
            std::process::exit(1);
        }
    };

    let lines = if has_flag(args, "--uapi") {
        params.uapi_lines()
    } else {
        params.conf_lines()
    };
    for l in lines {
        println!("{l}");
    }

    // Warnings go to stderr so `awg-tool gen > client.conf` stays a valid file.
    let warnings: Vec<_> = versions::validate_for_client(&params, client)
        .into_iter()
        .filter(|v| v.level == Level::Warn)
        .collect();
    if !warnings.is_empty() {
        eprintln!("{}:", t(lang, K::WarningsHeader));
        for w in warnings {
            eprintln!("  {}: {}", w.field, w.message);
        }
    }
    for issue in client.known_issues {
        eprintln!("{}: {issue}", t(lang, K::KnownIssue));
    }
}

fn cmd_clients(lang: Lang) {
    println!("{}:", t(lang, K::CmdClients));
    for c in &versions::CLIENTS {
        println!("  {:<20} {} ({})", c.id, c.name, c.platforms.join(", "));
        println!(
            "      maxH={} maxJc={} maxS4={} <c>={} <rc>={} <rd>={}",
            c.max_h_value,
            c.max_jc,
            c.max_s4,
            c.supports_tag_c,
            c.supports_tag_rc,
            c.supports_tag_rd
        );
        for issue in c.known_issues {
            println!("      ! {issue}");
        }
    }
    println!();
    println!(
        "{}: {}",
        t(lang, K::DefaultClient),
        versions::DEFAULT_CLIENT_ID
    );
}

fn cmd_profiles(lang: Lang) {
    println!("{}:", t(lang, K::CmdProfiles));
    for p in MimicProfile::ALL {
        println!("  {:<14} {}", p.id(), p.label());
    }
}

fn cmd_tui(lang: Lang) {
    if let Err(e) = tui::run(lang) {
        eprintln!("awg-tool: {e}");
        std::process::exit(1);
    }
}

fn cmd_donate(lang: Lang) {
    use awg_core::support::{CRYPTO_WALLETS, FIAT_METHODS};

    banner(lang);
    println!();
    println!("{}", t(lang, K::DonateIntro));
    println!();

    println!("{}:", t(lang, K::DonateFiat));
    for m in &FIAT_METHODS {
        let note = if lang == Lang::Ru {
            m.note_ru
        } else {
            m.note_en
        };
        println!("  {:<10} {:<24} {}", m.label, note, m.url);
    }

    println!();
    println!("{}:", t(lang, K::DonateCrypto));
    for w in &CRYPTO_WALLETS {
        let net = if lang == Lang::Ru {
            w.network_ru
        } else {
            w.network_en
        };
        println!("  {} · {}", w.ticker, net);
        // On its own line and nothing else on it, so selecting the address with
        // a mouse cannot pick up a label or a stray space along with it.
        println!("    {}", w.address);
    }
    println!();
    println!("  {}", t(lang, K::DonateNetworkWarn));

    println!();
    println!("  {} — {ARCHITECT_URL}", t(lang, K::DonateArchitect));
    println!("  {} — {SOURCES_URL}", t(lang, K::DonateSources));
}

fn cmd_about(lang: Lang) {
    banner(lang);
    println!();
    println!("{}", t(lang, K::AboutVaiexia));
    println!();
    println!("{}", t(lang, K::AboutAwg3));
    println!();
    println!("{}", t(lang, K::WhyUnique));
    println!();
    println!("{}", t(lang, K::Unofficial));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_command_is_found_whichever_side_of_the_flags_it_is_on() {
        assert_eq!(command_of(&a(&["status", "--host", "h"])), Some("status"));
        assert_eq!(command_of(&a(&["--host", "h", "status"])), Some("status"));
        assert_eq!(
            command_of(&a(&["--server", "home", "--lines", "50", "logs"])),
            Some("logs")
        );
    }

    #[test]
    fn a_flags_value_is_never_run_as_a_command() {
        // `--host status` would otherwise dispatch to the status command
        // against a server literally named "status".
        assert_eq!(command_of(&a(&["--host", "status"])), None);
        assert_eq!(command_of(&a(&["--client", "gen"])), None);
    }

    #[test]
    fn a_positional_after_the_command_is_not_the_command() {
        assert_eq!(command_of(&a(&["logs", "awg-server"])), Some("logs"));
        assert_eq!(command_of(&a(&["doctor", "vpn"])), Some("doctor"));
    }

    #[test]
    fn nothing_but_flags_still_finds_help_and_otherwise_asks_for_the_ui() {
        assert_eq!(command_of(&a(&["--help"])), Some("--help"));
        assert_eq!(command_of(&a(&["--lang", "ru"])), None);
        assert_eq!(command_of(&[]), None);
    }
}
