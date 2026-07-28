//! `awg-tool` — the command surface.
//!
//! Part of a joint release by AmneziaWG Architect and VAIEXIA.
//!
//! Arguments are parsed by hand rather than with clap: the binary ships inside
//! minimal containers, and the flag set is small enough that a dependency-free
//! parser is honest value rather than stubbornness.

mod i18n;
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

    match args.first().map(String::as_str) {
        Some("gen") | Some("generate") => cmd_gen(&args, lang),
        Some("clients") => cmd_clients(lang),
        Some("profiles") => cmd_profiles(lang),
        Some("install") | Some("tui") | Some("ui") => cmd_install(lang),
        Some("donate") | Some("support") => cmd_donate(lang),
        Some("about") => cmd_about(lang),
        None | Some("help") | Some("-h") | Some("--help") => usage(lang),
        Some(other) => {
            eprintln!("{}: {other}", t(lang, K::ErrUnknownCmd));
            usage(lang);
            std::process::exit(2);
        }
    }
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
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
    println!("  awg-tool gen [--version 3.0] [--profile quic] [--client amneziavpn] [--uapi]");
    println!("      {}", t(lang, K::CmdGen));
    println!("  awg-tool clients");
    println!("      {}", t(lang, K::CmdClients));
    println!("  awg-tool profiles");
    println!("      {}", t(lang, K::CmdProfiles));
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

fn cmd_install(lang: Lang) {
    if let Err(e) = tui::run(lang) {
        eprintln!("awg-tool: {e}");
        std::process::exit(1);
    }
}

fn cmd_donate(lang: Lang) {
    banner(lang);
    println!();
    println!("{}", t(lang, K::DonateIntro));
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
