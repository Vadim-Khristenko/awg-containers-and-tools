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
use awg_core::check::{self, CheckOptions};
use awg_core::engines::Engine;
use awg_core::mimic::hostdb::{self, HostQuery, Region, Role};
use awg_core::mimic::{BrowserProfile, MimicOptions, MimicProfile};
use awg_core::rng::SecureRng;
use awg_core::versions::{self, AwgVersion, ClientCapability, GenOptions, Level};
use awg_core::{profile, saved};
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
        Some("hosts") => cmd_hosts(&args, lang),
        Some("check") | Some("lint") => cmd_check(&args, lang),
        Some("sets") => cmd_sets(&args, lang),
        Some("under") | Some("amiunder") => cmd_under(&args, lang),
        Some("dns") => ops::cmd_dns(&args, lang),
        Some("peer") | Some("peers") => ops::cmd_peer(&args, lang),
        Some("rotate") => ops::cmd_rotate(&args, lang),
        Some("servers") => ops::cmd_servers(&args, lang),
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
pub(crate) const VALUE_FLAGS: &[&str] = &[
    "--version",
    "--profile",
    "--client",
    "--intensity",
    "--junk",
    "--container",
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
    "--client-release",
    "--server-engine",
    "--region",
    "--whitelisted",
    "--role",
    "--attempt",
    "--mimic-host",
    "--out",
    "--set",
    "--save",
    "--resolver",
    "--timeout",
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
        } else if a.starts_with("--") && it.clone().next().is_some_and(|v| is_switch_word(v)) {
            // `--random-trailers off`: the word after a switch is its value.
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

/// The words a switch takes after it.
fn is_switch_word(v: &str) -> bool {
    matches!(
        v.to_ascii_lowercase().as_str(),
        "on" | "off" | "yes" | "no" | "true" | "false" | "1" | "0"
    )
}

/// An on/off switch: absent means `default`, present alone means on, and
/// `on|off`, `yes|no`, `true|false`, `1|0` after it say which.
fn switch(args: &[String], name: &str, default: bool) -> bool {
    let Some(i) = args.iter().position(|a| a == name) else {
        return default;
    };
    !matches!(
        args.get(i + 1).map(|v| v.to_ascii_lowercase()).as_deref(),
        Some("0" | "false" | "off" | "no")
    )
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
    println!("  awg-tool hosts [--role quic] [--region ru] [--whitelisted ru] [--unknown]");
    println!("      {}", t(lang, K::CmdHosts));
    println!("  awg-tool gen [--set NAME] [... options] [--save NAME]");
    println!("  awg-tool sets [list | show NAME | rm NAME]");
    println!("      {}", t(lang, K::CmdSets));
    println!("  awg-tool check <file|-|vpn://...> [--client X] [--version 3.1] [--json]");
    println!("      {}", t(lang, K::CmdCheck));
    println!(
        "  awg-tool peer add <label> [ip] [--out FILE] [--vpn] [--mihomo] | list | rm <label|pubkey>"
    );
    println!("      {}", t(lang, K::CmdPeer));
    println!("  awg-tool rotate [--container X] [--dry-run] [--yes] [--out FILE] [any gen option]");
    println!("      {}", t(lang, K::CmdRotate));
    println!("  awg-tool dns [status] | block|unblock|allow|unallow NAME | query NAME");
    println!("      {}", t(lang, K::CmdDns));
    println!("  awg-tool under [HOST] [--resolver 172.29.172.254] [--timeout 3] [--json]");
    println!("      {}", t(lang, K::CmdUnder));
    println!(
        "  awg-tool servers [list] | add NAME --host ADDR [--user U] [--key PATH] [--sudo] | rm NAME"
    );
    println!("      {}", t(lang, K::CmdServers));
    println!("  awg-tool status [--server NAME | --host ADDR]");
    println!("      {}", t(lang, K::CmdStatus));
    println!("  awg-tool doctor [CONTAINER]");
    println!("      {}", t(lang, K::CmdDoctor));
    println!("  awg-tool logs [CONTAINER] [--lines 200]");
    println!("      {}", t(lang, K::CmdLogs));
    println!("  awg-tool update");
    println!("      {}", t(lang, K::CmdUpdate));
    println!(
        "  awg-tool install [--version 3.1] [any gen option; --mimic-host for the mimicry name]"
    );
    println!("      {}", t(lang, K::CmdInstall));
    println!("  awg-tool donate");
    println!("      {}", t(lang, K::CmdDonate));
    println!("  awg-tool about");
    println!("      {}", t(lang, K::CmdAbout));
    println!();
    println!("  --version 3.1        {}", t(lang, K::OptVersion));
    println!("  --profile quic       {}", t(lang, K::OptProfile));
    println!("  --client amneziavpn  {}", t(lang, K::OptClient));
    println!(
        "  --client-release pre-2.0.2  {}",
        t(lang, K::OptClientRelease)
    );
    println!("  --server-engine go   {}", t(lang, K::OptServerEngine));
    println!("  --uapi               {}", t(lang, K::OptUapi));
    println!("  --mihomo             {}", t(lang, K::OptMihomo));
    println!("  --json               {}", t(lang, K::OptJson));
    println!("  --out client.conf    {}", t(lang, K::OptOut));
    println!("  --intensity medium   {}", t(lang, K::OptIntensity));
    println!("  --junk 5             {}", t(lang, K::OptJunk));
    println!("  --extreme            {}", t(lang, K::OptExtreme));
    println!("  --narrow-h off       {}", t(lang, K::OptNarrowH));
    println!("  --router             {}", t(lang, K::OptRouter));
    println!("  --mtu 1500           {}", t(lang, K::OptMtu));
    println!("  --host example.com   {}", t(lang, K::OptHost));
    println!("  --region ru          {}", t(lang, K::OptRegion));
    println!("  --whitelisted ru     {}", t(lang, K::OptWhitelisted));
    println!("  --role quic          {}", t(lang, K::OptRole));
    println!("  --unknown            {}", t(lang, K::OptUnknown));
    println!("  --browser chrome     {}", t(lang, K::OptBrowser));
    println!("  --mimic-all          {}", t(lang, K::OptMimicAll));
    println!("  --tag-c              {}", t(lang, K::OptTagC));
    println!("  {}", t(lang, K::OptSwitchesNote));
    println!("  --header-protection  {}", t(lang, K::OptHeaderProtection));
    println!("  --content-padding    {}", t(lang, K::OptContentPadding));
    println!("  --random-timings     {}", t(lang, K::OptRandomTimings));
    println!("  --random-trailers    {}", t(lang, K::OptRandomTrailers));
    println!("  --disable-cookies    {}", t(lang, K::OptDisableCookies));
    println!("  --same-s             {}", t(lang, K::OptSameS));
    println!("  --disable-h          {}", t(lang, K::OptDisableH));
    println!("  --tag-t/-r/-rc/-rd off  {}", t(lang, K::OptTags));
    println!("  --attempt 4          {}", t(lang, K::OptAttempt));
    println!("  --lang en|ru         {}", t(lang, K::OptLang));
    println!();
    println!("{}:", t(lang, K::UsageServerFlags));
    println!("  --server home        {}", t(lang, K::OptProfileFlag));
    println!("  --host 10.0.0.5      {}", t(lang, K::OptHostFlag));
    println!("  --user root          {}", t(lang, K::OptUserFlag));
    println!("  --port 22            {}", t(lang, K::OptSshPort));
    println!("  --key ~/.ssh/id_ed25519  {}", t(lang, K::OptKeyFlag));
    println!("  --sudo               {}", t(lang, K::OptSudoFlag));
    println!("  --local              {}", t(lang, K::OptLocal));
    println!("  --container NAME     {}", t(lang, K::OptContainer));
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

/// Everything `gen` and `install` share: the version, its preset, and every
/// knob of the generator, read off the command line.
pub(crate) fn gen_options(args: &[String], lang: Lang) -> GenOptions {
    // The starting point: a saved set when one is named, otherwise the
    // version's preset, as Architect applies it when the version changes.
    // Every flag below overrides it only when it is actually given.
    let mut base = match flag_value(args, "--set") {
        Some(name) => load_set(&name, lang),
        None => GenOptions::for_version(AwgVersion::V3_0),
    };
    if let Some(v) = version_flag(args, lang)
        && (v != base.version || flag_value(args, "--set").is_none())
    {
        base.version = v;
        base.apply_preset();
        // Narrow H was the CLI's own 3.1 default before presets; it stays,
        // since it costs nothing and the trailers force it anyway.
        base.narrow_h = v == AwgVersion::V3_1;
    }

    let profile = match flag_value(args, "--profile") {
        None => base.profile,
        Some(raw) => match MimicProfile::parse(&raw) {
            Some(p) => p,
            None => {
                let valid: Vec<&str> = MimicProfile::ALL.iter().map(|p| p.id()).collect();
                bail(lang, K::ErrUnknownProfile, &raw, &valid);
            }
        },
    };
    let client = if has_flag(args, "--client") || has_flag(args, "--client-release") {
        client_flag(args, lang)
    } else {
        base.client
    };
    let server_engine = if has_flag(args, "--server-engine") {
        engine_flag(args, lang)
    } else {
        base.server_engine
    };
    let region = if has_flag(args, "--region") {
        region_flag(args, "--region", lang)
    } else {
        base.mimic.region
    };
    let whitelisted_in = if has_flag(args, "--whitelisted") {
        region_flag(args, "--whitelisted", lang)
    } else {
        base.mimic.whitelisted_in
    };
    let browser = match flag_value(args, "--browser") {
        None => base.mimic.browser,
        Some(raw) if raw == "off" || raw == "none" => None,
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
        Some("medium") => Intensity::Medium,
        Some("high") => Intensity::High,
        _ => base.intensity,
    };
    let mtu = match flag_value(args, "--mtu") {
        None => base.mimic.mtu,
        Some(raw) => match raw.parse::<u32>() {
            // Below the IPv4 minimum reassembly buffer there is no room for a
            // chain at all, and above 9000 nothing on the path will carry it.
            Ok(n) if (576..=9000).contains(&n) => n,
            _ => bail(lang, K::ErrBadMtu, &raw, &["576..9000"]),
        },
    };
    let junk_level = match flag_value(args, "--junk").as_deref() {
        None => base.junk_level,
        Some(raw) => match raw.parse::<u8>() {
            Ok(n) if n <= 32 => n,
            _ => bail(lang, K::ErrBadJunk, raw, &["0..32"]),
        },
    };
    let iter_count = match flag_value(args, "--attempt").as_deref() {
        None => base.mimic.iter_count,
        Some(raw) => match raw.parse::<u32>() {
            Ok(n) if n <= 100 => n,
            _ => bail(lang, K::ErrBadAttempt, raw, &["0..100"]),
        },
    };
    let router_mode = switch(args, "--router", base.router_mode);
    let custom_host = flag_value(args, "--mimic-host")
        .or_else(|| flag_value(args, "--host"))
        .or(base.mimic.custom_host.clone());
    let m = &base.mimic;
    GenOptions {
        version: base.version,
        profile,
        intensity,
        client,
        server_engine,
        router_mode,
        extreme: switch(args, "--extreme", base.extreme),
        junk_level,
        // The 3.x switches. The capability gates inside generate() eat them
        // on versions that do not read them, so a switch on an older version
        // is a no-op rather than a config the device refuses.
        header_protection: switch(args, "--header-protection", base.header_protection),
        content_padding: switch(args, "--content-padding", base.content_padding),
        random_timings: switch(args, "--random-timings", base.random_timings),
        random_trailers: switch(args, "--random-trailers", base.random_trailers),
        disable_cookies: switch(args, "--disable-cookies", base.disable_cookies),
        narrow_h: switch(args, "--narrow-h", base.narrow_h),
        same_s: switch(args, "--same-s", base.same_s),
        disable_h: switch(args, "--disable-h", base.disable_h),
        mimic: MimicOptions {
            mtu,
            mimic_all: switch(args, "--mimic-all", m.mimic_all),
            custom_host,
            region,
            whitelisted_in,
            // Kept so old scripts still parse; generate() decides <c> from the
            // engines on both ends.
            tag_c: has_flag(args, "--tag-c"),
            tag_t: switch(args, "--tag-t", m.tag_t),
            tag_r: switch(args, "--tag-r", m.tag_r),
            tag_rc: switch(args, "--tag-rc", m.tag_rc),
            tag_rd: switch(args, "--tag-rd", m.tag_rd),
            browser,
            router_mode,
            iter_count,
            ..MimicOptions::default()
        },
    }
}

/// A saved set by name, or a clear refusal naming the ones there are.
fn load_set(name: &str, lang: Lang) -> GenOptions {
    let dir = profile::default_config_dir().unwrap_or_else(|e| {
        eprintln!("awg-tool: {e}");
        std::process::exit(2);
    });
    match saved::get(&dir, name) {
        Ok(Some(set)) => set.to_options().unwrap_or_else(|e| {
            eprintln!("awg-tool: {e}");
            std::process::exit(2);
        }),
        Ok(None) => {
            let names: Vec<String> = saved::load_all(&dir)
                .unwrap_or_default()
                .into_iter()
                .map(|s| s.name)
                .collect();
            let valid: Vec<&str> = names.iter().map(String::as_str).collect();
            bail(lang, K::ErrUnknownSet, name, &valid);
        }
        Err(e) => {
            eprintln!("awg-tool: {e}");
            std::process::exit(2);
        }
    }
}

/// `awg-tool sets [list | show NAME | rm NAME]`.
fn cmd_sets(args: &[String], lang: Lang) {
    let dir = profile::default_config_dir().unwrap_or_else(|e| {
        eprintln!("awg-tool: {e}");
        std::process::exit(2);
    });
    let at = args.iter().position(|a| a == "sets").map_or(0, |i| i + 1);
    let words: Vec<&str> = args[at..]
        .iter()
        .filter(|a| !a.starts_with("--"))
        .map(String::as_str)
        .collect();
    match (words.first().copied(), words.get(1).copied()) {
        (None | Some("list" | "ls"), _) => {
            let all = saved::load_all(&dir).unwrap_or_default();
            if all.is_empty() {
                println!("{}", t(lang, K::MsgNoSets));
            }
            for s in all {
                println!(
                    "  {:<16} AWG {:<4} {:<12} {}",
                    s.name, s.version, s.profile, s.client
                );
            }
        }
        (Some("show"), Some(name)) => match saved::get(&dir, name) {
            Ok(Some(s)) => println!("{}", serde_json::to_string_pretty(&s).unwrap_or_default()),
            _ => bail(lang, K::ErrUnknownSet, name, &[]),
        },
        (Some("rm" | "remove"), Some(name)) => match saved::remove(&dir, name) {
            Ok(true) => println!("{} {name}", t(lang, K::MsgRemoved)),
            _ => bail(lang, K::ErrUnknownSet, name, &[]),
        },
        _ => {
            eprintln!("awg-tool sets [list | show NAME | rm NAME]");
            std::process::exit(2);
        }
    }
}

fn cmd_gen(args: &[String], lang: Lang) {
    let opts = gen_options(args, lang);
    let (client, server_engine) = (opts.client, opts.server_engine);
    let (version, profile) = (opts.version, opts.profile);

    // Written down before generating, so a set is saved even when the run
    // is only meant to record the choice.
    if let Some(name) = flag_value(args, "--save") {
        let saved_to = profile::default_config_dir()
            .and_then(|dir| saved::save(&dir, saved::SavedSet::from_options(&name, &opts)));
        match saved_to {
            Ok(()) => eprintln!("{} {name}", t(lang, K::MsgSaved)),
            Err(e) => {
                eprintln!("awg-tool: {e}");
                std::process::exit(1);
            }
        }
    }

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

    /*
     * --json speaks to scripts: the parameter set as an object, plus the raw
     * render, so a wrapper can take either the parsed keys or the exact text
     * without re-parsing. Built from the rendered lines rather than from the
     * internal types — the render is the contract, and this way the JSON can
     * never disagree with what the same run would have written to a file.
     */
    let body = if has_flag(args, "--mihomo") {
        awg_core::mihomo::render(&params, &awg_core::mihomo::MihomoPeer::placeholders())
            .trim_end()
            .to_string()
    } else if has_flag(args, "--json") {
        let mut obj = serde_json::Map::new();
        obj.insert("version".into(), serde_json::json!(version.as_str()));
        obj.insert("profile".into(), serde_json::json!(profile.id()));
        let mut map = serde_json::Map::new();
        for l in &lines {
            if let Some((k, v)) = l.split_once(" = ") {
                map.insert(k.to_string(), serde_json::json!(v));
            }
        }
        obj.insert("params".into(), serde_json::Value::Object(map));
        obj.insert(
            "lines".into(),
            serde_json::json!(lines.iter().collect::<Vec<_>>()),
        );
        serde_json::to_string_pretty(&serde_json::Value::Object(obj))
            .unwrap_or_else(|_| "{}".into())
    } else {
        lines.join("\n")
    };

    match flag_value(args, "--out") {
        // Warnings stay on stderr either way, so a pipe and a file carry the
        // same content and the operator still hears about anything odd.
        Some(path) => {
            std::fs::write(&path, body + "\n").unwrap_or_else(|e| {
                eprintln!("awg-tool: cannot write {path}: {e}");
                std::process::exit(1);
            });
        }
        None => println!("{body}"),
    }

    // Warnings go to stderr so `awg-tool gen > client.conf` stays a valid file.
    let warnings: Vec<_> = versions::validate_for(&params, client, server_engine)
        .into_iter()
        .filter(|v| v.level == Level::Warn)
        .collect();
    if !warnings.is_empty() {
        eprintln!("{}:", t(lang, K::WarningsHeader));
        for w in warnings {
            eprintln!("  {}: {}", w.field, w.text(lang == Lang::Ru));
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
        let tags: Vec<&str> = c
            .tags(versions::AwgVersion::V3_0)
            .iter()
            .map(|k| k.as_str())
            .collect();
        println!(
            "      engine={} maxH={} maxJc={} maxS4={} I1-I5={}",
            c.engine.id(),
            c.max_h_value,
            c.max_jc,
            c.max_s4,
            c.supports_i1_i5
        );
        println!("      tags (2.0+): {}", tags.join(" "));
        for issue in c.known_issues {
            println!("      ! {issue}");
        }
        for r in versions::releases_of(c.id) {
            println!(
                "      --client-release {} ({}): maxH={} maxJc={}",
                r.id, r.label, r.caps.max_h_value, r.caps.max_jc
            );
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

/// `--region`/`--whitelisted`: a region, or `any` (the same as leaving it out).
fn region_flag(args: &[String], flag: &str, lang: Lang) -> Option<Region> {
    let raw = flag_value(args, flag)?;
    if raw.trim().eq_ignore_ascii_case("any") {
        return None;
    }
    match Region::parse(&raw) {
        Some(r) => Some(r),
        None => {
            let mut valid: Vec<&str> = Region::ALL.iter().map(|r| r.id()).collect();
            valid.push("any");
            bail(lang, K::ErrUnknownRegion, &raw, &valid);
        }
    }
}

/// What the mimicry profiles may name, so a pool can be looked at before it
/// is used: `awg-tool hosts --role quic --region ru`.
fn cmd_hosts(args: &[String], lang: Lang) {
    let roles: Vec<Role> = match flag_value(args, "--role") {
        None => Role::ALL.to_vec(),
        Some(raw) => match Role::ALL.into_iter().find(|r| r.id() == raw.trim()) {
            Some(r) => vec![r],
            None => {
                let valid: Vec<&str> = Role::ALL.iter().map(|r| r.id()).collect();
                bail(lang, K::ErrUnknownRole, &raw, &valid);
            }
        },
    };
    let region = region_flag(args, "--region", lang);
    let whitelisted_in = region_flag(args, "--whitelisted", lang);
    let allow_unknown = has_flag(args, "--unknown");
    let list = roles.len() == 1;

    println!("{}:", t(lang, K::CmdHosts));
    for role in roles {
        let found = hostdb::hosts_for(&HostQuery {
            region,
            whitelisted_in,
            allow_unknown,
            ..HostQuery::new(role)
        });
        println!("  {:<6} {}", role.id(), found.len());
        if list {
            for host in found.iter() {
                println!("    {host}");
            }
        }
    }
}

/// `awg-tool under [host]`: the amiunder.vpn question asked from this machine.
/// Exit 0 when the page answered, 1 when it did not, so a script can wait on
/// the tunnel coming up.
fn cmd_under(args: &[String], lang: Lang) {
    let name = check_target(args).unwrap_or_else(|| "amiunder.vpn".to_string());
    let resolver = match flag_value(args, "--resolver") {
        None => std::net::Ipv4Addr::new(172, 29, 172, 254),
        Some(raw) => match raw.trim().parse() {
            Ok(ip) => ip,
            Err(_) => {
                eprintln!("{}: {raw}", t(lang, K::ErrBadResolver));
                std::process::exit(2);
            }
        },
    };
    let secs = match flag_value(args, "--timeout") {
        None => 3,
        Some(raw) => match raw.trim().parse::<u64>() {
            Ok(s) if (1..=60).contains(&s) => s,
            _ => {
                eprintln!("{}: {raw}", t(lang, K::ErrBadTimeout));
                std::process::exit(2);
            }
        },
    };
    let r = awg_core::under::check(&name, resolver, std::time::Duration::from_secs(secs));

    if has_flag(args, "--json") {
        let v = serde_json::json!({
            "under": r.under(),
            "name": r.name,
            "seen": r.seen,
            "tunnel_resolver": r.resolver.to_string(),
            "tunnel_answer": r.tunnel_answer.map(|a| a.to_string()),
            "system_answer": r.system_answer.map(|a| a.to_string()),
        });
        println!("{v}");
    } else {
        match &r.seen {
            Some(seen) => println!("{} {seen}", t(lang, K::UnderYes)),
            None => println!("{}", t(lang, K::UnderNo)),
        }
        match r.tunnel_answer {
            Some(a) => println!("  dns     {name} = {a} @ {resolver}"),
            None => println!("  dns     {} {resolver}", t(lang, K::UnderDnsNone)),
        }
        if r.system_dns_in_tunnel() {
            println!("  system  {}", t(lang, K::UnderSystemYes));
        } else {
            println!("  system  {}", t(lang, K::UnderSystemNo));
        }
    }
    std::process::exit(if r.under() { 0 } else { 1 });
}
/// `--client`, with `--client-release` applied when given.
fn client_flag(args: &[String], lang: Lang) -> &'static ClientCapability {
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
    // An older build of that client, when it differs from the current one.
    match flag_value(args, "--client-release") {
        None => client,
        Some(raw) => match versions::client_release(client.id, Some(&raw)) {
            Some(c) => c,
            None => {
                let mut valid = vec!["current"];
                valid.extend(versions::releases_of(client.id).map(|r| r.id));
                bail(lang, K::ErrUnknownRelease, &raw, &valid);
            }
        },
    }
}

/// `--server-engine`, amneziawg-go when absent.
fn engine_flag(args: &[String], lang: Lang) -> Engine {
    match flag_value(args, "--server-engine") {
        None => Engine::Go,
        Some(raw) => match Engine::parse(&raw) {
            Some(e) => e,
            None => {
                let valid: Vec<&str> = Engine::ALL.iter().map(|e| e.id()).collect();
                bail(lang, K::ErrUnknownEngine, &raw, &valid);
            }
        },
    }
}

/// `--version`, or `default` when absent.
fn version_flag(args: &[String], lang: Lang) -> Option<AwgVersion> {
    let raw = flag_value(args, "--version")?;
    match AwgVersion::parse(&raw) {
        Some(v) => Some(v),
        None => {
            let valid: Vec<&str> = AwgVersion::ALL.iter().map(|v| v.as_str()).collect();
            bail(lang, K::ErrUnknownVersion, &raw, &valid);
        }
    }
}

/// The file, `-` or link after the command word, skipping flags and their
/// values.
fn check_target(args: &[String]) -> Option<String> {
    let cmd = command_of(args)?;
    let at = args.iter().position(|a| a == cmd)?;
    let mut it = args[at + 1..].iter().peekable();
    while let Some(a) = it.next() {
        if VALUE_FLAGS.contains(&a.as_str()) {
            it.next();
        } else if a == "-" || !a.starts_with('-') {
            return Some(a.clone());
        }
    }
    None
}

/// `awg-tool check <file|-|vpn://...>`: read a config someone else wrote and
/// say what is wrong with it. Exit 0 when clean, 1 with warnings, 2 with
/// errors, so a script can gate on it.
fn cmd_check(args: &[String], lang: Lang) {
    let target = check_target(args);
    let Some(target) = target else {
        eprintln!("{}", t(lang, K::ErrCheckWhat));
        std::process::exit(2);
    };
    let text = if target == "-" {
        let mut s = String::new();
        if let Err(e) = std::io::Read::read_to_string(&mut std::io::stdin(), &mut s) {
            eprintln!("awg-tool: stdin: {e}");
            std::process::exit(2);
        }
        s
    } else if target.starts_with("vpn://") {
        target
    } else {
        match std::fs::read_to_string(&target) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("awg-tool: {target}: {e}");
                std::process::exit(2);
            }
        }
    };

    let opts = CheckOptions {
        client: client_flag(args, lang),
        server_engine: engine_flag(args, lang),
        version: version_flag(args, lang),
    };
    let report = check::check(&text, &opts);

    if has_flag(args, "--json") {
        let findings: Vec<serde_json::Value> = report
            .findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "level": level_word(f.level),
                    "field": f.field,
                    "code": f.code,
                    "message": f.message,
                    "message_ru": f.message_ru,
                })
            })
            .collect();
        let out = serde_json::json!({
            "version": report.version.map(|v| v.as_str()),
            "version_inferred": report.version_inferred,
            "client": opts.client.id,
            "server_engine": opts.server_engine.id(),
            "findings": findings,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    } else {
        match report.version {
            Some(v) => println!(
                "{}: AWG {v}{}",
                t(lang, K::LblVersion),
                if report.version_inferred {
                    format!(" ({})", t(lang, K::MsgInferred))
                } else {
                    String::new()
                }
            ),
            None => println!("{}", t(lang, K::MsgNotAwg)),
        }
        println!(
            "{}: {} ({})",
            t(lang, K::LblClient),
            opts.client.name,
            opts.client.engine.id()
        );
        if report.findings.is_empty() {
            println!("{}", t(lang, K::MsgCheckClean));
        }
        for f in &report.findings {
            let level = match (lang, f.level) {
                (Lang::Ru, Level::Error) => "ошибка",
                (Lang::Ru, Level::Warn) => "внимание",
                (Lang::Ru, Level::Info) => "заметка",
                (_, l) => level_word(l),
            };
            println!("  {level:<8} {:<20} {}", f.field, f.text(lang == Lang::Ru));
        }
    }

    std::process::exit(match report.worst() {
        Some(Level::Error) => 2,
        Some(Level::Warn) => 1,
        _ => 0,
    });
}

fn level_word(l: Level) -> &'static str {
    match l {
        Level::Error => "error",
        Level::Warn => "warning",
        Level::Info => "note",
    }
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
    fn check_finds_its_target_whatever_the_flags_around_it() {
        assert_eq!(
            check_target(&a(&["check", "x.conf"])).as_deref(),
            Some("x.conf")
        );
        assert_eq!(
            check_target(&a(&["lint", "x.conf"])).as_deref(),
            Some("x.conf")
        );
        assert_eq!(
            check_target(&a(&[
                "--client",
                "wiresock",
                "check",
                "--version",
                "3.1",
                "-"
            ]))
            .as_deref(),
            Some("-")
        );
        assert_eq!(
            check_target(&a(&["check", "--json", "vpn://AA"])).as_deref(),
            Some("vpn://AA")
        );
        assert_eq!(check_target(&a(&["check", "--json"])), None);
    }

    #[test]
    fn the_generator_value_flags_are_skipped() {
        for flag in [
            "--client-release",
            "--server-engine",
            "--region",
            "--whitelisted",
            "--role",
        ] {
            assert_eq!(command_of(&a(&[flag, "x", "gen"])), Some("gen"), "{flag}");
        }
    }

    #[test]
    fn a_switch_word_is_skipped_and_never_the_command() {
        assert_eq!(command_of(&a(&["--attempt", "4", "gen"])), Some("gen"));
        assert_eq!(command_of(&a(&["--disable-h", "off", "gen"])), Some("gen"));
        assert_eq!(command_of(&a(&["--mimic-all", "gen"])), Some("gen"));
    }

    #[test]
    fn a_switch_reads_its_word_or_stands_for_on() {
        let args = a(&[
            "gen",
            "--same-s",
            "--disable-h",
            "off",
            "--tag-rc",
            "no",
            "--uapi",
        ]);
        assert!(switch(&args, "--same-s", false));
        assert!(!switch(&args, "--disable-h", true));
        assert!(!switch(&args, "--tag-rc", true));
        assert!(
            switch(&args, "--random-trailers", true),
            "absent keeps the default"
        );
        assert!(!switch(&args, "--random-trailers", false));
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
