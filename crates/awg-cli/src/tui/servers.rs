//! The Servers screen: saved connections and this machine's own docker, what is
//! running on the one you pick, why it is unhappy, and its peers and resolver.
//!
//! Every question here is answered by `awg_core::docker`, the same code the
//! `status`, `doctor` and `logs` commands call. Two implementations of "is this
//! node healthy" would eventually disagree, and the one people trusted would be
//! whichever they happened to be looking at.
//!
//! Calls block the draw loop. For an SSH round trip on a local network that is
//! a flicker; on a slow link it is a pause. A background thread would need the
//! session to cross threads and would buy responsiveness in a screen whose only
//! job is to wait for a server anyway.

use awg_core::docker::dns::{self as dnsctl, List as DnsList};
use awg_core::docker::image::Generation;
use awg_core::docker::{self, Container, Host};
use awg_core::profile::{self, Profile};
use awg_core::ssh::{self, Session};
use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, Paragraph, Wrap};

use crate::i18n::{Key as K, Lang, t};
use crate::theme;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pane {
    Profiles,
    Containers,
}

/// What a line of typing is for. The name typed is the confirmation too: a
/// peer is revoked only by naming it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ask {
    Block,
    Unblock,
    Allow,
    Unallow,
    Query,
    PeerAdd,
    PeerRm,
    /// The node's own name, typed to confirm a rotation already shown.
    Rotate,
}

impl Ask {
    fn prompt(self, lang: Lang) -> &'static str {
        t(
            lang,
            match self {
                Ask::Block => K::AskBlock,
                Ask::Unblock => K::AskUnblock,
                Ask::Allow => K::AskAllow,
                Ask::Unallow => K::AskUnallow,
                Ask::Query => K::AskQuery,
                Ask::PeerAdd => K::AskPeerAdd,
                Ask::PeerRm => K::AskPeerRm,
                Ask::Rotate => K::AskRotateName,
            },
        )
    }

    /// Names, labels and public keys: nothing else is ever typed here.
    fn accepts(self, c: char) -> bool {
        c.is_ascii_alphanumeric()
            || match self {
                Ask::PeerRm => "._-+/=".contains(c),
                Ask::PeerAdd | Ask::Rotate => "._-".contains(c),
                _ => ".-_*".contains(c),
            }
    }
}

/// Not `Debug`, for the same reason `crate::remote::Target` is not: it can hold
/// a stored password for the length of a session.
pub struct Servers {
    profiles: Vec<Profile>,
    profile_idx: usize,
    pane: Pane,
    session: Option<Session>,
    /// Only ever the account password, never a key passphrase: it is what
    /// `sudo -S` reads. See `crate::remote::Target`.
    sudo_password: Option<String>,
    sudo: bool,
    connected_to: Option<String>,
    containers: Vec<Container>,
    summaries: Vec<String>,
    container_idx: usize,
    detail_title: String,
    detail: Vec<Line<'static>>,
    message: Option<(String, bool)>,
    /// Docker answers on this machine, so it is offered as the first row.
    local_row: bool,
    /// Connected to this machine's docker rather than over SSH.
    local: bool,
    input: Option<(Ask, String)>,
    /// A rotation worked out and shown, waiting for its confirmation.
    pending: Option<awg_core::docker::rotate::RotationPlan>,
}

impl Servers {
    pub fn new() -> Self {
        Self {
            profiles: Vec::new(),
            profile_idx: 0,
            pane: Pane::Profiles,
            session: None,
            sudo_password: None,
            sudo: false,
            connected_to: None,
            containers: Vec::new(),
            summaries: Vec::new(),
            container_idx: 0,
            detail_title: String::new(),
            detail: Vec::new(),
            message: None,
            local_row: false,
            local: false,
            input: None,
            pending: None,
        }
    }

    /// Read the saved profiles. Called when the screen is opened rather than at
    /// start-up, so a tool that is only ever used to generate configs never
    /// touches the config directory at all.
    pub fn open(&mut self, lang: Lang) {
        self.local_row = docker::docker_available();
        match profile::default_config_dir().and_then(|d| profile::load_all(&d)) {
            Ok(p) => {
                self.profiles = p;
                if self.profiles.is_empty() && !self.local_row {
                    self.message = Some((t(lang, K::MsgNoSavedProfiles).into(), false));
                }
            }
            Err(e) => self.message = Some((e.to_string(), true)),
        }
    }

    fn host(&self) -> Option<Host<'_>> {
        if self.local {
            return Some(Host::local());
        }
        self.session
            .as_ref()
            .map(|s| Host::new(s, self.sudo_password.as_deref()).with_docker_sudo(self.sudo))
    }

    /// Rows in the connections pane: this machine first when it has docker.
    fn rows(&self) -> usize {
        self.profiles.len() + usize::from(self.local_row)
    }

    /// Whether a line is being typed: then every key is input.
    pub fn typing(&self) -> bool {
        self.input.is_some()
    }

    fn connect(&mut self, lang: Lang) {
        if self.local_row && self.profile_idx == 0 {
            self.session = None;
            self.sudo_password = None;
            self.local = true;
            self.connected_to = None;
            self.message = None;
            self.pane = Pane::Containers;
            self.refresh(lang);
            return;
        }
        let at = self.profile_idx - usize::from(self.local_row);
        let Some(p) = self.profiles.get(at).cloned() else {
            return;
        };
        self.message = None;

        // A password would have to be typed into this screen, and a text field
        // that must never echo, never redraw its contents and never reach a
        // panic message is not something to add in passing. Stored secrets work
        // here; the rest is one command away and says so.
        let secret = if p.auth.needs_secret() {
            let stored = profile::default_config_dir()
                .ok()
                .and_then(|d| profile::load_password(&d, &p.name).ok())
                .flatten();
            match stored {
                Some(s) => Some(s),
                None => {
                    self.message = Some((
                        format!(
                            "{} · awg-tool status --server {}",
                            t(lang, K::MsgNeedsCli),
                            p.name
                        ),
                        true,
                    ));
                    return;
                }
            }
        } else {
            None
        };

        match ssh::connect(&p, secret.as_deref()) {
            Ok(s) => {
                self.local = false;
                self.sudo = p.sudo_required;
                self.connected_to = Some(p.name.clone());
                self.session = Some(s);
                // A key passphrase is not a sudo password, so only a real login
                // password is kept for privileged calls.
                self.sudo_password = matches!(p.auth, awg_core::profile::Auth::Password)
                    .then(|| secret.clone())
                    .flatten();
                self.pane = Pane::Containers;
                self.refresh(lang);
            }
            Err(e) => self.message = Some((e.to_string(), true)),
        }
    }

    fn refresh(&mut self, lang: Lang) {
        let Some(host) = self.host() else { return };
        let found = if self.local {
            docker::find_local_containers()
        } else {
            docker::find_awg_containers(&host)
        };
        match found {
            Ok(found) => {
                self.summaries = found.iter().map(|c| summarise(&host, c, lang)).collect();
                self.containers = found;
                self.container_idx = 0;
                self.detail.clear();
                self.detail_title.clear();
                if self.containers.is_empty() {
                    self.message = Some((t(lang, K::MsgNoContainers).into(), false));
                } else {
                    self.message = None;
                }
            }
            Err(e) => self.message = Some((e.to_string(), true)),
        }
    }

    // The results are built first and stored afterwards, on purpose: `host`
    // borrows `self`, so writing into `self` while it is alive does not
    // compile. Assigning at the end also means a failed call leaves the
    // previous panel intact rather than half-replacing it.
    fn diagnose(&mut self, lang: Lang) {
        let Some(host) = self.host() else { return };
        let Some(c) = self.containers.get(self.container_idx) else {
            return;
        };
        let title = format!("{} · {}", t(lang, K::MenuDoctor), c.name);
        let lines = match docker::diagnose_container(&host, c, None) {
            Ok(d) => {
                let mut out = Vec::new();
                if d.healthy {
                    out.push(Line::from(Span::styled(
                        format!("✓ {}", t(lang, K::MsgNoFaults)),
                        theme::ok(),
                    )));
                }
                for f in &d.findings {
                    let (mark, style) = match f.confidence {
                        docker::Confidence::Confirmed => ("✕", theme::error()),
                        docker::Confidence::Likely => ("!", theme::warn()),
                        docker::Confidence::Possible => ("?", theme::dim()),
                    };
                    out.push(Line::from(vec![
                        Span::styled(format!("{mark} "), style),
                        Span::styled(f.what.clone(), theme::base()),
                    ]));
                    for e in &f.evidence {
                        out.push(Line::from(Span::styled(format!("    · {e}"), theme::dim())));
                    }
                    out.push(Line::from(Span::styled(
                        format!("    → {}", f.next_step),
                        theme::base(),
                    )));
                    for a in &f.alternatives {
                        out.push(Line::from(Span::styled(
                            format!("    ~ {a}"),
                            theme::faint(),
                        )));
                    }
                }
                // Shown even alongside findings: what could not be looked at
                // changes how much the rest of the verdict is worth.
                for b in &d.blind_spots {
                    out.push(Line::from(Span::styled(format!("? {b}"), theme::faint())));
                }
                out
            }
            Err(e) => vec![Line::from(Span::styled(e.to_string(), theme::error()))],
        };
        self.detail_title = title;
        self.detail = lines;
    }

    fn logs(&mut self, lang: Lang) {
        let Some(host) = self.host() else { return };
        let Some(c) = self.containers.get(self.container_idx) else {
            return;
        };
        let title = format!("{} · {}", t(lang, K::MenuLogs), c.name);
        // Redaction happens in the core, on the way out of `docker::logs`.
        // Nothing on this side needs to know which fields were secret.
        let lines = match docker::logs(&host, &c.name, 400) {
            Ok(text) => text
                .lines()
                .map(|l| Line::from(Span::styled(l.to_string(), theme::base())))
                .collect(),
            Err(e) => vec![Line::from(Span::styled(e.to_string(), theme::error()))],
        };
        self.detail_title = title;
        self.detail = lines;
    }

    fn selected(&self) -> Option<&Container> {
        self.containers.get(self.container_idx)
    }

    /// The running resolver: the selected container when it is one, else the
    /// first running one on this host.
    fn resolver(&self) -> Option<String> {
        let is = |c: &&Container| c.generation == Some(Generation::Dns);
        self.selected()
            .filter(is)
            .or_else(|| {
                self.containers
                    .iter()
                    .filter(is)
                    .find(|c| c.state.is_running())
            })
            .map(|c| c.name.clone())
    }

    /// The node peers belong to: the selected container when it is one, else
    /// the first running node.
    fn node(&self) -> Option<String> {
        let is = |c: &&Container| c.generation.and_then(|g| g.awg()).is_some();
        self.selected()
            .filter(is)
            .or_else(|| {
                self.containers
                    .iter()
                    .filter(is)
                    .find(|c| c.state.is_running())
            })
            .map(|c| c.name.clone())
    }

    fn show(&mut self, title: String, lines: Vec<Line<'static>>) {
        self.detail_title = title;
        self.detail = lines;
    }

    fn dns_lines(&self, host: &Host, name: &str, lang: Lang) -> Vec<Line<'static>> {
        let s = match dnsctl::status(host, name) {
            Ok(s) => s,
            Err(e) => return vec![Line::from(Span::styled(e.to_string(), theme::error()))],
        };
        let mut out = vec![
            Line::from(Span::styled(
                format!("● {name}  ({} {})", t(lang, K::LblMode), s.mode),
                theme::ok(),
            )),
            Line::from(Span::styled(
                format!(
                    "  {} {}   {} {}",
                    t(lang, K::LblBlocked),
                    s.blocked,
                    t(lang, K::LblAllowed),
                    s.allowed
                ),
                theme::base(),
            )),
        ];
        if let Some(q) = s.stat("total.num.queries") {
            let hits = s.stat("total.num.cachehits").unwrap_or(0);
            let share = (hits * 100).checked_div(q).unwrap_or(0);
            out.push(Line::from(Span::styled(
                format!(
                    "  {} {q}, {} {share}%",
                    t(lang, K::LblQueries),
                    t(lang, K::LblCacheHits)
                ),
                theme::dim(),
            )));
        }
        for z in &s.zones {
            out.push(Line::from(Span::styled(
                format!("  {}: {z}", t(lang, K::LblZone)),
                theme::dim(),
            )));
        }
        let hops = s.chain_hops();
        if !hops.is_empty() {
            out.push(Line::from(""));
            out.push(Line::from(Span::styled(
                format!("{}:", t(lang, K::LblChain)),
                theme::base(),
            )));
            for (i, h) in hops.iter().enumerate() {
                out.push(Line::from(vec![
                    Span::styled(format!("  {}. {:<24}", i + 1, h.addr), theme::base()),
                    Span::styled(
                        format!(
                            " {} {}  {} {} ({} {})",
                            t(lang, K::LblAnswered),
                            h.answered,
                            t(lang, K::LblPassedOn),
                            h.passed,
                            t(lang, K::LblTimeouts),
                            h.timeouts
                        ),
                        theme::dim(),
                    ),
                ]));
            }
        }
        for (label, names) in [("block", &s.managed_block), ("allow", &s.managed_allow)] {
            if names.is_empty() {
                continue;
            }
            out.push(Line::from(""));
            out.push(Line::from(Span::styled(format!("{label}:"), theme::base())));
            for n in names {
                out.push(Line::from(Span::styled(format!("  {n}"), theme::dim())));
            }
        }
        out
    }

    fn dns(&mut self, lang: Lang, note: Option<Line<'static>>) {
        let Some(host) = self.host() else { return };
        let Some(name) = self.resolver() else {
            self.message = Some((t(lang, K::MsgNoResolver).into(), true));
            self.detail.clear();
            return;
        };
        let mut lines: Vec<Line<'static>> = note.into_iter().collect();
        lines.extend(self.dns_lines(&host, &name, lang));
        self.show(format!("DNS · {name}"), lines);
    }

    fn peer_lines(&self, host: &Host, node: &str, lang: Lang) -> Vec<Line<'static>> {
        match docker::peers::list(host, node) {
            Ok(rows) if rows.is_empty() => {
                vec![Line::from(Span::styled(
                    t(lang, K::MsgNoPeers),
                    theme::dim(),
                ))]
            }
            Ok(rows) => rows
                .into_iter()
                .map(|r| {
                    let key: String = r.public_key.chars().take(10).collect();
                    Line::from(vec![
                        Span::styled(format!("{:<16}", r.label), theme::base()),
                        Span::styled(format!(" {:<18}", r.allowed_ips), theme::dim()),
                        Span::styled(format!(" {key}… "), theme::faint()),
                        Span::styled(r.last_handshake, theme::dim()),
                    ])
                })
                .collect(),
            Err(e) => vec![Line::from(Span::styled(e.to_string(), theme::error()))],
        }
    }

    fn peers(&mut self, lang: Lang, note: Option<Line<'static>>) {
        let Some(host) = self.host() else { return };
        let Some(node) = self.node() else {
            self.message = Some((t(lang, K::MsgNoContainers).into(), true));
            self.detail.clear();
            return;
        };
        let mut lines: Vec<Line<'static>> = note.into_iter().collect();
        lines.extend(self.peer_lines(&host, &node, lang));
        self.show(format!("{} · {node}", t(lang, K::MenuPeers)), lines);
    }

    /// Issue a peer: the config is shown and written next to the saved
    /// connections, since copying a private key off a terminal screen is how
    /// it ends up in a scrollback buffer somewhere.
    fn add_peer(&mut self, label: &str, lang: Lang) {
        let Some(host) = self.host() else { return };
        let Some(node) = self.node() else { return };
        let conf = match docker::peers::add(&host, &node, label, None) {
            Ok(c) => c,
            Err(e) => {
                let line = Line::from(Span::styled(e.to_string(), theme::error()));
                return self.peers(lang, Some(line));
            }
        };
        let saved = profile::default_config_dir()
            .map(|d| d.join("issued"))
            .map_err(|e| e.to_string())
            .and_then(|dir| {
                std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
                let path = dir.join(format!("{node}-{label}.conf"));
                crate::ops::write_private(&path.to_string_lossy(), &conf)
                    .map_err(|e| e.to_string())?;
                Ok(path)
            });
        let mut lines = vec![match &saved {
            Ok(p) => Line::from(Span::styled(
                format!("✓ {label}: {} {}", t(lang, K::MsgWrote), p.display()),
                theme::ok(),
            )),
            Err(e) => Line::from(Span::styled(format!("! {e}"), theme::warn())),
        }];
        lines.push(Line::from(Span::styled(
            t(lang, K::MsgPeerPrivate),
            theme::warn(),
        )));
        lines.push(Line::from(""));
        lines.extend(
            conf.lines()
                .map(|l| Line::from(Span::styled(l.to_string(), theme::base()))),
        );
        if let Ok(link) = awg_core::vpn::conf_to_vpn(&conf) {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(link, theme::dim())));
        }
        self.show(format!("{} · {node}", t(lang, K::MenuPeers)), lines);
    }

    /// Work out a rotation for the selected node and show it; nothing is
    /// written until its name is typed back.
    fn plan_rotation(&mut self, lang: Lang) {
        use awg_core::docker::rotate;
        let Some(host) = self.host() else { return };
        let Some(name) = self.node() else { return };
        let Some(node) = self.containers.iter().find(|c| c.name == name) else {
            return;
        };
        let Some(version) = node.generation.and_then(|g| g.awg()) else {
            return;
        };
        let opts = awg_core::versions::GenOptions::for_version(version);
        let title = format!("{} · {name}", t(lang, K::HintRotate));
        match rotate::plan(&host, node, &opts) {
            Ok(plan) => {
                let mut lines = vec![
                    Line::from(Span::styled(
                        format!(
                            "{} {} (AWG {version})",
                            t(lang, K::MsgRotating),
                            plan.container
                        ),
                        theme::base(),
                    )),
                    Line::from(Span::styled(
                        format!("  {}: {}", t(lang, K::LblConfigFile), plan.host_path),
                        theme::dim(),
                    )),
                    Line::from(Span::styled(
                        format!(
                            "  {} ({}): {}",
                            t(lang, K::LblChanges),
                            plan.changed.len(),
                            plan.changed.join(", ")
                        ),
                        theme::dim(),
                    )),
                ];
                if let Ok(rows) = docker::peers::list(&host, &plan.container)
                    && !rows.is_empty()
                {
                    let labels: Vec<&str> = rows.iter().map(|r| r.label.as_str()).collect();
                    lines.push(Line::from(Span::styled(
                        format!(
                            "  {}: {}",
                            t(lang, K::LblClientsToUpdate),
                            labels.join(", ")
                        ),
                        theme::dim(),
                    )));
                }
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    t(lang, K::AskRotate),
                    theme::warn(),
                )));
                self.show(title, lines);
                self.pending = Some(plan);
                self.input = Some((Ask::Rotate, String::new()));
            }
            Err(e) => {
                let line = Line::from(Span::styled(e.to_string(), theme::error()));
                self.show(title, vec![line]);
            }
        }
    }

    /// Apply the shown rotation once the node's name was typed back. The new
    /// block is shown and written next to the issued configs, since every
    /// client needs it.
    fn rotate(&mut self, typed: &str, lang: Lang) {
        use awg_core::docker::rotate;
        let Some(plan) = self.pending.take() else {
            return;
        };
        let title = format!("{} · {}", t(lang, K::HintRotate), plan.container);
        if typed != plan.container {
            let line = Line::from(Span::styled(t(lang, K::MsgAborted), theme::warn()));
            return self.show(title, vec![line]);
        }
        let Some(host) = self.host() else { return };
        let mut lines = Vec::new();
        match rotate::apply(&host, &plan) {
            Ok(a) if a.rolled_back => lines.push(Line::from(Span::styled(
                format!("{} {}", t(lang, K::MsgRotateRolledBack), a.backup),
                theme::error(),
            ))),
            Ok(a) => {
                lines.push(Line::from(Span::styled(
                    format!("✓ {} {}", t(lang, K::MsgRotated), a.backup),
                    theme::ok(),
                )));
                let mut block = plan.client_block().join("\n");
                block.push('\n');
                let saved = profile::default_config_dir()
                    .map(|d| d.join("issued"))
                    .map_err(|e| e.to_string())
                    .and_then(|dir| {
                        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
                        let path = dir.join(format!("{}-obfuscation.conf", plan.container));
                        crate::ops::write_private(&path.to_string_lossy(), &block)
                            .map_err(|e| e.to_string())?;
                        Ok(path)
                    });
                if let Ok(p) = saved {
                    lines.push(Line::from(Span::styled(
                        format!("{} {}", t(lang, K::MsgWrote), p.display()),
                        theme::dim(),
                    )));
                }
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    t(lang, K::MsgClientBlock),
                    theme::base(),
                )));
                lines.extend(
                    block
                        .lines()
                        .map(|l| Line::from(Span::styled(l.to_string(), theme::base()))),
                );
            }
            Err(e) => lines.push(Line::from(Span::styled(e.to_string(), theme::error()))),
        }
        self.show(title, lines);
    }
    fn run_ask(&mut self, ask: Ask, text: &str, lang: Lang) {
        let text = text.trim();
        if text.is_empty() {
            return;
        }
        let note = |r: awg_core::Result<String>| match r {
            Ok(msg) => Line::from(Span::styled(
                format!("✓ {msg} · {}", t(lang, K::MsgDnsReloads)),
                theme::ok(),
            )),
            Err(e) => Line::from(Span::styled(e.to_string(), theme::error())),
        };
        match ask {
            Ask::PeerAdd => self.add_peer(text, lang),
            Ask::Rotate => self.rotate(text, lang),
            Ask::PeerRm => {
                let (Some(host), Some(node)) = (self.host(), self.node()) else {
                    return;
                };
                let line = match docker::peers::remove(&host, &node, text) {
                    Ok(msg) => Line::from(Span::styled(format!("✓ {msg}"), theme::ok())),
                    Err(e) => Line::from(Span::styled(e.to_string(), theme::error())),
                };
                self.peers(lang, Some(line));
            }
            Ask::Query => {
                let (Some(host), Some(name)) = (self.host(), self.resolver()) else {
                    return;
                };
                let mut lines = vec![Line::from(Span::styled(format!("? {text}"), theme::base()))];
                match dnsctl::query(&host, &name, text) {
                    Ok(a) if a.is_empty() => lines.push(Line::from(Span::styled(
                        format!("  {}", t(lang, K::MsgNoAnswer)),
                        theme::warn(),
                    ))),
                    Ok(a) => lines.extend(
                        a.into_iter()
                            .map(|l| Line::from(Span::styled(format!("  {l}"), theme::ok()))),
                    ),
                    Err(e) => lines.push(Line::from(Span::styled(e.to_string(), theme::error()))),
                }
                self.show(format!("DNS · {name}"), lines);
            }
            _ => {
                let (Some(host), Some(name)) = (self.host(), self.resolver()) else {
                    return;
                };
                let (list, add) = match ask {
                    Ask::Block => (DnsList::Block, true),
                    Ask::Unblock => (DnsList::Block, false),
                    Ask::Allow => (DnsList::Allow, true),
                    _ => (DnsList::Allow, false),
                };
                let line = note(dnsctl::edit(&host, &name, list, text, add));
                self.dns(lang, Some(line));
            }
        }
    }

    /// The keys the footer should offer for what is selected now.
    pub fn hints(&self, lang: Lang) -> Vec<(&'static str, &'static str)> {
        if let Some((_, _)) = &self.input {
            return vec![
                ("↵", t(lang, K::HintConfirm)),
                ("Esc", t(lang, K::HintCancel)),
            ];
        }
        let mut h = vec![
            ("↑↓", t(lang, K::HintMove)),
            ("Tab", t(lang, K::HintSwitchPane)),
        ];
        if self.pane == Pane::Profiles || self.containers.is_empty() {
            h.push(("↵", t(lang, K::HintConnect)));
            return h;
        }
        let on_resolver = self
            .selected()
            .is_some_and(|c| c.generation == Some(Generation::Dns));
        if on_resolver {
            h.extend([
                ("b/B", t(lang, K::HintBlock)),
                ("a/A", t(lang, K::HintAllow)),
                ("/", t(lang, K::HintQuery)),
            ]);
        } else {
            h.extend([
                ("d", t(lang, K::MenuDoctor)),
                ("p", t(lang, K::MenuPeers)),
                ("+/-", t(lang, K::HintPeerAddRm)),
                ("R", t(lang, K::HintRotate)),
                ("n", "DNS"),
            ]);
        }
        h.extend([("L", t(lang, K::MenuLogs)), ("r", t(lang, K::HintRefresh))]);
        h
    }
    /// Returns true when the key was consumed, so the caller can fall through
    /// to its own navigation when it was not.
    pub fn on_key(&mut self, code: KeyCode, lang: Lang) -> bool {
        if let Some((ask, mut text)) = self.input.take() {
            match code {
                KeyCode::Esc => self.pending = None,
                KeyCode::Enter => self.run_ask(ask, &text, lang),
                KeyCode::Backspace => {
                    text.pop();
                    self.input = Some((ask, text));
                }
                KeyCode::Char(c) if ask.accepts(c) => {
                    text.push(c);
                    self.input = Some((ask, text));
                }
                _ => self.input = Some((ask, text)),
            }
            return true;
        }
        let len = match self.pane {
            Pane::Profiles => self.rows(),
            Pane::Containers => self.containers.len(),
        };
        let connected = self.host().is_some() && !self.containers.is_empty();
        let ask = match code {
            KeyCode::Char('b') => Some(Ask::Block),
            KeyCode::Char('B') => Some(Ask::Unblock),
            KeyCode::Char('a') => Some(Ask::Allow),
            KeyCode::Char('A') => Some(Ask::Unallow),
            KeyCode::Char('/') => Some(Ask::Query),
            KeyCode::Char('+') => Some(Ask::PeerAdd),
            KeyCode::Char('-') => Some(Ask::PeerRm),
            KeyCode::Char('R') if connected => {
                self.plan_rotation(lang);
                return true;
            }
            _ => None,
        };
        if let Some(ask) = ask.filter(|_| connected) {
            self.input = Some((ask, String::new()));
            return true;
        }
        match code {
            KeyCode::Char('n') if connected => {
                self.dns(lang, None);
                return true;
            }
            KeyCode::Char('p') if connected => {
                self.peers(lang, None);
                return true;
            }
            KeyCode::Enter
                if self.pane == Pane::Containers
                    && self
                        .selected()
                        .is_some_and(|c| c.generation == Some(Generation::Dns)) =>
            {
                self.dns(lang, None);
                return true;
            }
            _ => {}
        }
        match code {
            KeyCode::Tab => {
                self.pane = match self.pane {
                    Pane::Profiles if !self.containers.is_empty() => Pane::Containers,
                    _ => Pane::Profiles,
                };
                true
            }
            KeyCode::Down | KeyCode::Char('j') if len > 0 => {
                let i = match self.pane {
                    Pane::Profiles => &mut self.profile_idx,
                    Pane::Containers => &mut self.container_idx,
                };
                *i = (*i + 1) % len;
                true
            }
            KeyCode::Up | KeyCode::Char('k') if len > 0 => {
                let i = match self.pane {
                    Pane::Profiles => &mut self.profile_idx,
                    Pane::Containers => &mut self.container_idx,
                };
                *i = (*i + len - 1) % len;
                true
            }
            KeyCode::Enter => {
                match self.pane {
                    Pane::Profiles => self.connect(lang),
                    Pane::Containers => self.diagnose(lang),
                }
                true
            }
            KeyCode::Char('d') => {
                self.diagnose(lang);
                true
            }
            KeyCode::Char('L') => {
                self.logs(lang);
                true
            }
            KeyCode::Char('r') => {
                self.refresh(lang);
                true
            }
            _ => false,
        }
    }

    pub fn detail_lines(&self) -> &[Line<'static>] {
        &self.detail
    }

    pub fn draw(&self, f: &mut ratatui::Frame, area: Rect, lang: Lang, scroll: u16) {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(34), Constraint::Min(30)])
            .split(area);
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(cols[0]);

        let shift = usize::from(self.local_row);
        let pick = |i: usize| i == self.profile_idx && self.pane == Pane::Profiles;
        let mut items: Vec<ListItem> = Vec::new();
        if self.local_row {
            items.push(ListItem::new(Line::from(vec![
                Span::styled(if self.local { "● " } else { "  " }, theme::ok()),
                Span::styled(
                    t(lang, K::LblThisMachine).to_string(),
                    if pick(0) {
                        theme::selected()
                    } else {
                        theme::base()
                    },
                ),
            ])));
        }
        items.extend(self.profiles.iter().enumerate().map(|(i, p)| {
            let i = i + shift;
            {
                let live = !self.local && self.connected_to.as_deref() == Some(p.name.as_str());
                ListItem::new(Line::from(vec![
                    Span::styled(if live { "● " } else { "  " }, theme::ok()),
                    Span::styled(
                        format!("{:<16}", p.name),
                        if pick(i) {
                            theme::selected()
                        } else {
                            theme::base()
                        },
                    ),
                    Span::styled(format!(" {}@{}", p.user, p.host), theme::faint()),
                ]))
            }
        }));
        f.render_widget(
            List::new(items).block(super::panel(
                t(lang, K::PanelProfiles),
                self.pane == Pane::Profiles,
            )),
            rows[0],
        );

        let items: Vec<ListItem> = self
            .containers
            .iter()
            .enumerate()
            .map(|(i, c)| {
                ListItem::new(vec![
                    Line::from(Span::styled(
                        format!(" {}", c.name),
                        if i == self.container_idx && self.pane == Pane::Containers {
                            theme::selected()
                        } else {
                            theme::base()
                        },
                    )),
                    Line::from(Span::styled(
                        format!("   {}", self.summaries.get(i).cloned().unwrap_or_default()),
                        theme::dim(),
                    )),
                ])
            })
            .collect();
        f.render_widget(
            List::new(items).block(super::panel(
                t(lang, K::PanelNodes),
                self.pane == Pane::Containers,
            )),
            rows[1],
        );

        let title = if self.detail_title.is_empty() {
            t(lang, K::PanelDetail).to_string()
        } else {
            self.detail_title.clone()
        };
        let body: Vec<Line> = if self.detail.is_empty() {
            match &self.message {
                Some((m, bad)) => vec![Line::from(Span::styled(
                    m.clone(),
                    if *bad { theme::error() } else { theme::dim() },
                ))],
                None => vec![Line::from(Span::styled(
                    t(lang, K::HintPickProfile),
                    theme::dim(),
                ))],
            }
        } else {
            self.detail.clone()
        };
        // A line being typed gets a pane of its own above the details, so
        // what it will act on stays in view while it is typed.
        let right = match &self.input {
            Some((ask, text)) => {
                let split = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Length(3), Constraint::Min(3)])
                    .split(cols[1]);
                f.render_widget(
                    Paragraph::new(Line::from(vec![
                        Span::styled(text.clone(), theme::base()),
                        Span::styled("█", theme::ok()),
                    ]))
                    .block(super::panel(ask.prompt(lang), true)),
                    split[0],
                );
                split[1]
            }
            None => cols[1],
        };
        let s = super::clamp_scroll(scroll, &body, right);
        f.render_widget(
            Paragraph::new(body.clone())
                .wrap(Wrap { trim: false })
                .scroll((s, 0))
                .block(super::panel(
                    &format!("{title}{}", super::scroll_marker(s, &body, right)),
                    false,
                )),
            right,
        );
    }
}

/// One line per node: enough to tell a working server from a sick one without
/// opening anything.
fn summarise(host: &Host, c: &Container, lang: Lang) -> String {
    if !c.state.is_running() {
        return c.state.as_str().to_string();
    }
    let iface = docker::inspect(host, &c.name)
        .map(|i| i.interface())
        .unwrap_or_else(|_| "awg0".into());
    match docker::health(host, &c.name, &iface) {
        Ok(h) => format!(
            "{} {} · {} {}/{}",
            if h.interface_up && h.uapi_ok {
                "✓"
            } else {
                "✕"
            },
            iface,
            t(lang, K::LblPeers),
            h.peers_ever_handshaked(),
            h.peer_count()
        ),
        Err(_) => format!("✕ {}", t(lang, K::LblUnreachable)),
    }
}

impl Default for Servers {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(s: &mut Servers, keys: &str) {
        for c in keys.chars() {
            assert!(s.on_key(KeyCode::Char(c), Lang::En));
        }
    }

    #[test]
    fn nothing_starts_typing_before_there_is_something_to_act_on() {
        let mut s = Servers::new();
        for c in ['b', 'a', '+', '-', '/'] {
            s.on_key(KeyCode::Char(c), Lang::En);
            assert!(!s.typing(), "{c} opened a prompt with nothing connected");
        }
    }

    #[test]
    fn a_prompt_takes_every_key_and_only_what_the_answer_can_hold() {
        let mut s = Servers::new();
        s.input = Some((Ask::Block, String::new()));
        typed(&mut s, "ads.Example-1.com q");
        assert_eq!(s.input.as_ref().unwrap().1, "ads.Example-1.comq");
        assert!(s.on_key(KeyCode::Backspace, Lang::En));
        assert_eq!(s.input.as_ref().unwrap().1, "ads.Example-1.com");
        assert!(s.on_key(KeyCode::Esc, Lang::En));
        assert!(!s.typing(), "Esc gives up");

        s.input = Some((Ask::PeerRm, String::new()));
        typed(&mut s, "Ab+/9=");
        assert_eq!(
            s.input.as_ref().unwrap().1,
            "Ab+/9=",
            "a public key is typeable"
        );
        s.input = Some((Ask::PeerAdd, String::new()));
        typed(&mut s, "my phone/");
        assert_eq!(s.input.as_ref().unwrap().1, "myphone");
    }

    #[test]
    fn this_machine_is_the_first_row_when_docker_answers() {
        let mut s = Servers::new();
        s.local_row = true;
        assert_eq!(s.rows(), 1);
        s.on_key(KeyCode::Down, Lang::En);
        assert_eq!(s.profile_idx, 0, "one row wraps onto itself");
        assert!(s.host().is_none(), "nothing is connected before Enter");
    }

    #[test]
    fn the_footer_offers_what_the_selection_can_do() {
        let mut s = Servers::new();
        let keys = |s: &Servers| s.hints(Lang::En).iter().map(|h| h.0).collect::<Vec<_>>();
        assert!(keys(&s).contains(&"↵"));
        s.input = Some((Ask::Query, String::new()));
        assert_eq!(keys(&s), ["↵", "Esc"]);
    }

    /// Against this machine's docker with a node and a resolver running, for
    /// example `AWG_TEST_HOLD=300 containers/dnstest.sh 3.1`:
    /// `cargo test -p awg-cli live_local -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn live_local_node_and_resolver() {
        let mut s = Servers::new();
        s.open(Lang::En);
        assert!(s.local_row, "docker does not answer here");
        s.on_key(KeyCode::Enter, Lang::En);
        assert!(!s.containers.is_empty(), "{:?}", s.message);
        let dump = |s: &Servers| {
            println!("--- {}", s.detail_title);
            for l in &s.detail {
                println!("{l}");
            }
            s.detail
                .iter()
                .map(|l| l.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        };

        s.on_key(KeyCode::Char('n'), Lang::En);
        assert!(dump(&s).contains("mode"), "dns status");
        s.on_key(KeyCode::Char('b'), Lang::En);
        typed(&mut s, "tui-test.example");
        s.on_key(KeyCode::Enter, Lang::En);
        assert!(dump(&s).contains("tui-test.example"), "blocked name listed");
        s.on_key(KeyCode::Char('B'), Lang::En);
        typed(&mut s, "tui-test.example");
        s.on_key(KeyCode::Enter, Lang::En);
        assert!(!dump(&s).contains("  tui-test.example"), "unblocked");
        s.on_key(KeyCode::Char('/'), Lang::En);
        typed(&mut s, "amiunder.vpn");
        s.on_key(KeyCode::Enter, Lang::En);
        assert!(dump(&s).contains("172.29.172.253"), "query answered");

        // The node with a tunnel, not a bystander running the same image.
        s.container_idx = s
            .containers
            .iter()
            .position(|c| c.name.ends_with("server"))
            .expect("a node named *server");
        s.on_key(KeyCode::Char('+'), Lang::En);
        typed(&mut s, "tuitest");
        s.on_key(KeyCode::Enter, Lang::En);
        let issued = dump(&s);
        assert!(
            issued.contains("[Interface]") && issued.contains("vpn://"),
            "issued"
        );
        s.on_key(KeyCode::Char('p'), Lang::En);
        assert!(dump(&s).contains("tuitest"), "listed");
        s.on_key(KeyCode::Char('-'), Lang::En);
        typed(&mut s, "tuitest");
        s.on_key(KeyCode::Enter, Lang::En);
        let after = dump(&s);
        assert!(after.starts_with("✓ removed tuitest"), "revoked");
        assert!(
            !after.lines().skip(1).any(|l| l.starts_with("tuitest")),
            "still listed"
        );
        // The issued config holds a private key; this test leaves none behind.
        let issued = profile::default_config_dir()
            .unwrap()
            .join("issued")
            .join(format!(
                "{}-tuitest.conf",
                s.containers[s.container_idx].name
            ));
        std::fs::remove_file(issued).unwrap();
    }
}
