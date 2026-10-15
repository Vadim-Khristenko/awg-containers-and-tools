//! Terminal UI.
//!
//! Built so the same operations are reachable three ways — flags, this UI, and
//! (later) VAIEXIA calling `awg-core` as a library. The UI therefore holds no
//! logic of its own: it collects options and renders what the core returns.
//!
//! Navigation is a stack, not a variable. Every screen can be left the way it
//! was entered, and the path is drawn in the header, because a UI you can get
//! into but not out of is worse than no UI.
//!
//! The terminal is restored from a panic hook as well as on the normal path. A
//! TUI that dies mid-draw and leaves the terminal in raw mode with no cursor is
//! the kind of thing people remember about a tool.

use std::io::{Stdout, stdout};

use awg_core::awg3::Intensity;
use awg_core::check::{self, CheckOptions, CheckReport};
use awg_core::engines::Engine;
use awg_core::mimic::hostdb::Region;
use awg_core::mimic::{BrowserProfile, MimicProfile};
use awg_core::rng::SecureRng;
use awg_core::versions::{
    self, AwgVersion, ClientCapability, GenOptions, Level, VersionedParams, Violation,
};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use crate::i18n::{Key as K, Lang, t};
use crate::theme;

mod servers;

// ─────────────────────────────────────────────────────────────── screens

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Home,
    Generate,
    Servers,
    Deploy,
    About,
    Donate,
    Check,
}

impl Screen {
    fn title(self, lang: Lang) -> &'static str {
        match self {
            Screen::Home => t(lang, K::NavHome),
            Screen::Generate => t(lang, K::MenuGenerate),
            Screen::Servers => t(lang, K::MenuServers),
            Screen::Deploy => t(lang, K::MenuDeploy),
            Screen::About => t(lang, K::MenuAbout),
            Screen::Donate => t(lang, K::MenuDonate),
            Screen::Check => t(lang, K::MenuCheck),
        }
    }
}

/// One editable option on the generate screen. Every knob the generator has,
/// so nothing is reachable from the flags alone.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Version,
    Profile,
    Client,
    Release,
    ServerEngine,
    Region,
    Whitelisted,
    Browser,
    Intensity,
    Junk,
    Mtu,
    Attempt,
    MimicAll,
    HeaderProtection,
    ContentPadding,
    RandomTimings,
    RandomTrailers,
    DisableCookies,
    NarrowH,
    SameS,
    DisableH,
    TagT,
    TagR,
    TagRc,
    TagRd,
    Router,
    Extreme,
    Format,
}

impl Field {
    const ALL: [Field; 28] = [
        Field::Version,
        Field::Profile,
        Field::Client,
        Field::Release,
        Field::ServerEngine,
        Field::Region,
        Field::Whitelisted,
        Field::Browser,
        Field::Intensity,
        Field::Junk,
        Field::Mtu,
        Field::Attempt,
        Field::MimicAll,
        Field::HeaderProtection,
        Field::ContentPadding,
        Field::RandomTimings,
        Field::RandomTrailers,
        Field::DisableCookies,
        Field::NarrowH,
        Field::SameS,
        Field::DisableH,
        Field::TagT,
        Field::TagR,
        Field::TagRc,
        Field::TagRd,
        Field::Router,
        Field::Extreme,
        Field::Format,
    ];

    fn label(self, lang: Lang) -> &'static str {
        match self {
            Field::Version => t(lang, K::LblVersion),
            Field::Profile => t(lang, K::LblProfile),
            Field::Client => t(lang, K::LblClient),
            Field::Release => t(lang, K::LblRelease),
            Field::ServerEngine => t(lang, K::LblServerEngine),
            Field::Region => t(lang, K::LblRegion),
            Field::Whitelisted => t(lang, K::LblWhitelisted),
            Field::Browser => t(lang, K::LblBrowser),
            Field::Intensity => t(lang, K::LblIntensity),
            Field::Junk => t(lang, K::LblJunk),
            Field::Mtu => "MTU",
            Field::Attempt => t(lang, K::LblAttempt),
            Field::MimicAll => t(lang, K::LblMimicAll),
            Field::HeaderProtection => "HeaderProtection",
            Field::ContentPadding => "ContentPadding",
            Field::RandomTimings => t(lang, K::LblRandomTimings),
            Field::RandomTrailers => "RandomTrailers",
            Field::DisableCookies => "DisableCookies",
            Field::NarrowH => t(lang, K::LblNarrowH),
            Field::SameS => t(lang, K::LblSameS),
            Field::DisableH => t(lang, K::LblDisableH),
            Field::TagT => "<t>",
            Field::TagR => "<r>",
            Field::TagRc => "<rc>",
            Field::TagRd => "<rd>",
            Field::Router => t(lang, K::LblRouter),
            Field::Extreme => t(lang, K::LblExtreme),
            Field::Format => t(lang, K::LblFormat),
        }
    }
}

// ─────────────────────────────────────────────────────────────────── state

pub struct App {
    lang: Lang,
    /// Never empty: `Screen::Home` is the floor.
    stack: Vec<Screen>,
    menu_idx: usize,
    field_idx: usize,
    opts: GenOptions,
    client_idx: usize,
    /// 0 is the current build; n is the nth older release of that client.
    release_idx: usize,
    params: Option<VersionedParams>,
    violations: Vec<Violation>,
    show_uapi: bool,
    /// Vertical offset of whichever pane on the current screen can overflow.
    /// Reset on every navigation, because arriving somewhere already scrolled
    /// looks like missing content.
    scroll: u16,
    servers: servers::Servers,
    status: Option<(String, Status)>,
    quit: bool,
    /// The check screen: what was typed, and what the last run found.
    check_input: String,
    check_report: Option<CheckReport>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Ok,
    Bad,
}

impl App {
    pub fn new(lang: Lang) -> Self {
        let opts = GenOptions::default();
        let client_idx = versions::CLIENTS
            .iter()
            .position(|c| c.id == opts.client.id)
            .unwrap_or(0);
        Self {
            lang,
            stack: vec![Screen::Home],
            menu_idx: 0,
            field_idx: 0,
            opts,
            client_idx,
            release_idx: 0,
            params: None,
            violations: Vec::new(),
            show_uapi: false,
            scroll: 0,
            servers: servers::Servers::new(),
            status: None,
            quit: false,
            check_input: String::new(),
            check_report: None,
        }
    }

    fn screen(&self) -> Screen {
        *self.stack.last().unwrap_or(&Screen::Home)
    }

    fn push(&mut self, s: Screen) {
        self.stack.push(s);
        self.scroll = 0;
    }

    /// Move the scrollable pane. The upper bound is a coarse guard only —
    /// wrapping means the real limit depends on the pane width, so the exact
    /// clamp happens at draw time against the wrapped height.
    fn scroll_by(&mut self, delta: i32) {
        let limit = match self.screen() {
            Screen::Generate => self
                .params
                .as_ref()
                .map(|p| p.conf_lines().len())
                .unwrap_or(0),
            Screen::Servers => self.servers.detail_lines().len(),
            Screen::Check => self
                .check_report
                .as_ref()
                .map_or(0, |r| r.findings.len() * 3),
            _ => 200,
        } as i32;
        self.scroll = (self.scroll as i32 + delta).clamp(0, limit.max(0)) as u16;
    }

    /// Pop one level. At the root there is nothing above to go to, so say so
    /// rather than quitting on a keypress that everywhere else means "back".
    fn back(&mut self) {
        if self.stack.len() > 1 {
            self.stack.pop();
            self.scroll = 0;
            self.status = None;
        } else {
            self.status = Some((t(self.lang, K::HintQuitFromHere).into(), Status::Ok));
        }
    }

    fn menu_items(&self) -> [(&'static str, &'static str, Screen); 6] {
        [
            (
                t(self.lang, K::MenuGenerate),
                t(self.lang, K::MenuGenerateSub),
                Screen::Generate,
            ),
            (
                t(self.lang, K::MenuCheck),
                t(self.lang, K::MenuCheckSub),
                Screen::Check,
            ),
            (
                t(self.lang, K::MenuServers),
                t(self.lang, K::MenuServersSub),
                Screen::Servers,
            ),
            (
                t(self.lang, K::MenuDeploy),
                t(self.lang, K::MenuDeploySub),
                Screen::Deploy,
            ),
            (
                t(self.lang, K::MenuAbout),
                t(self.lang, K::MenuAboutSub),
                Screen::About,
            ),
            (
                t(self.lang, K::MenuDonate),
                t(self.lang, K::MenuDonateSub),
                Screen::Donate,
            ),
        ]
    }

    fn regenerate(&mut self) {
        self.opts.client = self.client();
        match versions::generate(&mut SecureRng, &self.opts) {
            Ok(p) => {
                self.violations =
                    versions::validate_for(&p, self.opts.client, self.opts.server_engine);
                self.params = Some(p);
                let errs = self
                    .violations
                    .iter()
                    .filter(|v| v.level == Level::Error)
                    .count();
                self.status = Some(if errs == 0 {
                    (t(self.lang, K::StatusGenerated).into(), Status::Ok)
                } else {
                    (
                        format!("{} — {errs}× {}", t(self.lang, K::StatusGenerated), "error"),
                        Status::Bad,
                    )
                });
            }
            // The core refuses parameter sets that would violate a protocol
            // invariant; surfacing that verbatim beats showing a broken config.
            Err(e) => {
                self.params = None;
                self.violations.clear();
                self.status = Some((format!("{e}"), Status::Bad));
            }
        }
    }

    /// Move the field under the cursor one step. `delta` is +1 or -1 so the
    /// same code serves both arrows.
    fn adjust(&mut self, delta: i32) {
        let field = Field::ALL[self.field_idx];
        let o = &mut self.opts;
        match field {
            Field::Version => {
                o.version = cycle(&AwgVersion::ALL, o.version, delta);
                // Picking a version is picking a feature set, as in Architect:
                // the switches move to where that version recommends.
                o.apply_preset();
                o.narrow_h = o.version == AwgVersion::V3_1;
            }
            Field::Profile => o.profile = cycle(&MimicProfile::ALL, o.profile, delta),
            Field::Client => {
                self.client_idx = wrap(self.client_idx, versions::CLIENTS.len(), delta);
                self.release_idx = 0;
            }
            Field::Release => {
                let n = versions::releases_of(self.client_base().id).count() + 1;
                self.release_idx = wrap(self.release_idx, n, delta);
            }
            Field::ServerEngine => o.server_engine = cycle(&Engine::ALL, o.server_engine, delta),
            Field::Region => o.mimic.region = cycle_opt(&Region::ALL, o.mimic.region, delta),
            Field::Whitelisted => {
                o.mimic.whitelisted_in = cycle_opt(&Region::ALL, o.mimic.whitelisted_in, delta)
            }
            Field::Browser => {
                o.mimic.browser = cycle_opt(&BrowserProfile::ALL, o.mimic.browser, delta)
            }
            Field::Intensity => {
                const I: [Intensity; 3] = [Intensity::Low, Intensity::Medium, Intensity::High];
                o.intensity = cycle(&I, o.intensity, delta);
            }
            Field::Junk => o.junk_level = (o.junk_level as i32 + delta).clamp(0, 32) as u8,
            Field::Mtu => {
                const MTUS: [u32; 7] = [1280, 1320, 1380, 1400, 1420, 1460, 1500];
                o.mimic.mtu = cycle(&MTUS, o.mimic.mtu, delta);
            }
            Field::Attempt => {
                o.mimic.iter_count = (o.mimic.iter_count as i32 + delta).clamp(0, 10) as u32
            }
            Field::MimicAll => o.mimic.mimic_all = !o.mimic.mimic_all,
            Field::HeaderProtection => o.header_protection = !o.header_protection,
            Field::ContentPadding => o.content_padding = !o.content_padding,
            Field::RandomTimings => o.random_timings = !o.random_timings,
            Field::RandomTrailers => o.random_trailers = !o.random_trailers,
            Field::DisableCookies => o.disable_cookies = !o.disable_cookies,
            Field::NarrowH => o.narrow_h = !o.narrow_h,
            Field::SameS => o.same_s = !o.same_s,
            Field::DisableH => o.disable_h = !o.disable_h,
            Field::TagT => o.mimic.tag_t = !o.mimic.tag_t,
            Field::TagR => o.mimic.tag_r = !o.mimic.tag_r,
            Field::TagRc => o.mimic.tag_rc = !o.mimic.tag_rc,
            Field::TagRd => o.mimic.tag_rd = !o.mimic.tag_rd,
            Field::Router => {
                o.router_mode = !o.router_mode;
                o.mimic.router_mode = o.router_mode;
            }
            Field::Extreme => o.extreme = !o.extreme,
            // Format changes how the same parameters are printed, so it must
            // not draw new ones: regenerating here would look like the output
            // format altered the config.
            Field::Format => {
                self.show_uapi = !self.show_uapi;
                return;
            }
        }
        self.regenerate();
    }

    /// Read what was typed (a path, or a vpn:// link) and check it against the
    /// client and server engine chosen on the generate screen.
    fn run_check(&mut self) {
        let target = self.check_input.trim();
        let text = if target.starts_with("vpn://") {
            Ok(target.to_string())
        } else {
            std::fs::read_to_string(target)
        };
        match text {
            Ok(text) => {
                let report = check::check(
                    &text,
                    &CheckOptions {
                        client: self.client(),
                        server_engine: self.opts.server_engine,
                        version: None,
                    },
                );
                let status = match report.worst() {
                    Some(Level::Error) => Status::Bad,
                    _ => Status::Ok,
                };
                self.status = Some((
                    format!(
                        "{} {}",
                        report.findings.len(),
                        t(self.lang, K::StatusFindings)
                    ),
                    status,
                ));
                self.check_report = Some(report);
                self.scroll = 0;
            }
            Err(e) => {
                self.check_report = None;
                self.status = Some((format!("{target}: {e}"), Status::Bad));
            }
        }
    }

    fn on_key(&mut self, code: KeyCode) {
        // The check screen takes text, so letters and Backspace are input
        // there rather than quit and back. Esc still leaves.
        if self.screen() == Screen::Check {
            match code {
                KeyCode::Esc => self.back(),
                KeyCode::Enter => self.run_check(),
                KeyCode::Backspace => {
                    self.check_input.pop();
                }
                KeyCode::Char(c) => self.check_input.push(c),
                KeyCode::Down => self.scroll_by(1),
                KeyCode::Up => self.scroll_by(-1),
                _ => {}
            }
            return;
        }
        // Back and quit mean the same thing on every other screen.
        match code {
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                self.quit = true;
                return;
            }
            KeyCode::Esc | KeyCode::Backspace => {
                self.back();
                return;
            }
            // Left means "back" everywhere except the generate screen, where it
            // is how you change the value under the cursor.
            KeyCode::Left if self.screen() != Screen::Generate => {
                self.back();
                return;
            }
            _ => {}
        }

        match self.screen() {
            Screen::Home => match code {
                KeyCode::Down | KeyCode::Char('j') => {
                    self.menu_idx = (self.menu_idx + 1) % self.menu_items().len();
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    let n = self.menu_items().len();
                    self.menu_idx = (self.menu_idx + n - 1) % n;
                }
                KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                    let target = self.menu_items()[self.menu_idx].2;
                    self.push(target);
                    match target {
                        Screen::Generate if self.params.is_none() => self.regenerate(),
                        Screen::Servers => self.servers.open(self.lang),
                        _ => {}
                    }
                }
                _ => {}
            },
            Screen::Generate => match code {
                KeyCode::Down | KeyCode::Char('j') => {
                    self.field_idx = (self.field_idx + 1) % Field::ALL.len();
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.field_idx = (self.field_idx + Field::ALL.len() - 1) % Field::ALL.len();
                }
                KeyCode::Right | KeyCode::Char('l') | KeyCode::Enter => self.adjust(1),
                KeyCode::Left | KeyCode::Char('h') => self.adjust(-1),
                KeyCode::Char('g') | KeyCode::Char('G') => self.regenerate(),
                // ↑↓ belong to the option list here, so the output pane gets
                // the page keys instead.
                KeyCode::PageDown => self.scroll_by(8),
                KeyCode::PageUp => self.scroll_by(-8),
                _ => {}
            },
            // The servers screen owns its own selection, so it gets first
            // refusal on every key and only what it declines falls through.
            Screen::Servers => {
                if !self.servers.on_key(code, self.lang) {
                    match code {
                        KeyCode::PageDown => self.scroll_by(8),
                        KeyCode::PageUp => self.scroll_by(-8),
                        _ => {}
                    }
                }
            }
            // The prose screens have nothing to select, so the arrows scroll.
            _ => match code {
                KeyCode::Down | KeyCode::Char('j') => self.scroll_by(1),
                KeyCode::Up | KeyCode::Char('k') => self.scroll_by(-1),
                KeyCode::PageDown => self.scroll_by(8),
                KeyCode::PageUp => self.scroll_by(-8),
                KeyCode::Home => self.scroll = 0,
                _ => {}
            },
        }
    }

    fn field_value(&self, f: Field) -> String {
        let o = &self.opts;
        let any = || t(self.lang, K::ValAny).to_string();
        let off = || on_off(self.lang, false);
        let current = || t(self.lang, K::ValCurrent).to_string();
        match f {
            Field::Version => o.version.as_str().to_string(),
            Field::Profile => o.profile.label().to_string(),
            Field::Client => self.client_base().name.to_string(),
            Field::Release => match self.release_idx {
                0 => current(),
                i => versions::releases_of(self.client_base().id)
                    .nth(i - 1)
                    .map_or_else(current, |r| r.label.to_string()),
            },
            Field::ServerEngine => o.server_engine.id().to_string(),
            Field::Region => o.mimic.region.map_or_else(any, |r| r.id().to_string()),
            Field::Whitelisted => o
                .mimic
                .whitelisted_in
                .map_or_else(off, |r| r.id().to_string()),
            Field::Browser => o.mimic.browser.map_or_else(off, |b| b.id().to_string()),
            Field::Intensity => match o.intensity {
                Intensity::Low => t(self.lang, K::ValLow).into(),
                Intensity::Medium => t(self.lang, K::ValMedium).into(),
                Intensity::High => t(self.lang, K::ValHigh).into(),
            },
            Field::Junk => o.junk_level.to_string(),
            Field::Mtu => o.mimic.mtu.to_string(),
            Field::Attempt => o.mimic.iter_count.to_string(),
            Field::MimicAll => on_off(self.lang, o.mimic.mimic_all),
            Field::HeaderProtection => on_off(self.lang, o.header_protection),
            Field::ContentPadding => on_off(self.lang, o.content_padding),
            Field::RandomTimings => on_off(self.lang, o.random_timings),
            Field::RandomTrailers => on_off(self.lang, o.random_trailers),
            Field::DisableCookies => on_off(self.lang, o.disable_cookies),
            Field::NarrowH => on_off(self.lang, o.narrow_h),
            Field::SameS => on_off(self.lang, o.same_s),
            Field::DisableH => on_off(self.lang, o.disable_h),
            Field::TagT => on_off(self.lang, o.mimic.tag_t),
            Field::TagR => on_off(self.lang, o.mimic.tag_r),
            Field::TagRc => on_off(self.lang, o.mimic.tag_rc),
            Field::TagRd => on_off(self.lang, o.mimic.tag_rd),
            Field::Router => on_off(self.lang, o.router_mode),
            Field::Extreme => on_off(self.lang, o.extreme),
            Field::Format => if self.show_uapi { "UAPI" } else { ".conf" }.to_string(),
        }
    }

    /// The client as listed, before any older release is applied.
    fn client_base(&self) -> &'static ClientCapability {
        versions::CLIENTS
            .get(self.client_idx)
            .unwrap_or_else(|| versions::default_client())
    }

    /// The client with the chosen release applied: what generation targets.
    fn client(&self) -> &'static ClientCapability {
        let base = self.client_base();
        match self.release_idx {
            0 => base,
            i => versions::releases_of(base.id)
                .nth(i - 1)
                .map_or(base, |r| &r.caps),
        }
    }
}

/// Step through `None` (shown as off or any) and every value.
fn cycle_opt<T: PartialEq + Copy>(all: &[T], current: Option<T>, delta: i32) -> Option<T> {
    let i = current
        .and_then(|c| all.iter().position(|v| *v == c))
        .map_or(0, |i| i + 1);
    match wrap(i, all.len() + 1, delta) {
        0 => None,
        n => Some(all[n - 1]),
    }
}

fn on_off(lang: Lang, v: bool) -> String {
    t(lang, if v { K::ValOn } else { K::ValOff }).to_string()
}

fn wrap(idx: usize, len: usize, delta: i32) -> usize {
    if len == 0 {
        return 0;
    }
    let n = len as i32;
    (((idx as i32 + delta) % n + n) % n) as usize
}

fn cycle<T: PartialEq + Copy>(all: &[T], current: T, delta: i32) -> T {
    let i = all.iter().position(|v| *v == current).unwrap_or(0);
    all[wrap(i, all.len(), delta)]
}

// ──────────────────────────────────────────────────────────────── drawing

/// Rows a block of lines occupies once wrapped into `width` columns.
fn wrapped_height(lines: &[Line], width: u16) -> usize {
    let w = width.max(1) as usize;
    lines
        .iter()
        .map(|l| {
            let n: usize = l.spans.iter().map(|s| s.content.chars().count()).sum();
            n.max(1).div_ceil(w)
        })
        .sum()
}

/// The real scroll limit, which only the renderer knows: it depends on how the
/// text wrapped into this particular pane. Without it the last page scrolls off
/// into blank space and the content looks lost.
fn clamp_scroll(scroll: u16, lines: &[Line], area: Rect) -> u16 {
    let inner_h = area.height.saturating_sub(2) as usize;
    let total = wrapped_height(lines, area.width.saturating_sub(2));
    scroll.min(total.saturating_sub(inner_h) as u16)
}

/// `12%` style marker, or nothing at all when everything already fits.
fn scroll_marker(scroll: u16, lines: &[Line], area: Rect) -> String {
    let inner_h = area.height.saturating_sub(2) as usize;
    let total = wrapped_height(lines, area.width.saturating_sub(2));
    if total <= inner_h {
        return String::new();
    }
    let max = total - inner_h;
    let pct = (scroll as usize * 100).div_ceil(max.max(1)).min(100);
    format!("  ↕ {pct}%")
}

/// `Esc back` rendered as a key cap plus a label, the way a status bar reads
/// in tools people already know.
fn key_hint<'a>(key: &'a str, label: &'a str) -> Vec<Span<'a>> {
    vec![
        Span::styled(format!(" {key} "), theme::key_cap()),
        Span::styled(format!(" {label}   "), theme::dim()),
    ]
}

fn header(app: &App, f: &mut ratatui::Frame, area: Rect) {
    // Give the breadcrumb exactly what it needs and the rest to the wordmark.
    // A fixed half-and-half split truncated the strapline on normal terminals.
    let crumb_w: usize = app
        .stack
        .iter()
        .map(|s| s.title(app.lang).chars().count())
        .sum::<usize>()
        + 3 * app.stack.len().saturating_sub(1)
        + 1;
    let crumb_w = (crumb_w as u16).min(area.width.saturating_sub(24));
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(20), Constraint::Length(crumb_w)])
        .split(area);

    let brand = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("▌", Style::default().fg(theme::AMBER).bg(theme::BG)),
            Span::styled(" awg-tool ", theme::title()),
            Span::styled(env!("CARGO_PKG_VERSION"), theme::faint()),
        ]),
        Line::from(Span::styled(t(app.lang, K::JointRelease), theme::faint())),
    ])
    .style(theme::base());
    f.render_widget(brand, cols[0]);

    // Breadcrumb: the whole stack, so "where am I and what is above me" is
    // answered without pressing anything.
    let mut crumbs: Vec<Span> = Vec::new();
    for (i, s) in app.stack.iter().enumerate() {
        if i > 0 {
            crumbs.push(Span::styled(" › ", theme::faint()));
        }
        let last = i + 1 == app.stack.len();
        crumbs.push(Span::styled(
            s.title(app.lang),
            if last { theme::title() } else { theme::dim() },
        ));
    }
    f.render_widget(
        Paragraph::new(Line::from(crumbs))
            .alignment(Alignment::Right)
            .style(theme::base()),
        cols[1],
    );
}

/// The title is copied into an owned span, so the block outlives the string it
/// was named from and callers can pass a `format!` result inline.
fn panel(title: &str, active: bool) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(if active {
            theme::border_active()
        } else {
            theme::border()
        })
        .title(Span::styled(
            format!(" {title} "),
            if active { theme::title() } else { theme::dim() },
        ))
        .style(theme::base())
}

fn draw_home(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .menu_items()
        .iter()
        .enumerate()
        .flat_map(|(i, (label, sub, _))| {
            let on = i == app.menu_idx;
            vec![
                ListItem::new(Line::from(vec![
                    Span::styled(if on { " ▸ " } else { "   " }, theme::warn()),
                    Span::styled(
                        format!("{label} "),
                        if on { theme::selected() } else { theme::base() },
                    ),
                ])),
                ListItem::new(Line::from(Span::styled(
                    format!("     {sub}"),
                    if on { theme::dim() } else { theme::faint() },
                ))),
                ListItem::new(Line::from(Span::styled("", theme::base()))),
            ]
        })
        .collect();
    f.render_widget(
        List::new(items).block(panel(t(app.lang, K::NavHome), true)),
        area,
    );
}

/// Colour the generated config the way an editor would: keys apart from values,
/// comments quieter than both. It is the difference between a wall of text and
/// something you can scan for the one field you care about.
fn config_lines(raw: &[String]) -> Vec<Line<'static>> {
    raw.iter()
        .map(|l| {
            if l.trim_start().starts_with('#') {
                return Line::from(Span::styled(l.clone(), theme::faint()));
            }
            match l.split_once('=') {
                Some((k, v)) => Line::from(vec![
                    Span::styled(
                        k.to_string(),
                        Style::default().fg(theme::AMBER).bg(theme::BG),
                    ),
                    Span::styled("=", theme::faint()),
                    Span::styled(v.to_string(), theme::base()),
                ]),
                None => Line::from(Span::styled(l.clone(), theme::base())),
            }
        })
        .collect()
}

fn draw_generate(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(42), Constraint::Min(24)])
        .split(area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(7)])
        .split(cols[0]);

    // ── options ──
    let opts: Vec<ListItem> = Field::ALL
        .iter()
        .enumerate()
        .map(|(i, fld)| {
            let on = i == app.field_idx;
            let label = fld.label(app.lang);
            let value = app.field_value(*fld);
            ListItem::new(Line::from(vec![
                Span::styled(if on { "▸ " } else { "  " }, theme::warn()),
                Span::styled(
                    format!("{label:<17}"),
                    if on { theme::base() } else { theme::dim() },
                ),
                Span::styled(
                    format!(" {value} "),
                    if on {
                        theme::selected()
                    } else {
                        Style::default().fg(theme::AMBER2).bg(theme::BG)
                    },
                ),
            ]))
        })
        .collect();
    // Twenty-eight knobs do not fit every terminal; the list follows the
    // cursor instead of letting the selection fall off the bottom.
    let mut state = ListState::default().with_selected(Some(app.field_idx));
    f.render_stateful_widget(
        List::new(opts).block(panel(t(app.lang, K::PanelOptions), true)),
        rows[0],
        &mut state,
    );

    // ── what this client will and will not take ──
    let c = app.client();
    let caps = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("max H  ", theme::dim()),
            Span::styled(c.max_h_value.to_string(), theme::base()),
        ]),
        Line::from(vec![
            Span::styled("max Jc ", theme::dim()),
            Span::styled(c.max_jc.to_string(), theme::base()),
            Span::styled("   max S4 ", theme::dim()),
            Span::styled(c.max_s4.to_string(), theme::base()),
        ]),
        Line::from(vec![
            Span::styled("engine ", theme::dim()),
            Span::styled(c.engine.label(), theme::base()),
        ]),
        Line::from(vec![
            Span::styled("tags   ", theme::dim()),
            Span::styled(
                {
                    let tags: Vec<&str> = c
                        .tags(app.opts.version)
                        .iter()
                        .map(|k| k.as_str())
                        .collect();
                    if tags.is_empty() {
                        "none".to_string()
                    } else {
                        tags.join(" ")
                    }
                },
                theme::base(),
            ),
        ]),
        Line::from(Span::styled(
            c.known_issues.first().copied().unwrap_or(""),
            theme::warn(),
        )),
    ])
    .wrap(Wrap { trim: true })
    .block(panel(t(app.lang, K::PanelClient), false));
    f.render_widget(caps, rows[1]);

    // ── output, with any complaints underneath ──
    let has_violations = !app.violations.is_empty();
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints(if has_violations {
            [Constraint::Min(6), Constraint::Length(6)]
        } else {
            [Constraint::Min(6), Constraint::Length(0)]
        })
        .split(cols[1]);

    let body: Vec<Line> = match &app.params {
        Some(p) => config_lines(&if app.show_uapi {
            p.uapi_lines()
        } else {
            p.conf_lines()
        }),
        None => vec![Line::from(Span::styled(
            t(app.lang, K::HintRegenerate),
            theme::dim(),
        ))],
    };
    let s = clamp_scroll(app.scroll, &body, right[0]);
    f.render_widget(
        Paragraph::new(body.clone())
            .wrap(Wrap { trim: false })
            .scroll((s, 0))
            .block(panel(
                &format!(
                    "{} {}{}",
                    app.opts.version.as_str(),
                    app.field_value(Field::Format),
                    scroll_marker(s, &body, right[0])
                ),
                false,
            )),
        right[0],
    );

    if has_violations {
        let lines: Vec<Line> = app
            .violations
            .iter()
            .map(|v| {
                let (mark, style) = match v.level {
                    Level::Error => ("✕", theme::error()),
                    Level::Warn => ("!", theme::warn()),
                    Level::Info => ("i", theme::dim()),
                };
                Line::from(vec![
                    Span::styled(format!(" {mark} "), style),
                    Span::styled(format!("{}: ", v.field), theme::dim()),
                    Span::styled(v.text(app.lang == Lang::Ru).to_string(), theme::base()),
                ])
            })
            .collect();
        f.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: true })
                .block(panel(t(app.lang, K::PanelWarnings), false)),
            right[1],
        );
    }
}

/// The check screen: a line to type a path or link into, and what it found.
fn draw_check(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(4)])
        .split(area);

    let input = Paragraph::new(Line::from(vec![
        Span::styled(app.check_input.clone(), theme::base()),
        Span::styled("█", theme::warn()),
    ]))
    .block(panel(t(app.lang, K::CheckPrompt), true));
    f.render_widget(input, rows[0]);

    let c = app.client();
    let mut lines = vec![Line::from(vec![
        Span::styled(format!("{}  ", t(app.lang, K::LblClient)), theme::dim()),
        Span::styled(
            format!("{} ({})", c.name, app.opts.server_engine.id()),
            theme::base(),
        ),
    ])];
    match &app.check_report {
        None => lines.push(Line::from(Span::styled(
            t(app.lang, K::CheckHint),
            theme::dim(),
        ))),
        Some(r) => {
            lines.push(Line::from(vec![
                Span::styled(format!("{}  ", t(app.lang, K::LblVersion)), theme::dim()),
                Span::styled(
                    r.version
                        .map_or_else(|| "-".to_string(), |v| format!("AWG {v}")),
                    theme::base(),
                ),
            ]));
            lines.push(Line::from(""));
            if r.findings.is_empty() {
                lines.push(Line::from(Span::styled(
                    t(app.lang, K::MsgCheckClean),
                    theme::base(),
                )));
            }
            for v in &r.findings {
                let (mark, style) = match v.level {
                    Level::Error => ("✕", theme::error()),
                    Level::Warn => ("!", theme::warn()),
                    Level::Info => ("i", theme::dim()),
                };
                lines.push(Line::from(vec![
                    Span::styled(format!("{mark} "), style),
                    Span::styled(format!("{}: ", v.field), style),
                    Span::styled(v.text(app.lang == Lang::Ru).to_string(), theme::base()),
                ]));
            }
        }
    }
    let height = rows[1].height.saturating_sub(2);
    let width = rows[1].width.saturating_sub(2);
    let max_scroll = wrapped_height(&lines, width).saturating_sub(height as usize) as u16;
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .scroll((app.scroll.min(max_scroll), 0))
            .block(panel(t(app.lang, K::PanelWarnings), false)),
        rows[1],
    );
}

fn draw_prose(
    f: &mut ratatui::Frame,
    app: &App,
    area: Rect,
    title: &str,
    body: Vec<Line<'static>>,
) {
    let s = clamp_scroll(app.scroll, &body, area);
    f.render_widget(
        Paragraph::new(body.clone())
            .wrap(Wrap { trim: false })
            .scroll((s, 0))
            .block(panel(
                &format!("{title}{}", scroll_marker(s, &body, area)),
                true,
            )),
        area,
    );
}

/// The support screen, laid out so an address can be selected on its own.
///
/// Each address sits alone on its line with nothing beside it: a label or a
/// trailing space picked up by a mouse selection turns into a paste that goes
/// nowhere, and with a crypto address there is nothing to undo.
fn donate_lines(lang: Lang) -> Vec<Line<'static>> {
    use awg_core::support::{ARCHITECT_URL, CRYPTO_WALLETS, FIAT_METHODS, SOURCES_URL};

    let mut out = vec![
        Line::from(Span::styled(
            t(lang, K::DonateIntro).to_string(),
            theme::base(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("{}:", t(lang, K::DonateFiat)),
            theme::title(),
        )),
    ];
    for m in &FIAT_METHODS {
        let note = if lang == Lang::Ru {
            m.note_ru
        } else {
            m.note_en
        };
        out.push(Line::from(vec![
            Span::styled(format!("  {:<10}", m.label), theme::base()),
            Span::styled(format!("{note:<24}"), theme::dim()),
            Span::styled(m.url.to_string(), theme::warn()),
        ]));
    }

    out.push(Line::from(""));
    out.push(Line::from(Span::styled(
        format!("{}:", t(lang, K::DonateCrypto)),
        theme::title(),
    )));
    for w in &CRYPTO_WALLETS {
        let net = if lang == Lang::Ru {
            w.network_ru
        } else {
            w.network_en
        };
        out.push(Line::from(vec![
            Span::styled(format!("  {:<6}", w.ticker), theme::warn()),
            Span::styled(net.to_string(), theme::dim()),
        ]));
        out.push(Line::from(Span::styled(
            format!("    {}", w.address),
            theme::base(),
        )));
    }
    out.push(Line::from(""));
    out.push(Line::from(Span::styled(
        format!("  {}", t(lang, K::DonateNetworkWarn)),
        theme::warn(),
    )));
    out.push(Line::from(""));
    out.push(Line::from(Span::styled(
        format!("  {} — {ARCHITECT_URL}", t(lang, K::DonateArchitect)),
        theme::dim(),
    )));
    out.push(Line::from(Span::styled(
        format!("  {} — {SOURCES_URL}", t(lang, K::DonateSources)),
        theme::dim(),
    )));
    out
}

fn prose(text: &str) -> Vec<Line<'static>> {
    text.lines()
        .map(|l| Line::from(Span::styled(l.to_string(), theme::base())))
        .collect()
}

fn footer(app: &App, f: &mut ratatui::Frame, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(area);

    if let Some((msg, kind)) = &app.status {
        let style = match kind {
            Status::Ok => theme::ok(),
            Status::Bad => theme::error(),
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(format!(" {msg}"), style))).style(theme::base()),
            rows[0],
        );
    } else {
        f.render_widget(Paragraph::new("").style(theme::base()), rows[0]);
    }

    let mut spans = vec![Span::styled(" ", theme::base())];
    match app.screen() {
        Screen::Home => {
            spans.extend(key_hint("↑↓", t(app.lang, K::HintMove)));
            spans.extend(key_hint("↵", t(app.lang, K::HintOpen)));
        }
        Screen::Generate => {
            spans.extend(key_hint("↑↓", t(app.lang, K::HintMove)));
            spans.extend(key_hint("←→", t(app.lang, K::HintChange)));
            spans.extend(key_hint("g", t(app.lang, K::HintRegenerate)));
            spans.extend(key_hint("PgUp/PgDn", t(app.lang, K::HintScroll)));
        }
        Screen::Servers => {
            spans.extend(key_hint("↑↓", t(app.lang, K::HintMove)));
            spans.extend(key_hint("Tab", t(app.lang, K::HintSwitchPane)));
            spans.extend(key_hint("↵", t(app.lang, K::HintConnect)));
            spans.extend(key_hint("d", t(app.lang, K::MenuDoctor)));
            spans.extend(key_hint("L", t(app.lang, K::MenuLogs)));
            spans.extend(key_hint("r", t(app.lang, K::HintRefresh)));
        }
        _ => {
            spans.extend(key_hint("↑↓", t(app.lang, K::HintScroll)));
        }
    }
    if app.stack.len() > 1 {
        spans.extend(key_hint("Esc", t(app.lang, K::HintBack)));
    }
    spans.extend(key_hint("q", t(app.lang, K::HintQuit)));
    f.render_widget(
        Paragraph::new(Line::from(spans)).style(theme::base()),
        rows[1],
    );
}

fn draw(f: &mut ratatui::Frame, app: &App) {
    // Paint the whole frame first: without it the terminal's own background
    // shows between panels and the palette looks half-applied.
    f.render_widget(Block::default().style(theme::base()), f.area());

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Min(6),
            Constraint::Length(2),
        ])
        .split(f.area());

    header(app, f, rows[0]);
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "─".repeat(rows[1].width as usize),
            theme::border(),
        )))
        .style(theme::base()),
        rows[1],
    );

    let body = rows[2];
    match app.screen() {
        Screen::Home => draw_home(f, app, body),
        Screen::Generate => draw_generate(f, app, body),
        Screen::Servers => app.servers.draw(f, body, app.lang, app.scroll),
        Screen::Check => draw_check(f, app, body),
        Screen::Deploy => draw_prose(
            f,
            app,
            body,
            Screen::Deploy.title(app.lang),
            prose(&format!(
                "{}\n\n{}",
                t(app.lang, K::DeployHow),
                t(app.lang, K::DeploySteps)
            )),
        ),
        Screen::About => draw_prose(
            f,
            app,
            body,
            Screen::About.title(app.lang),
            prose(&format!(
                "{}\n\n{}\n\n{}\n\n{}",
                t(app.lang, K::AboutOrigin),
                t(app.lang, K::AboutAwg3),
                t(app.lang, K::WhyUnique),
                t(app.lang, K::Unofficial)
            )),
        ),
        Screen::Donate => draw_prose(
            f,
            app,
            body,
            Screen::Donate.title(app.lang),
            donate_lines(app.lang),
        ),
    }

    footer(app, f, rows[3]);
}

// ──────────────────────────────────────────────────────────────── runtime

type Term = Terminal<CrosstermBackend<Stdout>>;

fn enter() -> std::io::Result<Term> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    Terminal::new(CrosstermBackend::new(out))
}

fn leave() {
    let _ = disable_raw_mode();
    let _ = execute!(stdout(), LeaveAlternateScreen);
}

pub fn run(lang: Lang) -> std::io::Result<()> {
    // Restore the terminal even if a draw panics, otherwise the user is left
    // with an invisible cursor and no echo.
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        leave();
        prev(info);
    }));

    let mut term = enter()?;
    let mut app = App::new(lang);
    let res = loop {
        if let Err(e) = term.draw(|f| draw(f, &app)) {
            break Err(e);
        }
        match event::read() {
            Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => app.on_key(k.code),
            Ok(_) => {}
            Err(e) => break Err(e),
        }
        if app.quit {
            break Ok(());
        }
    };
    leave();
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        App::new(Lang::En)
    }

    fn select(a: &mut App, f: Field) {
        a.field_idx = Field::ALL.iter().position(|x| *x == f).unwrap();
    }

    #[test]
    fn every_knob_turns_both_ways_and_leaves_a_valid_config() {
        let mut a = app();
        for (i, _) in Field::ALL.iter().enumerate() {
            a.field_idx = i;
            for delta in [1, 1, -1, -1, -1] {
                a.adjust(delta);
                if let Some(p) = &a.params {
                    assert!(
                        a.violations.iter().all(|v| v.level != Level::Error),
                        "field {i}: {:?}",
                        a.violations
                    );
                    assert_eq!(p.version, a.opts.version);
                }
            }
            assert!(!a.field_value(Field::ALL[i]).is_empty());
        }
    }

    #[test]
    fn the_last_knob_is_on_screen_in_an_ordinary_terminal() {
        use ratatui::backend::TestBackend;
        let mut a = app();
        a.push(Screen::Generate);
        a.regenerate();
        a.field_idx = Field::ALL.len() - 1;
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| draw(f, &a)).unwrap();
        let screen: String = term
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(
            screen.contains("format"),
            "the selected last field scrolled into view"
        );
    }

    #[test]
    fn the_check_screen_takes_typing_and_checks_a_file() {
        use ratatui::backend::TestBackend;
        let path = std::env::temp_dir().join(format!("awg-tui-check-{}.conf", std::process::id()));
        std::fs::write(&path, "Jc = 4\nJmin = 40\nJmax = 30\nS1 = 20\nS2 = 30\n").unwrap();

        let mut a = app();
        a.push(Screen::Check);
        for c in path.to_string_lossy().chars() {
            a.on_key(KeyCode::Char(c));
        }
        // Letters are input here: q types a q rather than quitting.
        a.on_key(KeyCode::Char('q'));
        assert!(!a.quit);
        a.on_key(KeyCode::Backspace);
        a.on_key(KeyCode::Enter);
        let r = a.check_report.as_ref().expect("a report");
        assert!(
            r.findings.iter().any(|f| f.code == "j.inverted"),
            "{:?}",
            r.findings
        );

        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| draw(f, &a)).unwrap();

        a.on_key(KeyCode::Esc);
        assert_eq!(a.screen(), Screen::Home);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn choosing_a_version_applies_its_preset() {
        let mut a = app();
        select(&mut a, Field::Version);
        while a.opts.version != AwgVersion::V3_1 {
            a.adjust(1);
        }
        assert!(a.opts.random_trailers && a.opts.disable_h);
        assert_eq!(a.opts.mimic.mtu, 1280);
        let p = a.params.as_ref().unwrap();
        assert_eq!(p.h_range(0).hi, 1, "plain headers on 3.1");
    }

    #[test]
    fn an_older_client_build_brings_its_own_limits() {
        let mut a = app();
        a.client_idx = versions::CLIENTS
            .iter()
            .position(|c| c.id == "amneziawg-windows")
            .unwrap();
        assert_eq!(a.client().max_h_value, u32::MAX);
        select(&mut a, Field::Release);
        a.adjust(1);
        assert_eq!(a.client().max_h_value, 2_147_483_647);
        assert_eq!(
            a.opts.client.max_h_value, 2_147_483_647,
            "generation targets it"
        );
        // Changing client goes back to that client's current build.
        select(&mut a, Field::Client);
        a.adjust(1);
        assert_eq!(a.release_idx, 0);
    }

    #[test]
    fn every_screen_can_be_left_again() {
        let mut a = app();
        for target in [
            Screen::Generate,
            Screen::Deploy,
            Screen::About,
            Screen::Donate,
        ] {
            a.push(target);
            assert_eq!(a.screen(), target);
            a.on_key(KeyCode::Esc);
            assert_eq!(a.screen(), Screen::Home, "could not leave a screen");
            assert!(!a.quit, "leaving a screen must not quit the app");
        }
    }

    #[test]
    fn back_at_the_root_explains_itself_instead_of_quitting() {
        let mut a = app();
        a.on_key(KeyCode::Esc);
        assert_eq!(a.screen(), Screen::Home);
        assert!(!a.quit);
        assert!(a.status.is_some(), "the root must say why nothing happened");
    }

    #[test]
    fn q_quits_from_anywhere() {
        for depth in 0..3 {
            let mut a = app();
            for _ in 0..depth {
                a.push(Screen::About);
            }
            a.on_key(KeyCode::Char('q'));
            assert!(a.quit);
        }
    }

    #[test]
    fn arrows_cycle_a_field_and_come_back_round() {
        let mut a = app();
        a.push(Screen::Generate);
        let start = a.opts.version;
        for _ in 0..AwgVersion::ALL.len() {
            a.on_key(KeyCode::Right);
        }
        assert_eq!(
            a.opts.version, start,
            "a full cycle must return to the start"
        );
    }

    #[test]
    fn every_version_generates_something_the_ui_can_show() {
        let mut a = app();
        a.push(Screen::Generate);
        for _ in 0..AwgVersion::ALL.len() {
            a.regenerate();
            assert!(
                a.params.is_some(),
                "version {} produced nothing to display",
                a.opts.version.as_str()
            );
            a.on_key(KeyCode::Right);
        }
    }

    #[test]
    fn switching_output_format_does_not_redraw_new_parameters() {
        // Changing how a config is printed must not change the config. If it
        // did, a user comparing .conf against UAPI would be comparing two
        // different servers.
        let mut a = app();
        a.push(Screen::Generate);
        a.regenerate();
        let before = a.params.as_ref().unwrap().conf_lines();
        a.field_idx = Field::ALL.iter().position(|f| *f == Field::Format).unwrap();
        a.on_key(KeyCode::Right);
        assert!(a.show_uapi);
        assert_eq!(before, a.params.as_ref().unwrap().conf_lines());
    }

    #[test]
    fn the_breadcrumb_never_empties() {
        let mut a = app();
        for _ in 0..5 {
            a.on_key(KeyCode::Esc);
        }
        assert_eq!(a.stack.len(), 1);
    }

    fn lines(n: usize, width: usize) -> Vec<Line<'static>> {
        (0..n)
            .map(|_| Line::from(Span::raw("x".repeat(width))))
            .collect()
    }

    #[test]
    fn scrolling_stops_at_the_last_page_rather_than_running_into_blank_space() {
        // 40 lines in a pane that shows 8: the furthest useful offset is 32,
        // and anything beyond it would scroll the text off the top for nothing.
        let area = Rect::new(0, 0, 40, 10);
        let body = lines(40, 10);
        assert_eq!(clamp_scroll(0, &body, area), 0);
        assert_eq!(clamp_scroll(5, &body, area), 5);
        assert_eq!(clamp_scroll(9_999, &body, area), 32);
    }

    #[test]
    fn content_that_fits_cannot_be_scrolled_at_all() {
        let area = Rect::new(0, 0, 40, 20);
        let body = lines(3, 10);
        assert_eq!(clamp_scroll(50, &body, area), 0);
        assert!(scroll_marker(0, &body, area).is_empty());
    }

    #[test]
    fn wrapped_lines_count_as_the_rows_they_actually_occupy() {
        // One 100-character line in a 25-column pane is four rows, not one.
        // Counting it as one is how the end of a config scrolls out of reach.
        let body = lines(1, 100);
        assert_eq!(wrapped_height(&body, 25), 4);
        assert_eq!(wrapped_height(&lines(0, 0), 25), 0);
        // An empty line still takes a row.
        assert_eq!(wrapped_height(&[Line::from("")], 25), 1);
    }

    #[test]
    fn arriving_at_a_screen_always_starts_at_the_top() {
        let mut a = app();
        a.push(Screen::About);
        a.scroll_by(20);
        assert!(a.scroll > 0);
        a.on_key(KeyCode::Esc);
        a.push(Screen::About);
        assert_eq!(a.scroll, 0, "a screen must not open part-way down");
    }

    #[test]
    fn wrapping_handles_both_directions_and_an_empty_list() {
        assert_eq!(wrap(0, 3, -1), 2);
        assert_eq!(wrap(2, 3, 1), 0);
        assert_eq!(wrap(0, 0, 1), 0);
    }
}
