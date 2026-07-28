//! The Servers screen: saved connections, what is running on the one you pick,
//! and why it is unhappy.
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

/// Not `Debug`, for the same reason `crate::remote::Target` is not: it can hold
/// a stored password for the length of a session.
pub struct Servers {
    profiles: Vec<Profile>,
    profile_idx: usize,
    pane: Pane,
    session: Option<Session>,
    /// Only ever the account password, never a key passphrase — it is what
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
        }
    }

    /// Read the saved profiles. Called when the screen is opened rather than at
    /// start-up, so a tool that is only ever used to generate configs never
    /// touches the config directory at all.
    pub fn open(&mut self, lang: Lang) {
        match profile::default_config_dir().and_then(|d| profile::load_all(&d)) {
            Ok(p) => {
                self.profiles = p;
                if self.profiles.is_empty() {
                    self.message = Some((t(lang, K::MsgNoSavedProfiles).into(), false));
                }
            }
            Err(e) => self.message = Some((e.to_string(), true)),
        }
    }

    fn host(&self) -> Option<Host<'_>> {
        self.session
            .as_ref()
            .map(|s| Host::new(s, self.sudo_password.as_deref()).with_docker_sudo(self.sudo))
    }

    fn connect(&mut self, lang: Lang) {
        let Some(p) = self.profiles.get(self.profile_idx).cloned() else {
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
                            "{} — awg-tool status --server {}",
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
        match docker::find_awg_containers(&host) {
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
        let title = format!("{} — {}", t(lang, K::MenuDoctor), c.name);
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
        let title = format!("{} — {}", t(lang, K::MenuLogs), c.name);
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

    /// Returns true when the key was consumed, so the caller can fall through
    /// to its own navigation when it was not.
    pub fn on_key(&mut self, code: KeyCode, lang: Lang) -> bool {
        let len = match self.pane {
            Pane::Profiles => self.profiles.len(),
            Pane::Containers => self.containers.len(),
        };
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

        let items: Vec<ListItem> = self
            .profiles
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let live = self.connected_to.as_deref() == Some(p.name.as_str());
                ListItem::new(Line::from(vec![
                    Span::styled(if live { "● " } else { "  " }, theme::ok()),
                    Span::styled(
                        format!("{:<16}", p.name),
                        if i == self.profile_idx && self.pane == Pane::Profiles {
                            theme::selected()
                        } else {
                            theme::base()
                        },
                    ),
                    Span::styled(format!(" {}@{}", p.user, p.host), theme::faint()),
                ]))
            })
            .collect();
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
        let s = super::clamp_scroll(scroll, &body, cols[1]);
        f.render_widget(
            Paragraph::new(body.clone())
                .wrap(Wrap { trim: false })
                .scroll((s, 0))
                .block(super::panel(
                    &format!("{title}{}", super::scroll_marker(s, &body, cols[1])),
                    false,
                )),
            cols[1],
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
