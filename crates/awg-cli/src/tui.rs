//! Terminal UI.
//!
//! Built so the same operations are reachable three ways — flags, this UI, and
//! (later) VAIEXIA calling `awg-core` as a library. The UI therefore holds no
//! logic of its own: it collects options and renders what the core returns.
//!
//! The terminal is restored from a panic hook as well as on the normal path. A
//! TUI that dies mid-draw and leaves the terminal in raw mode with no cursor is
//! the kind of thing people remember about a tool.

use std::io::{Stdout, stdout};

use awg_core::awg3::{Awg3Options, Awg3Params, Intensity, generate};
use awg_core::render::{awg3_conf_lines, awg3_uapi_lines};
use awg_core::rng::SecureRng;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

use crate::i18n::{Key as K, Lang, t};

const ACCENT: Color = Color::Rgb(0x39, 0xC5, 0xBB);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Menu,
    Generate,
    Deploy,
    About,
    Donate,
}

pub struct App {
    lang: Lang,
    screen: Screen,
    menu_idx: usize,
    opts: Awg3Options,
    params: Option<Awg3Params>,
    show_uapi: bool,
    status: String,
    quit: bool,
}

impl App {
    pub fn new(lang: Lang) -> Self {
        Self {
            lang,
            screen: Screen::Menu,
            menu_idx: 0,
            opts: Awg3Options::default(),
            params: None,
            show_uapi: false,
            status: String::new(),
            quit: false,
        }
    }

    fn menu_items(&self) -> [(&'static str, Screen); 4] {
        [
            (t(self.lang, K::MenuGenerate), Screen::Generate),
            (t(self.lang, K::MenuDeploy), Screen::Deploy),
            (t(self.lang, K::MenuAbout), Screen::About),
            (t(self.lang, K::MenuDonate), Screen::Donate),
        ]
    }

    fn regenerate(&mut self) {
        match generate(&mut SecureRng, self.opts) {
            Ok(p) => {
                self.params = Some(p);
                self.status = t(self.lang, K::StatusGenerated).into();
            }
            // The core refuses parameter sets that would violate a protocol
            // invariant; surfacing that verbatim beats showing a broken config.
            Err(e) => self.status = format!("{e}"),
        }
    }

    fn on_key(&mut self, code: KeyCode) {
        match self.screen {
            Screen::Menu => match code {
                KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
                KeyCode::Down | KeyCode::Char('j') => {
                    self.menu_idx = (self.menu_idx + 1) % self.menu_items().len()
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    let n = self.menu_items().len();
                    self.menu_idx = (self.menu_idx + n - 1) % n
                }
                KeyCode::Enter => {
                    self.screen = self.menu_items()[self.menu_idx].1;
                    if self.screen == Screen::Generate && self.params.is_none() {
                        self.regenerate();
                    }
                }
                _ => {}
            },
            Screen::Generate => match code {
                KeyCode::Esc | KeyCode::Char('q') => self.screen = Screen::Menu,
                KeyCode::Char('g') => self.regenerate(),
                KeyCode::Char('u') => self.show_uapi = !self.show_uapi,
                KeyCode::Char('r') => {
                    self.opts.router_mode = !self.opts.router_mode;
                    self.regenerate();
                }
                KeyCode::Char('i') => {
                    self.opts.intensity = match self.opts.intensity {
                        Intensity::Low => Intensity::Medium,
                        Intensity::Medium => Intensity::High,
                        Intensity::High => Intensity::Low,
                    };
                    self.regenerate();
                }
                _ => {}
            },
            _ => {
                if matches!(code, KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter) {
                    self.screen = Screen::Menu;
                }
            }
        }
    }
}

fn header(app: &App) -> Paragraph<'static> {
    Paragraph::new(vec![
        Line::from(Span::styled(
            "awg-tool",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        )),
        Line::from(t(app.lang, K::JointRelease)),
    ])
    .block(Block::default().borders(Borders::BOTTOM))
}

fn draw_menu(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .menu_items()
        .iter()
        .enumerate()
        .map(|(i, (label, _))| {
            let style = if i == app.menu_idx {
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(Span::styled(
                format!("{} {label}", if i == app.menu_idx { "▸" } else { " " }),
                style,
            )))
        })
        .collect();
    f.render_widget(
        List::new(items).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn draw_generate(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(34), Constraint::Min(20)])
        .split(area);

    let intensity = match app.opts.intensity {
        Intensity::Low => "low",
        Intensity::Medium => "medium",
        Intensity::High => "high",
    };
    let opts = Paragraph::new(vec![
        Line::from(format!("[i] {}: {intensity}", t(app.lang, K::LblIntensity))),
        Line::from(format!(
            "[r] {}: {}",
            t(app.lang, K::LblRouter),
            if app.opts.router_mode { "on" } else { "off" }
        )),
        Line::from(format!(
            "[u] {}: {}",
            t(app.lang, K::LblFormat),
            if app.show_uapi { "UAPI" } else { ".conf" }
        )),
        Line::from(""),
        Line::from(format!("[g] {}", t(app.lang, K::HintRegenerate))),
        Line::from(format!("[q] {}", t(app.lang, K::HintBack))),
    ])
    .block(Block::default().borders(Borders::ALL).title(" AWG 3.0 "));
    f.render_widget(opts, cols[0]);

    let body = match &app.params {
        Some(p) => {
            let lines = if app.show_uapi {
                awg3_uapi_lines(p)
            } else {
                awg3_conf_lines(p)
            };
            lines.join("\n")
        }
        None => t(app.lang, K::HintRegenerate).to_string(),
    };
    f.render_widget(
        Paragraph::new(body)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL)),
        cols[1],
    );
}

fn draw_text_screen(f: &mut ratatui::Frame, area: Rect, body: String) {
    f.render_widget(
        Paragraph::new(body)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn draw(f: &mut ratatui::Frame, app: &App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(f.area());

    f.render_widget(header(app), rows[0]);
    match app.screen {
        Screen::Menu => draw_menu(f, app, rows[1]),
        Screen::Generate => draw_generate(f, app, rows[1]),
        Screen::Deploy => draw_text_screen(
            f,
            rows[1],
            format!(
                "{}\n\n{}",
                t(app.lang, K::DeployPlanned),
                t(app.lang, K::NotYetImplemented)
            ),
        ),
        Screen::About => draw_text_screen(
            f,
            rows[1],
            format!(
                "{}\n\n{}\n\n{}",
                t(app.lang, K::AboutAwg3),
                t(app.lang, K::WhyUnique),
                t(app.lang, K::Unofficial)
            ),
        ),
        Screen::Donate => draw_text_screen(
            f,
            rows[1],
            format!(
                "{}\n\n  {} — https://architect.vai-rice.space\n  {} — https://github.com/Vadim-Khristenko/awg-containers-and-tools",
                t(app.lang, K::DonateIntro),
                t(app.lang, K::DonateArchitect),
                t(app.lang, K::DonateSources)
            ),
        ),
    }
    f.render_widget(
        Paragraph::new(app.status.clone()).style(Style::default().fg(ACCENT)),
        rows[2],
    );
}

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
