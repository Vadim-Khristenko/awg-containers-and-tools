//! The Any Tech ARCHITECT palette, transcribed for a terminal.
//!
//! Values come from `assets/main.css` in the Architect repository — the "Rich
//! Dark Amber / Technical Precision" set — so the two halves of the release
//! look like one product rather than two tools that happen to ship together.
//!
//! The web palette leans on translucency (`rgba(232,168,64,0.14)` over a near
//! black page). A terminal cell has no alpha, so the composited results are
//! pre-computed here against the surface each one is actually drawn on.

use ratatui::style::{Color, Modifier, Style};

// ── Backgrounds ──────────────────────────────────────────────────────────
pub const BG: Color = Color::Rgb(0x0a, 0x08, 0x06);
pub const BG3: Color = Color::Rgb(0x18, 0x14, 0x10);

// ── Accent: amber ────────────────────────────────────────────────────────
pub const AMBER: Color = Color::Rgb(0xe8, 0xa8, 0x40);
pub const AMBER2: Color = Color::Rgb(0xf5, 0xc0, 0x60);
pub const AMBER3: Color = Color::Rgb(0xff, 0xd9, 0x80);
pub const AMBER_DIM: Color = Color::Rgb(0x7a, 0x58, 0x20);

// ── Semantic ─────────────────────────────────────────────────────────────
pub const GREEN: Color = Color::Rgb(0x5c, 0xb8, 0x7a);
pub const RED: Color = Color::Rgb(0xd4, 0x60, 0x4a);

// ── Text ─────────────────────────────────────────────────────────────────
pub const TEXT: Color = Color::Rgb(0xe0, 0xd4, 0xb8);
pub const TEXT2: Color = Color::Rgb(0x9a, 0x8a, 0x68);
pub const TEXT3: Color = Color::Rgb(0x5e, 0x50, 0x38);

/// `--border`, composited over `--bg3`: amber at 14% on #181410.
pub const BORDER: Color = Color::Rgb(0x35, 0x29, 0x17);

pub fn base() -> Style {
    Style::default().fg(TEXT).bg(BG)
}

/// An unfocused panel edge — present, but not competing for attention.
pub fn border() -> Style {
    Style::default().fg(BORDER).bg(BG)
}

/// The edge of the panel that currently takes keys.
pub fn border_active() -> Style {
    Style::default().fg(AMBER_DIM).bg(BG)
}

pub fn title() -> Style {
    Style::default()
        .fg(AMBER2)
        .bg(BG)
        .add_modifier(Modifier::BOLD)
}

pub fn dim() -> Style {
    Style::default().fg(TEXT2).bg(BG)
}

pub fn faint() -> Style {
    Style::default().fg(TEXT3).bg(BG)
}

/// The selected row: reversed rather than merely coloured, so it stays visible
/// on terminals that quietly drop the RGB and fall back to their own palette.
pub fn selected() -> Style {
    Style::default()
        .fg(BG)
        .bg(AMBER)
        .add_modifier(Modifier::BOLD)
}

pub fn key_cap() -> Style {
    Style::default()
        .fg(AMBER3)
        .bg(BG3)
        .add_modifier(Modifier::BOLD)
}

pub fn ok() -> Style {
    Style::default().fg(GREEN).bg(BG)
}

pub fn warn() -> Style {
    Style::default().fg(AMBER).bg(BG)
}

pub fn error() -> Style {
    Style::default().fg(RED).bg(BG)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_palette_is_the_architect_one() {
        // Pinned deliberately: these are shared with the web app, and a "tidy
        // up the colours" commit here would silently split the two products.
        assert_eq!(AMBER, Color::Rgb(0xe8, 0xa8, 0x40));
        assert_eq!(TEXT, Color::Rgb(0xe0, 0xd4, 0xb8));
        assert_eq!(BG, Color::Rgb(0x0a, 0x08, 0x06));
    }

    #[test]
    fn every_style_paints_its_own_background() {
        // A style that leaves bg unset shows the terminal's default through the
        // panel, which looks like a rendering bug on a light colour scheme.
        for s in [base(), dim(), faint(), ok(), warn(), error(), title()] {
            assert!(s.bg.is_some());
        }
    }
}
