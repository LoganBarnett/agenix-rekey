//! User-facing colored status output.
//!
//! Colors match the original bash implementation:
//!   bold green  ([1;32m) — something was generated or rekeyed
//!   bold gray   ([1;90m) — skipped (already up to date, de-emphasised)
//!
//! Colors are suppressed when stderr is not a terminal or when `NO_COLOR` is set.

use owo_colors::{OwoColorize, Style, Stream::Stderr};

/// One line per secret that was skipped (already up to date).  Bold dark gray.
pub fn skipped(msg: &str) {
  eprintln!("  {}  {msg}", "skipped".if_supports_color(Stderr, |t| t.style(Style::new().bold().bright_black())));
}

/// One line per secret that was rekeyed.  Bold green.
pub fn rekeyed(msg: &str) {
  eprintln!("  {}  {msg}", "rekeyed".if_supports_color(Stderr, |t| t.style(Style::new().bold().green())));
}

/// One line per secret that was generated.  Bold green.
pub fn generated(msg: &str) {
  eprintln!("  {}  {msg}", "generated".if_supports_color(Stderr, |t| t.style(Style::new().bold().green())));
}
