//! User-facing colored status output.
//!
//! Prints one line per secret showing its final disposition.  Colors are
//! suppressed when stderr is not a terminal or when `NO_COLOR` is set.

use owo_colors::{OwoColorize, Stream::Stderr};

/// One line per secret that was skipped (already up to date).  Green.
pub fn skipped(msg: &str) {
  eprintln!("  {}  {msg}", "skipped".if_supports_color(Stderr, |t| t.green()));
}

/// One line per secret that was rekeyed.  Cyan.
pub fn rekeyed(msg: &str) {
  eprintln!("  {}  {msg}", "rekeyed".if_supports_color(Stderr, |t| t.cyan()));
}

/// One line per secret that was generated.  Cyan.
pub fn generated(msg: &str) {
  eprintln!("{}  {msg}", "generated".if_supports_color(Stderr, |t| t.cyan()));
}
