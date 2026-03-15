//! User-facing colored status output.
//!
//! Prints one line per secret showing its final disposition.  Colors are
//! suppressed when stderr is not a terminal or when `NO_COLOR` is set.

use std::io::IsTerminal as _;

const GREEN: &str = "\x1b[32m";
const CYAN: &str = "\x1b[36m";
const RESET: &str = "\x1b[0m";

fn use_color() -> bool {
  std::env::var_os("NO_COLOR").is_none() && std::io::stderr().is_terminal()
}

fn paint(color: &str, text: &str) -> String {
  if use_color() {
    format!("{color}{text}{RESET}")
  } else {
    text.to_string()
  }
}

/// One line per secret that was skipped (already up to date).  Green.
pub fn skipped(msg: &str) {
  eprintln!("  {}  {msg}", paint(GREEN, "skipped"));
}

/// One line per secret that was rekeyed.  Cyan.
pub fn rekeyed(msg: &str) {
  eprintln!("  {}  {msg}", paint(CYAN, "rekeyed"));
}

/// One line per secret that was generated.  Cyan.
pub fn generated(msg: &str) {
  eprintln!("{}  {msg}", paint(CYAN, "generated"));
}
