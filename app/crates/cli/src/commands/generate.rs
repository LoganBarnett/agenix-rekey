//! `generate` subcommand — run generator scripts and encrypt their output.
//!
//! # Flow
//!
//! For each [`GenerateEntry`] in the manifest (already in topological order):
//! 1. Check the filter / tags to see if the entry is wanted.
//! 2. Determine whether regeneration is needed (force flag, file absent, or
//!    any dependency newer than the output).
//! 3. Pre-decrypt every dependency to a restricted temp file (mode 0600 inside
//!    a mode 0700 directory).
//! 4. Write a small shell "decrypt wrapper" script that maps each dep's
//!    original path to its temp file via `cat`.
//! 5. Substitute the `__RAGENIX_DECRYPT__` placeholder in the generator script
//!    string with the wrapper path, so old-style `${decrypt} dep.age` calls
//!    route through it.
//! 6. Execute the script with `bash -c`, also setting `$decrypt` as an env var
//!    (for generators that use `$decrypt` in bash rather than `${decrypt}` in
//!    Nix interpolation).
//! 7. Encrypt stdout with all session recipients; write armored output.
//! 8. Optionally `git add` the output file.
//!
//! After processing all entries, any `.age` files in known generation
//! directories that are no longer referenced are removed (orphan cleanup).

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::status;

use ragenix_rekey_lib::{
  decrypt_file, encrypt_to_recipients, IdentityError, IdentitySession,
};
use ragenix_rekey_lib::manifest::{GenerateEntry, Manifest};
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum GenerateError {
  #[error(
    "filter path {0} matches no known secret — \
     pass a path relative to the flake root (e.g. ./secrets/foo.age)"
  )]
  UnknownFilterPath(String),

  #[error("no encryption recipients available; add a pubkey to at least one master identity")]
  NoRecipients,

  #[error("failed to load identities: {0}")]
  Identity(#[from] IdentityError),

  #[error("failed to decrypt dependency {dep} for {secret}: {source}")]
  DepDecrypt {
    dep: String,
    secret: String,
    #[source]
    source: IdentityError,
  },

  #[error("generator script failed for {path} (exit {status}):\n{stderr}")]
  ScriptFailed {
    path: String,
    status: i32,
    stderr: String,
  },

  #[error("failed to encrypt generated secret {path}: {source}")]
  EncryptSecret {
    path: String,
    #[source]
    source: IdentityError,
  },

  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Arguments extracted from the CLI `generate` subcommand.
pub struct GenerateArgs {
  /// Force re-generation even when the output file exists and deps are
  /// unmodified.
  pub force: bool,
  /// Stage generated / removed files with `git add`.
  pub add_to_git: bool,
  /// Additional secret selection by tag (each element may be comma-separated).
  pub tags: Vec<String>,
  /// Limit generation to these paths (relative to flake root).
  pub filter: Vec<String>,
  /// Fail if a passphrase prompt would be needed to load an identity.
  pub no_prompt: bool,
}

/// Run the generate command.
///
/// Identity loading (and any passphrase prompt) is deferred until after we
/// know there is at least one entry that actually needs (re)generation.
/// A no-op run (all secrets up-to-date) exits without touching identities.
pub fn run(args: &GenerateArgs, manifest: &Manifest) -> Result<(), GenerateError> {
  // `manifest.flake_dir` is the Nix store copy of the user's flake (read-only).
  // All output is written relative to CWD, which must be the user's actual
  // flake root (same contract as the bash generate script).
  let cwd = std::env::current_dir()?;

  // Validate filter paths up-front for a clear error message.
  for f in &args.filter {
    let known = manifest
      .generate
      .iter()
      .any(|e| e.path == *f || cwd.join(&e.path) == PathBuf::from(f));
    if !known {
      return Err(GenerateError::UnknownFilterPath(f.clone()));
    }
  }

  // Determine which entries need (re)generation before loading identities.
  // Iterate every in-scope entry so we can print a status line for each one,
  // including those that are already up to date.
  let mut to_generate: Vec<&GenerateEntry> = Vec::new();

  for entry in manifest.generate.iter().filter(|e| wants_entry(e, &args.filter, &args.tags)) {
    let output_path = cwd.join(&entry.path);
    if !args.force && output_path.exists() && !deps_are_newer(entry, &output_path, &cwd) {
      status::skipped(&entry.path);
    } else {
      to_generate.push(entry);
    }
  }

  if to_generate.is_empty() {
    tracing::info!("nothing to generate (all secrets up to date)");
    return Ok(());
  }

  // Load identities now — may prompt for passphrases.
  let session = IdentitySession::load(
    &manifest.master_identities,
    &manifest.extra_encryption_pubkeys,
    args.no_prompt,
  )?;

  if session.recipients.is_empty() {
    return Err(GenerateError::NoRecipients);
  }

  let count = to_generate.len();
  for entry in to_generate {
    tracing::debug!(path = %entry.path, defs = ?entry.defs, "generating");
    let output_path = cwd.join(&entry.path);
    generate_entry(entry, &output_path, &cwd, args.add_to_git, &session)?;
  }

  tracing::info!(generated = count, "generate complete");
  Ok(())
}

// ── Filter logic ──────────────────────────────────────────────────────────────

/// Return `true` if this entry should be generated given the provided
/// path filter and tag sets.
fn wants_entry(entry: &GenerateEntry, filter: &[String], tags: &[String]) -> bool {
  // No filter at all → generate everything.
  if filter.is_empty() && tags.is_empty() {
    return true;
  }

  // Path filter: entry path matches one of the positional arguments.
  for f in filter {
    if entry.path == *f {
      return true;
    }
  }

  // Tag filter: any comma-separated tag in --tags overlaps entry.tags.
  for tag_arg in tags {
    for tag in tag_arg.split(',') {
      let tag = tag.trim();
      if entry.tags.iter().any(|et| et == tag) {
        return true;
      }
    }
  }

  false
}

// ── Staleness check ───────────────────────────────────────────────────────────

/// Return `true` if any dependency is newer than the output file.
fn deps_are_newer(entry: &GenerateEntry, output_path: &Path, flake_dir: &Path) -> bool {
  let output_mtime = match output_path.metadata().and_then(|m| m.modified()) {
    Ok(t) => t,
    Err(_) => return true,
  };

  for dep in &entry.dependencies {
    let dep_path = flake_dir.join(&dep.path);
    if let Ok(meta) = dep_path.metadata() {
      if let Ok(dep_mtime) = meta.modified() {
        if dep_mtime > output_mtime {
          return true;
        }
      }
    }
  }

  false
}

// ── Per-entry generation ──────────────────────────────────────────────────────

fn generate_entry(
  entry: &GenerateEntry,
  output_path: &Path,
  flake_dir: &Path,
  add_to_git: bool,
  session: &IdentitySession,
) -> Result<(), GenerateError> {
  // Restricted temp directory for dep plaintext and the decrypt wrapper.
  let dep_dir = tempfile::Builder::new()
    .prefix("ragenix-deps-")
    .tempdir()?;

  set_mode_700(dep_dir.path())?;

  // Pre-decrypt each dependency secret to a temp file.
  let mut dep_map: HashMap<String, PathBuf> = HashMap::new();

  for dep in &entry.dependencies {
    let dep_age_path = flake_dir.join(&dep.path);
    let temp_path = dep_dir.path().join(&dep.name);

    let plaintext =
      decrypt_file(&dep_age_path, &session.identities).map_err(|e| {
        GenerateError::DepDecrypt {
          dep: dep.path.clone(),
          secret: entry.path.clone(),
          source: e,
        }
      })?;

    std::fs::write(&temp_path, &plaintext)?;
    set_mode_600(&temp_path)?;

    dep_map.insert(dep.path.clone(), temp_path);
  }

  // Write the decrypt wrapper script.
  let wrapper_path = dep_dir.path().join("decrypt");
  write_decrypt_wrapper(&wrapper_path, &dep_map)?;

  let wrapper_str = wrapper_path
    .to_str()
    .unwrap_or("/dev/null");

  // Write the git-add wrapper script.
  let git_add_path = dep_dir.path().join("git-add");
  write_git_add_wrapper(&git_add_path, add_to_git)?;

  let git_add_str = git_add_path
    .to_str()
    .unwrap_or("true");

  // Substitute the placeholders baked into the script by apps/manifest.nix.
  let script = entry.script
    .replace("__RAGENIX_DECRYPT__", wrapper_str)
    .replace("__RAGENIX_GIT_ADD__", git_add_str);

  // Derive $name from the first "host:secretName" def, or fall back to path.
  let name = entry
    .defs
    .first()
    .and_then(|d| d.split(':').nth(1))
    .unwrap_or(&entry.path);

  // Execute the generator script.
  let output = std::process::Command::new("bash")
    .arg("-c")
    .arg(&script)
    // Set $decrypt for bash-style `$decrypt dep.age` usage (backward compat).
    .env("decrypt", wrapper_str)
    // Set $gitAdd so generators can call it without Nix interpolation.
    .env("gitAdd", git_add_str)
    // Conventional env vars that generators may reference.
    .env("file", &entry.path)
    .env("name", name)
    .current_dir(flake_dir)
    .output()?;

  if !output.status.success() {
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    return Err(GenerateError::ScriptFailed {
      path: entry.path.clone(),
      status: output.status.code().unwrap_or(-1),
      stderr,
    });
  }

  // Encrypt the generator's stdout.
  let ciphertext =
    encrypt_to_recipients(&output.stdout, &session.recipients).map_err(|e| {
      GenerateError::EncryptSecret {
        path: entry.path.clone(),
        source: e,
      }
    })?;

  // Write the output file.
  if let Some(parent) = output_path.parent() {
    std::fs::create_dir_all(parent)?;
  }
  std::fs::write(output_path, &ciphertext)?;

  status::generated(&entry.path);

  if add_to_git {
    let status = std::process::Command::new("git")
      .arg("add")
      .arg(output_path)
      .current_dir(flake_dir)
      .status()?;

    if !status.success() {
      tracing::warn!(path = %output_path.display(), "git add returned non-zero");
    }
  }

  Ok(())
}

// ── Decrypt wrapper script ────────────────────────────────────────────────────

/// Write a shell script that maps dep paths to pre-decrypted temp files.
///
/// Old-style generator scripts call `${decrypt} <path>` where `${decrypt}`
/// was expanded at Nix eval time.  At runtime, the placeholder is substituted
/// with this wrapper path, so `dep.age` → `cat /tmp/.../dep`.
fn write_decrypt_wrapper(
  wrapper_path: &Path,
  dep_map: &HashMap<String, PathBuf>,
) -> Result<(), std::io::Error> {
  let mut script = String::from("#!/bin/sh\ncase \"$1\" in\n");

  for (dep_path, temp_path) in dep_map {
    script.push_str(&format!(
      "  {})\n    cat {}\n    ;;\n",
      shell_single_quote(dep_path),
      shell_single_quote(temp_path.to_str().unwrap_or("")),
    ));
  }

  script.push_str(
    "  *)\n    printf 'ragenix-rekey: unknown dep: %s\\n' \"$1\" >&2\n    exit 1\n    ;;\nesac\n",
  );

  let mut file = std::fs::File::create(wrapper_path)?;
  file.write_all(script.as_bytes())?;
  drop(file);

  set_mode_700(wrapper_path)?;

  Ok(())
}

/// Write a shell script that either runs `git add "$@"` or silently no-ops,
/// depending on whether `add_to_git` is true.
///
/// Generator scripts receive the path to this wrapper as `$gitAdd` (env var)
/// or via `__RAGENIX_GIT_ADD__` substitution (Nix interpolation style), and
/// call it unconditionally on any companion files they write alongside the
/// encrypted secret (e.g. a `.pub` key for a generated private key).
fn write_git_add_wrapper(wrapper_path: &Path, add_to_git: bool) -> Result<(), std::io::Error> {
  let script = if add_to_git {
    "#!/bin/sh\nexec git add \"$@\"\n"
  } else {
    "#!/bin/sh\ntrue\n"
  };

  std::fs::write(wrapper_path, script)?;
  set_mode_700(wrapper_path)?;

  Ok(())
}

// ── Shell / permission helpers ────────────────────────────────────────────────

/// Single-quote a string for safe embedding in POSIX shell.
fn shell_single_quote(s: &str) -> String {
  format!("'{}'", s.replace('\'', r"'\''"))
}

#[cfg(unix)]
fn set_mode_700(path: &Path) -> Result<(), std::io::Error> {
  use std::os::unix::fs::PermissionsExt;
  std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_mode_700(_path: &Path) -> Result<(), std::io::Error> {
  Ok(())
}

#[cfg(unix)]
fn set_mode_600(path: &Path) -> Result<(), std::io::Error> {
  use std::os::unix::fs::PermissionsExt;
  std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_mode_600(_path: &Path) -> Result<(), std::io::Error> {
  Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
  use super::*;
  use ragenix_rekey_lib::manifest::DependencyEntry;
  use std::fs::FileTimes;
  use std::time::{Duration, SystemTime};
  use tempfile::tempdir;

  fn make_entry(path: &str, tags: &[&str]) -> GenerateEntry {
    GenerateEntry {
      path: path.to_string(),
      defs: vec![],
      script: String::new(),
      tags: tags.iter().map(|s| s.to_string()).collect(),
      settings: serde_json::Value::Null,
      dependencies: vec![],
    }
  }

  fn make_entry_with_dep(path: &str, dep_path: &str) -> GenerateEntry {
    GenerateEntry {
      path: path.to_string(),
      defs: vec![],
      script: String::new(),
      tags: vec![],
      settings: serde_json::Value::Null,
      dependencies: vec![DependencyEntry {
        name: "dep".to_string(),
        host: "host1".to_string(),
        path: dep_path.to_string(),
      }],
    }
  }

  fn set_mtime(path: &Path, secs_since_epoch: u64) {
    let t = SystemTime::UNIX_EPOCH + Duration::from_secs(secs_since_epoch);
    let times = FileTimes::new().set_modified(t);
    std::fs::OpenOptions::new()
      .write(true)
      .open(path)
      .unwrap()
      .set_times(times)
      .unwrap();
  }

  // ── wants_entry ─────────────────────────────────────────────────────────────

  #[test]
  fn wants_entry_no_filter_matches_all() {
    let e = make_entry("./secrets/foo.age", &["tls"]);
    assert!(wants_entry(&e, &[], &[]));
  }

  #[test]
  fn wants_entry_path_filter_exact_match() {
    let e = make_entry("./secrets/foo.age", &[]);
    assert!(wants_entry(&e, &["./secrets/foo.age".to_string()], &[]));
  }

  #[test]
  fn wants_entry_path_filter_no_match() {
    let e = make_entry("./secrets/foo.age", &[]);
    assert!(!wants_entry(&e, &["./secrets/bar.age".to_string()], &[]));
  }

  #[test]
  fn wants_entry_tag_filter_single_match() {
    let e = make_entry("./secrets/cert.age", &["tls", "infra"]);
    assert!(wants_entry(&e, &[], &["tls".to_string()]));
  }

  #[test]
  fn wants_entry_tag_filter_comma_separated_one_matches() {
    let e = make_entry("./secrets/cert.age", &["tls"]);
    assert!(wants_entry(&e, &[], &["other,tls,infra".to_string()]));
  }

  #[test]
  fn wants_entry_tag_filter_no_match() {
    let e = make_entry("./secrets/cert.age", &["tls"]);
    assert!(!wants_entry(&e, &[], &["infra".to_string()]));
  }

  #[test]
  fn wants_entry_path_filter_wins_when_tag_misses() {
    let e = make_entry("./secrets/foo.age", &["tls"]);
    assert!(wants_entry(
      &e,
      &["./secrets/foo.age".to_string()],
      &["infra".to_string()]
    ));
  }

  #[test]
  fn wants_entry_neither_filter_nor_tag_matches() {
    let e = make_entry("./secrets/foo.age", &["tls"]);
    assert!(!wants_entry(
      &e,
      &["./secrets/bar.age".to_string()],
      &["infra".to_string()]
    ));
  }

  // ── deps_are_newer ──────────────────────────────────────────────────────────

  #[test]
  fn deps_are_newer_output_missing_returns_true() {
    let dir = tempdir().unwrap();
    let output = dir.path().join("output.age");
    // output does not exist
    let entry = make_entry("output.age", &[]);
    assert!(deps_are_newer(&entry, &output, dir.path()));
  }

  #[test]
  fn deps_are_newer_no_deps_returns_false() {
    let dir = tempdir().unwrap();
    let output = dir.path().join("output.age");
    std::fs::write(&output, b"data").unwrap();
    set_mtime(&output, 2000);

    let entry = make_entry("output.age", &[]);
    assert!(!deps_are_newer(&entry, &output, dir.path()));
  }

  #[test]
  fn deps_are_newer_dep_older_returns_false() {
    let dir = tempdir().unwrap();
    let dep = dir.path().join("dep.age");
    let output = dir.path().join("output.age");

    std::fs::write(&dep, b"dep").unwrap();
    std::fs::write(&output, b"out").unwrap();

    set_mtime(&dep, 1000);
    set_mtime(&output, 2000); // output newer than dep

    let entry = make_entry_with_dep("output.age", "dep.age");
    assert!(!deps_are_newer(&entry, &output, dir.path()));
  }

  #[test]
  fn deps_are_newer_dep_newer_returns_true() {
    let dir = tempdir().unwrap();
    let dep = dir.path().join("dep.age");
    let output = dir.path().join("output.age");

    std::fs::write(&dep, b"dep").unwrap();
    std::fs::write(&output, b"out").unwrap();

    set_mtime(&output, 1000);
    set_mtime(&dep, 2000); // dep newer than output

    let entry = make_entry_with_dep("output.age", "dep.age");
    assert!(deps_are_newer(&entry, &output, dir.path()));
  }

  #[test]
  fn deps_are_newer_missing_dep_file_is_ignored() {
    // A dep that doesn't exist on disk is silently skipped — the output
    // is not considered stale on account of a missing dep.
    let dir = tempdir().unwrap();
    let output = dir.path().join("output.age");
    std::fs::write(&output, b"out").unwrap();
    set_mtime(&output, 2000);

    let entry = make_entry_with_dep("output.age", "ghost.age"); // ghost.age doesn't exist
    assert!(!deps_are_newer(&entry, &output, dir.path()));
  }

  // ── write_git_add_wrapper ────────────────────────────────────────────────────

  #[test]
  fn git_add_wrapper_noop_when_false() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("git-add");
    write_git_add_wrapper(&path, false).unwrap();
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(
      content.contains("true"),
      "expected no-op script to contain 'true', got: {content}"
    );
    assert!(
      !content.contains("git add"),
      "expected no-op script not to call git add, got: {content}"
    );
  }

  #[test]
  fn git_add_wrapper_executes_git_add_when_true() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("git-add");
    write_git_add_wrapper(&path, true).unwrap();
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(
      content.contains("git add"),
      "expected active script to contain 'git add', got: {content}"
    );
  }

  #[cfg(unix)]
  #[test]
  fn git_add_wrapper_is_mode_700() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    let path = dir.path().join("git-add");
    write_git_add_wrapper(&path, false).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(
      mode & 0o777,
      0o700,
      "expected mode 0700, got {:o}",
      mode & 0o777
    );
  }

  // ── shell_single_quote ───────────────────────────────────────────────────────

  #[test]
  fn shell_quote_simple_string() {
    assert_eq!(shell_single_quote("hello"), "'hello'");
  }

  #[test]
  fn shell_quote_empty_string() {
    assert_eq!(shell_single_quote(""), "''");
  }

  #[test]
  fn shell_quote_string_with_spaces() {
    assert_eq!(shell_single_quote("hello world"), "'hello world'");
  }

  #[test]
  fn shell_quote_string_with_single_quote() {
    // it's  →  'it'\''s'
    assert_eq!(shell_single_quote("it's"), r"'it'\''s'");
  }

  #[test]
  fn shell_quote_string_with_special_chars() {
    assert_eq!(shell_single_quote("$HOME/foo"), "'$HOME/foo'");
  }

  #[test]
  fn shell_quote_path_with_single_quote_in_dirname() {
    // /tmp/bob's dir/file  →  '/tmp/bob'\''s dir/file'
    assert_eq!(
      shell_single_quote("/tmp/bob's dir/file"),
      r"'/tmp/bob'\''s dir/file'"
    );
  }

  #[test]
  fn shell_quote_multiple_single_quotes() {
    assert_eq!(shell_single_quote("a'b'c"), r"'a'\''b'\''c'");
  }
}
