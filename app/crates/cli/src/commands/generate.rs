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
  let to_generate: Vec<&GenerateEntry> = manifest
    .generate
    .iter()
    .filter(|e| wants_entry(e, &args.filter, &args.tags))
    .filter(|e| {
      let output_path = cwd.join(&e.path);
      args.force || !output_path.exists() || deps_are_newer(e, &output_path, &cwd)
    })
    .collect();

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
    tracing::info!(path = %entry.path, defs = ?entry.defs, "generating");
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

  // Substitute the __RAGENIX_DECRYPT__ placeholder baked into the script.
  let script = entry.script.replace("__RAGENIX_DECRYPT__", wrapper_str);

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

  tracing::info!(path = %entry.path, bytes = ciphertext.len(), "written");

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
