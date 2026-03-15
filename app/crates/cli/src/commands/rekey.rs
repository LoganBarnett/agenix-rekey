//! `rekey` subcommand — re-encrypt master-encrypted secrets for each host's pubkey.
//!
//! # Flow (local storage mode)
//!
//! For each host whose `storageMode` is `"local"`:
//! 1. For each secret, compute an identity hash from the host pubkey and the
//!    source file's content hash (same formula as the bash implementation).
//! 2. Collect the secrets that are absent or stale (or `--force`).
//! 3. If anything needs rekeying, load identities (may prompt for passphrases).
//! 4. Decrypt each source `.age` with the master identities; encrypt the
//!    plaintext to the host's age pubkey; write atomically.
//! 5. Remove orphaned `.age` files in the local storage directory.
//! 6. Optionally `git add` the storage directory.
//!
//! # Derivation storage mode
//!
//! Not yet implemented.  Hosts using derivation mode are skipped with a warning.
//! (Derivation mode requires `nix build --extra-sandbox-paths` which needs
//! deeper Nix integration.)
//!
//! # Identity hash formula
//!
//! Matches the Nix bash implementation exactly:
//! ```text
//! pubkeyHash = sha256(pubkey_string)
//! rekeyFileHash = sha256(file_contents)
//! identHash = sha256(pubkeyHash_hex + rekeyFileHash_hex)[..32]
//! outputPath = localStorageDir / identHash-secretName.age
//! ```

use std::collections::HashSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::status;

use ragenix_rekey_lib::{
  decrypt_file, encrypt_to_recipients, parse_recipient_string, IdentityError, IdentitySession,
};
use ragenix_rekey_lib::manifest::{HostConfig, HostSecret, Manifest, StorageMode};
use thiserror::Error;

// ── Constants ─────────────────────────────────────────────────────────────────

/// The sentinel pubkey that marks a host as a placeholder (no real key).
/// Matches the value from `modules/agenix-rekey.nix`.
const DUMMY_PUBKEY: &str =
  "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq";

const DUMMY_PLAINTEXT: &[u8] =
  b"This is a dummy replacement value used for testing purposes only.";

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum RekeyError {
  #[error("failed to load identities: {0}")]
  Identity(#[from] IdentityError),

  #[error("host {host} has local storage mode but localStorageDir is not set")]
  MissingLocalStorageDir { host: String },

  #[error("invalid pubkey for host {host}: {source}")]
  InvalidPubkey {
    host: String,
    #[source]
    source: IdentityError,
  },

  #[error("failed to decrypt {src} for host {host}: {source}")]
  DecryptFailed {
    src: String,
    host: String,
    #[source]
    source: IdentityError,
  },

  #[error("failed to encrypt for host {host}: {source}")]
  EncryptFailed {
    host: String,
    #[source]
    source: IdentityError,
  },

  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
}

// ── Public API ────────────────────────────────────────────────────────────────

pub struct RekeyArgs {
  pub force: bool,
  pub add_to_git: bool,
  /// Substitute a dummy plaintext instead of decrypting; useful for CI.
  pub dummy: bool,
  pub no_prompt: bool,
}

/// Run the rekey command.
///
/// Identity loading (and any passphrase prompt) is deferred until after we
/// know there is at least one secret that actually needs rekeying.
pub fn run(args: &RekeyArgs, manifest: &Manifest) -> Result<(), RekeyError> {
  // `manifest.flake_dir` is the Nix store copy of the user's flake (read-only)
  // and is used only for reading source `.age` files during decryption.
  // All output paths are resolved relative to CWD, which must be the user's
  // actual flake root (same contract as the bash rekey script).
  let flake_dir = &manifest.flake_dir;
  let cwd = std::env::current_dir()?;

  // Partition hosts, warn about unsupported modes.
  let mut local_hosts: Vec<(&String, &HostConfig)> = Vec::new();

  let mut hosts: Vec<(&String, &HostConfig)> = manifest.hosts.iter().collect();
  hosts.sort_by_key(|(name, _)| name.as_str());

  for (hostname, host) in hosts {
    if host.pubkey == DUMMY_PUBKEY {
      tracing::info!(host = %hostname, "skipping (dummy pubkey)");
      continue;
    }
    match host.storage_mode {
      StorageMode::Local => {
        if host.local_storage_dir.is_none() {
          return Err(RekeyError::MissingLocalStorageDir { host: hostname.clone() });
        }
        local_hosts.push((hostname, host));
      }
      StorageMode::Derivation => {
        tracing::warn!(
          host = %hostname,
          "derivation storage mode is not yet supported by the Rust runtime; skipping"
        );
      }
    }
  }

  // Determine what needs rekeying before loading identities.
  struct WorkItem<'a> {
    hostname: &'a str,
    host: &'a HostConfig,
    storage_dir: PathBuf,
    /// Secrets that need rekeying: (name, host_secret, output_path)
    pending: Vec<(&'a String, &'a HostSecret, PathBuf)>,
    /// All expected output paths for this host (for orphan cleanup).
    all_outputs: HashSet<PathBuf>,
  }

  let mut work: Vec<WorkItem> = Vec::new();

  for (hostname, host) in &local_hosts {
    // `local_storage_dir` is a flake-relative path (e.g. "./secrets/rekeyed/host").
    // Resolve against CWD so writes go to the user's actual filesystem.
    let storage_dir = cwd.join(host.local_storage_dir.as_ref().unwrap());
    let mut pending = Vec::new();
    let mut all_outputs = HashSet::new();

    let mut secrets: Vec<(&String, &HostSecret)> = host.secrets.iter().collect();
    secrets.sort_by_key(|(name, _)| name.as_str());

    for (secret_name, secret) in secrets {
      // Intermediary secrets exist only as generator dependencies and are
      // never deployed to hosts.  Skip them entirely — any previously-rekeyed
      // file will be removed by the orphan sweep below.
      if secret.intermediary {
        continue;
      }

      let output_path = storage_dir.join(format!("{}-{}.age", secret.ident_hash, secret_name));

      all_outputs.insert(output_path.clone());

      if !args.force && output_path.exists() {
        status::skipped(&format!("{hostname}/{secret_name}"));
        continue;
      }

      pending.push((secret_name, secret, output_path));
    }

    if !pending.is_empty() {
      work.push(WorkItem {
        hostname,
        host,
        storage_dir,
        pending,
        all_outputs,
      });
    }
  }

  if work.is_empty() {
    tracing::info!("nothing to rekey (all secrets up to date)");
    return Ok(());
  }

  // Load identities now — may prompt for passphrases.
  let session = IdentitySession::load(
    &manifest.master_identities,
    &manifest.extra_encryption_pubkeys,
    args.no_prompt,
  )?;

  let mut total = 0usize;

  for item in &work {
    let host_recipients = vec![
      parse_recipient_string(&item.host.pubkey).map_err(|e| RekeyError::InvalidPubkey {
        host: item.hostname.to_string(),
        source: e,
      })?,
    ];

    std::fs::create_dir_all(&item.storage_dir)?;

    for (secret_name, secret, output_path) in &item.pending {
      tracing::debug!(host = %item.hostname, secret = %secret_name, "rekeying");

      // Prefer the CWD copy of the source file so that secrets freshly
      // generated in the same workflow (not yet committed to git, and
      // therefore absent from the read-only flake_dir store path) can be
      // rekeyed immediately without requiring a git commit + flake rebuild.
      let src_path = {
        let cwd_path = cwd.join(&secret.rekey_file);
        if cwd_path.exists() { cwd_path } else { flake_dir.join(&secret.rekey_file) }
      };

      let plaintext = if args.dummy {
        DUMMY_PLAINTEXT.to_vec()
      } else {
        decrypt_file(&src_path, &session.identities).map_err(|e| RekeyError::DecryptFailed {
          src: src_path.display().to_string(),
          host: item.hostname.to_string(),
          source: e,
        })?
      };

      let ciphertext =
        encrypt_to_recipients(&plaintext, &host_recipients).map_err(|e| {
          RekeyError::EncryptFailed {
            host: item.hostname.to_string(),
            source: e,
          }
        })?;

      write_atomic(output_path, &ciphertext)?;

      status::rekeyed(&format!("{}/{}", item.hostname, secret_name));
      total += 1;
    }

    // Remove orphaned .age files in the storage dir.
    let removed = remove_orphans(&item.storage_dir, &item.all_outputs)?;
    if removed > 0 {
      tracing::info!(host = %item.hostname, count = removed, "removed orphaned files");
    }

    if args.add_to_git && (!item.pending.is_empty() || removed > 0) {
      let status = std::process::Command::new("git")
        .arg("add")
        .arg(&item.storage_dir)
        .current_dir(&cwd)
        .status()?;
      if !status.success() {
        tracing::warn!(path = %item.storage_dir.display(), "git add returned non-zero");
      }
    }
  }

  tracing::info!(rekeyed = total, "rekey complete");
  Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Write `data` to `path` atomically (temp file in same dir + rename).
fn write_atomic(path: &Path, data: &[u8]) -> Result<(), std::io::Error> {
  let dir = path.parent().unwrap_or(Path::new("."));
  std::fs::create_dir_all(dir)?;

  let mut tmp = tempfile::Builder::new()
    .prefix(".tmp.ragenix.")
    .suffix(".tmp")
    .tempfile_in(dir)?;

  tmp.write_all(data)?;
  tmp.persist(path).map_err(|e| e.error)?;

  Ok(())
}

/// Remove `.age` files in `dir` whose paths are not in `tracked`.
/// Returns the number of files removed.
fn remove_orphans(dir: &Path, tracked: &HashSet<PathBuf>) -> Result<usize, std::io::Error> {
  if !dir.exists() {
    return Ok(0);
  }

  let mut removed = 0;
  for entry in std::fs::read_dir(dir)? {
    let entry = entry?;
    let path = entry.path();
    if path.is_file()
      && path.extension().and_then(|e| e.to_str()) == Some("age")
      && !tracked.contains(&path)
    {
      std::fs::remove_file(&path)?;
      tracing::debug!(path = %path.display(), "removed orphan");
      removed += 1;
    }
  }

  Ok(removed)
}
