//! Manifest types shared between the Nix layer and all subcommands.
//!
//! The Nix layer serialises a [`Manifest`] to JSON and passes its path via
//! `--manifest` / `RAGENIX_REKEY_MANIFEST`.  Every subcommand deserialises
//! the same file and uses whichever fields it needs.
//!
//! JSON keys are camelCase (matching Nix attrset conventions); Rust fields
//! are snake_case as usual.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

// ── Top-level ────────────────────────────────────────────────────────────────

/// The complete manifest produced by `nix eval` and consumed by every
/// ragenix-rekey subcommand.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
  /// Absolute path to the user's flake root directory.
  pub flake_dir: PathBuf,

  /// Master identities used for encrypting and decrypting secrets.
  pub master_identities: Vec<MasterIdentity>,

  /// Additional recipients for encryption beyond the master identities
  /// (pubkey strings or absolute paths to recipient files).
  #[serde(default)]
  pub extra_encryption_pubkeys: Vec<String>,

  /// Secrets that have generators, in dependency order (dependencies always
  /// appear before the secrets that depend on them).
  ///
  /// Used by the `generate` subcommand.
  pub generate: Vec<GenerateEntry>,

  /// Per-host configuration for rekeying.
  ///
  /// Used by the `rekey` and `update-masterkeys` subcommands.
  pub hosts: HashMap<String, HostConfig>,
}

// ── Master identities ────────────────────────────────────────────────────────

/// A single master identity used for encryption and decryption.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MasterIdentity {
  /// Absolute path to the identity file.
  ///
  /// May be a plain age identity, a passphrase-protected age identity
  /// (`.age` extension), or a plugin identity file.
  pub identity: PathBuf,

  /// Explicit public key for this identity.
  ///
  /// When present it is used for encryption in place of prompting the
  /// identity, avoiding unnecessary passphrase prompts for keys that are
  /// only needed for decryption.
  pub pubkey: Option<String>,
}

// ── Generate entries ─────────────────────────────────────────────────────────

/// A single secret entry for the `generate` subcommand.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateEntry {
  /// Relative path from the flake root to the output `.age` file.
  pub path: String,

  /// Human-readable `"host:secretName"` labels used in log messages.
  pub defs: Vec<String>,

  /// Fully-resolved bash script that writes the plaintext secret to stdout.
  ///
  /// All Nix store paths are already interpolated; the script can be run
  /// directly with `bash -c`.
  ///
  /// The script receives the following environment / arguments:
  /// - `$decrypt` — `"cat"` for backward compatibility with scripts that
  ///   call `${decrypt} ${dep.file}`.  Dependencies are pre-decrypted to
  ///   FIFOs by the runtime, so `cat` is sufficient.
  /// - `$file`    — the output path (same as `path`).
  /// - `$name`    — the secret name as defined in `age.secrets`.
  pub script: String,

  /// Tags used for `--tags` filtering.
  #[serde(default)]
  pub tags: Vec<String>,

  /// Validated settings from the generator's `settingsModule`, serialised
  /// as a JSON object.  `null` when no `settingsModule` was declared.
  pub settings: serde_json::Value,

  /// Secrets that must be decrypted before this script runs.
  ///
  /// All dependencies are guaranteed to appear earlier in the `generate`
  /// list (topological order is computed by Nix).
  #[serde(default)]
  pub dependencies: Vec<DependencyEntry>,
}

/// A single dependency of a generated secret.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyEntry {
  /// The secret's name as defined in `age.secrets`.
  pub name: String,

  /// The hostname that defines this secret.
  pub host: String,

  /// Relative path from the flake root to the dependency's `.age` file.
  pub path: String,
}

// ── Host / rekey entries ─────────────────────────────────────────────────────

/// Per-host configuration used by the `rekey` subcommand.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostConfig {
  /// The host's age public key (used as the rekey recipient).
  pub pubkey: String,

  /// Where rekeyed secrets are stored.
  pub storage_mode: StorageMode,

  /// Directory for rekeyed secrets.  Required when `storage_mode` is
  /// [`StorageMode::Local`].
  pub local_storage_dir: Option<String>,

  /// Secrets to rekey for this host, keyed by secret name.
  pub secrets: HashMap<String, HostSecret>,
}

/// Storage strategy for rekeyed secrets.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum StorageMode {
  /// Secrets are stored as files in `local_storage_dir`.
  Local,
  /// Secrets are stored inside a Nix derivation (legacy mode).
  Derivation,
}

/// A single secret within a host's configuration.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostSecret {
  /// Relative path to the master-encrypted `.age` file.
  pub rekey_file: String,

  /// When true this secret is only used as an intermediary and should not
  /// be deployed to the host (a dummy secret is used in its place).
  #[serde(default)]
  pub intermediary: bool,
}
