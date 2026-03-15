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

// Tests are at the bottom of this file.

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

  /// Output filename prefix computed by Nix eval using the same formula as
  /// the bash rekey script:
  ///
  /// ```text
  /// sha256( sha256(pubkey) + hashFile(rekeyFile) )[..32]
  /// ```
  ///
  /// Storing it in the manifest ensures Nix and Rust always agree on the
  /// output path (avoids divergence from e.g. trailing newlines in pubkeys
  /// read via `builtins.readFile`).
  pub ident_hash: String,

  /// When true this secret is only used as an intermediary and should not
  /// be deployed to the host (a dummy secret is used in its place).
  #[serde(default)]
  pub intermediary: bool,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
  use super::*;

  // ── StorageMode ─────────────────────────────────────────────────────────────

  #[test]
  fn storage_mode_deserialises_local() {
    let m: StorageMode = serde_json::from_str("\"local\"").unwrap();
    assert!(matches!(m, StorageMode::Local));
  }

  #[test]
  fn storage_mode_deserialises_derivation() {
    let m: StorageMode = serde_json::from_str("\"derivation\"").unwrap();
    assert!(matches!(m, StorageMode::Derivation));
  }

  #[test]
  fn storage_mode_round_trips() {
    for mode in [StorageMode::Local, StorageMode::Derivation] {
      let json = serde_json::to_string(&mode).unwrap();
      let back: StorageMode = serde_json::from_str(&json).unwrap();
      assert_eq!(
        serde_json::to_string(&back).unwrap(),
        json,
        "StorageMode round-trip failed for {json}"
      );
    }
  }

  // ── HostSecret ──────────────────────────────────────────────────────────────

  #[test]
  fn host_secret_deserialises_required_fields() {
    let json = r#"{
      "rekeyFile": "./secrets/foo.age",
      "identHash": "abc123def456789012345678901234ab"
    }"#;
    let s: HostSecret = serde_json::from_str(json).unwrap();
    assert_eq!(s.rekey_file, "./secrets/foo.age");
    assert_eq!(s.ident_hash, "abc123def456789012345678901234ab");
    assert!(!s.intermediary, "intermediary should default to false");
  }

  #[test]
  fn host_secret_deserialises_intermediary_true() {
    let json = r#"{
      "rekeyFile": "./secrets/ca.age",
      "identHash": "deadbeef00000000000000000000abcd",
      "intermediary": true
    }"#;
    let s: HostSecret = serde_json::from_str(json).unwrap();
    assert!(s.intermediary);
  }

  // ── HostConfig ──────────────────────────────────────────────────────────────

  #[test]
  fn host_config_with_local_storage() {
    let json = r#"{
      "pubkey": "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
      "storageMode": "local",
      "localStorageDir": "./secrets/rekeyed/myhost",
      "secrets": {
        "myapp": {
          "rekeyFile": "./secrets/myapp.age",
          "identHash": "1234567890abcdef1234567890abcdef"
        }
      }
    }"#;
    let h: HostConfig = serde_json::from_str(json).unwrap();
    assert_eq!(h.local_storage_dir.as_deref(), Some("./secrets/rekeyed/myhost"));
    assert!(matches!(h.storage_mode, StorageMode::Local));
    assert!(h.secrets.contains_key("myapp"));
  }

  #[test]
  fn host_config_null_local_storage_dir() {
    let json = r#"{
      "pubkey": "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
      "storageMode": "derivation",
      "localStorageDir": null,
      "secrets": {}
    }"#;
    let h: HostConfig = serde_json::from_str(json).unwrap();
    assert!(h.local_storage_dir.is_none());
    assert!(matches!(h.storage_mode, StorageMode::Derivation));
  }

  // ── GenerateEntry ────────────────────────────────────────────────────────────

  #[test]
  fn generate_entry_defaults_for_optional_fields() {
    let json = r#"{
      "path": "./secrets/gen.age",
      "defs": ["host1:mysecret"],
      "script": "echo hello",
      "tags": [],
      "settings": null
    }"#;
    let e: GenerateEntry = serde_json::from_str(json).unwrap();
    assert_eq!(e.path, "./secrets/gen.age");
    assert!(e.dependencies.is_empty(), "dependencies should default to empty");
  }

  #[test]
  fn generate_entry_with_dependency() {
    let json = r#"{
      "path": "./secrets/leaf.age",
      "defs": ["host1:leaf"],
      "script": "sign",
      "tags": ["tls"],
      "settings": null,
      "dependencies": [
        {"name": "ca", "host": "host1", "path": "./secrets/ca.age"}
      ]
    }"#;
    let e: GenerateEntry = serde_json::from_str(json).unwrap();
    assert_eq!(e.dependencies.len(), 1);
    assert_eq!(e.dependencies[0].name, "ca");
    assert_eq!(e.dependencies[0].host, "host1");
    assert_eq!(e.dependencies[0].path, "./secrets/ca.age");
  }

  // ── Full Manifest ────────────────────────────────────────────────────────────

  #[test]
  fn full_manifest_round_trip() {
    let json = r#"{
      "flakeDir": "/nix/store/abc-source",
      "masterIdentities": [
        {"identity": "/path/to/key.txt", "pubkey": "age1abc"},
        {"identity": "/path/to/encrypted.age", "pubkey": null}
      ],
      "extraEncryptionPubkeys": ["age1extra"],
      "generate": [],
      "hosts": {
        "server": {
          "pubkey": "age1server",
          "storageMode": "local",
          "localStorageDir": "./secrets/rekeyed/server",
          "secrets": {
            "db-pass": {
              "rekeyFile": "./secrets/db-pass.age",
              "identHash": "ffffffffffffffffffffffffffffffff",
              "intermediary": false
            }
          }
        }
      }
    }"#;

    let m: Manifest = serde_json::from_str(json).unwrap();
    assert_eq!(m.master_identities.len(), 2);
    assert_eq!(m.master_identities[0].pubkey.as_deref(), Some("age1abc"));
    assert!(m.master_identities[1].pubkey.is_none());
    assert_eq!(m.extra_encryption_pubkeys, vec!["age1extra"]);
    assert!(m.generate.is_empty());
    assert!(m.hosts.contains_key("server"));
    let server = &m.hosts["server"];
    assert_eq!(server.secrets["db-pass"].ident_hash, "ffffffffffffffffffffffffffffffff");
  }

  #[test]
  fn manifest_extra_encryption_pubkeys_defaults_to_empty() {
    // The field is optional in the JSON (marked #[serde(default)]).
    let json = r#"{
      "flakeDir": "/nix/store/abc",
      "masterIdentities": [],
      "generate": [],
      "hosts": {}
    }"#;
    let m: Manifest = serde_json::from_str(json).unwrap();
    assert!(m.extra_encryption_pubkeys.is_empty());
  }
}
