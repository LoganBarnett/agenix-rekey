//! ragenix-rekey — Rust runtime for agenix-rekey
//!
//! Replaces the Nix-generated bash scripts with a single binary that:
//! - Prompts for master identity passphrases once per session
//! - Holds decrypted identities in memory for all subsequent operations
//! - Accepts a JSON manifest from the Nix layer describing all hosts,
//!   secrets, generators, and master identities
//!
//! # LLM Development Guidelines
//! When modifying this code:
//! - Keep configuration logic in config.rs
//! - Keep business logic out of main.rs - use separate modules
//! - Maintain the staged configuration pattern (CliRaw -> Config)
//! - Use semantic error types with thiserror - NO anyhow blindly wrapping
//! - Add context at each error site explaining WHAT failed and WHY
//! - Never log sensitive data (passphrases, plaintext secrets)

mod commands;
mod config;

use clap::Parser;
use config::{CliRaw, Command, Config, ConfigError};
use ragenix_rekey_lib::{init_logging, manifest::Manifest, IdentitySession};
use std::path::Path;
use thiserror::Error;

use commands::generate::{GenerateArgs, GenerateError};

#[derive(Debug, Error)]
enum ApplicationError {
  #[error("Failed to load configuration: {0}")]
  ConfigurationLoad(#[from] ConfigError),

  #[error("--manifest / RAGENIX_REKEY_MANIFEST is required for this subcommand")]
  ManifestRequired,

  #[error("Failed to read manifest {path}: {source}")]
  ManifestRead {
    path: String,
    #[source]
    source: std::io::Error,
  },

  #[error("Failed to parse manifest {path}: {source}")]
  ManifestParse {
    path: String,
    #[source]
    source: serde_json::Error,
  },

  #[error("Failed to load identities: {0}")]
  Identity(#[from] ragenix_rekey_lib::IdentityError),

  #[error("Generate failed: {0}")]
  Generate(#[from] GenerateError),

  #[error("Operation not yet implemented: {0}")]
  NotImplemented(String),
}

fn main() -> Result<(), ApplicationError> {
  let cli = CliRaw::parse();

  let config = Config::from_cli(cli).map_err(|e| {
    eprintln!("Configuration error: {}", e);
    ApplicationError::ConfigurationLoad(e)
  })?;

  init_logging(config.log_level, config.log_format);

  run(config)
}

fn run(config: Config) -> Result<(), ApplicationError> {
  match config.command {
    Command::Generate {
      filter,
      force,
      add_to_git,
      tags,
    } => {
      let manifest = load_manifest(config.manifest.as_deref())?;
      let session =
        IdentitySession::load(&manifest.master_identities, &manifest.extra_encryption_pubkeys)?;

      let args = GenerateArgs {
        force,
        add_to_git,
        tags,
        filter,
      };

      commands::generate::run(&args, &manifest, &session)?;
      Ok(())
    }

    Command::Rekey => Err(ApplicationError::NotImplemented("rekey".into())),

    Command::Edit { file } => {
      let _ = file;
      Err(ApplicationError::NotImplemented("edit".into()))
    }

    Command::UpdateMasterkeys => Err(ApplicationError::NotImplemented("update-masterkeys".into())),
  }
}

/// Read and deserialise the JSON manifest from the provided path.
fn load_manifest(path: Option<&Path>) -> Result<Manifest, ApplicationError> {
  let path = path.ok_or(ApplicationError::ManifestRequired)?;

  let content = std::fs::read_to_string(path).map_err(|e| ApplicationError::ManifestRead {
    path: path.display().to_string(),
    source: e,
  })?;

  serde_json::from_str(&content).map_err(|e| ApplicationError::ManifestParse {
    path: path.display().to_string(),
    source: e,
  })
}
