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
mod status;

use clap::Parser;
use config::{CliRaw, Command, Config, ConfigError};
use ragenix_rekey_lib::{init_logging, manifest::Manifest};
use std::path::Path;
use thiserror::Error;

use commands::generate::{GenerateArgs, GenerateError};
use commands::rekey::{RekeyArgs, RekeyError};
use ragenix_rekey_lib::IdentitySession;

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

  #[error("Generate failed: {0}")]
  Generate(#[from] GenerateError),

  #[error("Rekey failed: {0}")]
  Rekey(#[from] RekeyError),

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
      rekey: also_rekey,
    } => {
      let manifest = load_manifest(config.manifest.as_deref())?;
      let gen_args = GenerateArgs {
        force,
        add_to_git,
        tags,
        filter,
        no_prompt: config.no_prompt,
      };

      if also_rekey {
        // Combined generate + rekey: load identities at most once, even if
        // only one side has work to do.
        let rekey_args = RekeyArgs {
          force: false,
          add_to_git,
          dummy: false,
          no_prompt: config.no_prompt,
        };

        let gen_plan = commands::generate::plan(&gen_args, &manifest)?;
        let rekey_plan = commands::rekey::plan(&rekey_args, &manifest)?;

        if gen_plan.is_empty() && rekey_plan.is_empty() {
          tracing::info!("nothing to generate or rekey (all secrets up to date)");
          return Ok(());
        }

        // Single passphrase prompt covers both operations.
        let session = IdentitySession::load(
          &manifest.master_identities,
          &manifest.extra_encryption_pubkeys,
          config.no_prompt,
        )
        .map_err(|e| ApplicationError::Generate(GenerateError::Identity(e)))?;

        if !gen_plan.is_empty() {
          if session.recipients.is_empty() {
            return Err(ApplicationError::Generate(GenerateError::NoRecipients));
          }
          commands::generate::execute(gen_plan, &gen_args, &session)?;
        }

        commands::rekey::execute(rekey_plan, &rekey_args, &session)?;
      } else {
        commands::generate::run(&gen_args, &manifest)?;
      }

      Ok(())
    }

    Command::Rekey { force, add_to_git, dummy } => {
      let manifest = load_manifest(config.manifest.as_deref())?;
      let args = RekeyArgs { force, add_to_git, dummy, no_prompt: config.no_prompt };
      commands::rekey::run(&args, &manifest)?;
      Ok(())
    }

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
