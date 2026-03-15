//! ragenix-rekey - Rust runtime for agenix-rekey
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

mod config;

use clap::Parser;
use config::{CliRaw, Command, Config, ConfigError};
use ragenix_rekey_lib::init_logging;
use thiserror::Error;

#[derive(Debug, Error)]
enum ApplicationError {
  #[error("Failed to load configuration during startup: {0}")]
  ConfigurationLoad(#[from] ConfigError),

  #[error("Operation failed: {0}")]
  Execution(String),
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
    Command::Generate { filter } => {
      let _ = filter;
      Err(ApplicationError::Execution("generate not yet implemented".into()))
    }
    Command::Rekey => {
      Err(ApplicationError::Execution("rekey not yet implemented".into()))
    }
    Command::Edit { file } => {
      let _ = file;
      Err(ApplicationError::Execution("edit not yet implemented".into()))
    }
    Command::UpdateMasterkeys => Err(ApplicationError::Execution(
      "update-masterkeys not yet implemented".into(),
    )),
  }
}
