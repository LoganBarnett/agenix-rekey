use clap::{Parser, Subcommand};
use ragenix_rekey_lib::{LogFormat, LogLevel};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
  #[error("Configuration validation failed: {0}")]
  Validation(String),
}

/// Subcommands mirroring the agenix-rekey operations.
#[derive(Debug, Subcommand)]
pub enum Command {
  /// Generate secrets using their configured generators.
  Generate {
    /// Limit generation to secrets at these paths (relative to flake root).
    /// If omitted along with --tags, all secrets with generators are processed.
    #[arg(value_name = "PATH")]
    filter: Vec<String>,

    /// Force re-generation even when the output file already exists and all
    /// dependencies are unchanged.
    #[arg(short, long)]
    force: bool,

    /// Stage generated (and removed orphan) files with `git add`.
    #[arg(short = 'a', long = "add-to-git")]
    add_to_git: bool,

    /// Also select secrets whose tags overlap this comma-separated list.
    /// May be specified multiple times.
    #[arg(short, long, value_name = "TAGS")]
    tags: Vec<String>,
  },

  /// Re-encrypt master-encrypted secrets for each host's public key.
  Rekey,

  /// Decrypt a secret, open it in $EDITOR, and re-encrypt on save.
  Edit {
    /// Path to the secret file to edit. Uses fzf to select if omitted.
    file: Option<PathBuf>,
  },

  /// Re-encrypt all secrets under a new set of master keys.
  UpdateMasterkeys,
}

#[derive(Debug, Parser)]
#[command(
  author,
  version,
  about = "Rust runtime for agenix-rekey secret management",
  long_about = None,
)]
pub struct CliRaw {
  /// Log level (trace, debug, info, warn, error).
  #[arg(long, env = "LOG_LEVEL", global = true)]
  pub log_level: Option<String>,

  /// Log format (text, json).
  #[arg(long, env = "LOG_FORMAT", global = true)]
  pub log_format: Option<String>,

  /// Path to the JSON manifest produced by the Nix layer.
  /// The manifest contains all host configurations, secret definitions,
  /// master identities, and generator metadata.
  #[arg(long, env = "RAGENIX_REKEY_MANIFEST", global = true)]
  pub manifest: Option<PathBuf>,

  #[command(subcommand)]
  pub command: Command,
}

#[derive(Debug)]
pub struct Config {
  pub log_level: LogLevel,
  pub log_format: LogFormat,
  pub manifest: Option<PathBuf>,
  pub command: Command,
}

impl Config {
  pub fn from_cli(cli: CliRaw) -> Result<Self, ConfigError> {
    let log_level = cli
      .log_level
      .unwrap_or_else(|| "info".to_string())
      .parse::<LogLevel>()
      .map_err(|e| ConfigError::Validation(e.to_string()))?;

    let log_format = cli
      .log_format
      .unwrap_or_else(|| "text".to_string())
      .parse::<LogFormat>()
      .map_err(|e| ConfigError::Validation(e.to_string()))?;

    Ok(Config {
      log_level,
      log_format,
      manifest: cli.manifest,
      command: cli.command,
    })
  }
}
