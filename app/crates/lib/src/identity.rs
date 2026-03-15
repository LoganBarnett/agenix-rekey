//! Age identity loading and cryptographic helpers.
//!
//! Provides [`IdentitySession`] which holds all master identities for
//! decryption and their corresponding public-key recipients for encryption.
//! Loading happens once per session; passphrase-protected identity files
//! prompt the user exactly once.

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use rpassword::prompt_password;
use std::io::{BufReader, Cursor, Read, Write};
use std::path::Path;
use thiserror::Error;

use crate::manifest::MasterIdentity;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum IdentityError {
  #[error("I/O error reading {path}: {source}")]
  Io {
    path: String,
    #[source]
    source: std::io::Error,
  },

  #[error("Failed to parse identity file {path}: {message}")]
  AgeParse { path: String, message: String },

  #[error("Failed to decrypt {path}: {message}")]
  AgeDecrypt { path: String, message: String },

  #[error("Failed to read passphrase from terminal: {0}")]
  PassphraseRead(#[source] std::io::Error),

  #[error(
    "passphrase required for {path} but --no-prompt was set; \
     use a plain (unencrypted) identity file or remove --no-prompt"
  )]
  PassphraseRequired { path: String },

  #[error("Invalid public key {pubkey}: {reason}")]
  InvalidPubkey { pubkey: String, reason: String },

  #[error("Age encrypt error: {0}")]
  Encrypt(String),

  #[error("Age decrypt error for {path}: {message}")]
  Decrypt { path: String, message: String },
}

// ── IdentitySession ───────────────────────────────────────────────────────────

/// Holds loaded age identities (for decryption) and recipients (for
/// encryption), assembled from the manifest's `masterIdentities` and
/// `extraEncryptionPubkeys`.
pub struct IdentitySession {
  /// Identities used to decrypt secrets.
  pub identities: Vec<Box<dyn age::Identity>>,
  /// Recipients used to encrypt newly-generated secrets.
  pub recipients: Vec<Box<dyn age::Recipient + Send>>,
}

impl IdentitySession {
  /// Load all identities and collect encryption recipients.
  ///
  /// For each master identity:
  /// - If the file has a `.age` extension it is treated as a
  ///   passphrase-encrypted identity file (decrypted once via scrypt, then
  ///   the decrypted content is parsed as a plain identity file).
  /// - Otherwise the file is parsed directly as an age identity file.
  ///
  /// Recipients are taken from the explicit `pubkey` field when present, or
  /// extracted from `# public key: age1...` comments in the identity file.
  /// `extraEncryptionPubkeys` entries are appended last.
  pub fn load(
    master_identities: &[MasterIdentity],
    extra_pubkeys: &[String],
    no_prompt: bool,
  ) -> Result<Self, IdentityError> {
    let mut identities: Vec<Box<dyn age::Identity>> = Vec::new();
    let mut recipients: Vec<Box<dyn age::Recipient + Send>> = Vec::new();

    for mi in master_identities {
      let path = &mi.identity;
      let is_passphrase_protected = path.extension().map_or(false, |e| e == "age");

      let loaded_ids = if is_passphrase_protected {
        if no_prompt {
          return Err(IdentityError::PassphraseRequired {
            path: path.to_string_lossy().into_owned(),
          });
        }
        load_passphrase_identity_file(path)?
      } else {
        load_plain_identity_file(path)?
      };

      identities.extend(loaded_ids);

      // Collect the recipient for this identity (for encryption).
      if let Some(ref pubkey) = mi.pubkey {
        let recipient = parse_recipient_string(pubkey)?;
        recipients.push(recipient);
      } else if let Some(pubkey) = extract_pubkey_comment(path)? {
        match parse_recipient_string(&pubkey) {
          Ok(r) => recipients.push(r),
          Err(e) => tracing::debug!(
            path = %path.display(),
            %pubkey,
            error = %e,
            "found public key comment but could not parse as recipient"
          ),
        }
      }
    }

    for pubkey in extra_pubkeys {
      let recipient = parse_recipient_string(pubkey)?;
      recipients.push(recipient);
    }

    Ok(IdentitySession {
      identities,
      recipients,
    })
  }
}

// ── Identity file loading ─────────────────────────────────────────────────────

/// Load a plain (non-encrypted) age identity file.
fn load_plain_identity_file(
  path: &Path,
) -> Result<Vec<Box<dyn age::Identity>>, IdentityError> {
  let filename = path.to_string_lossy().into_owned();

  age::IdentityFile::from_file(filename.clone())
    .map_err(|e| IdentityError::Io {
      path: filename.clone(),
      source: e,
    })?
    .into_identities()
    .map_err(|e| IdentityError::AgeParse {
      path: filename,
      message: e.to_string(),
    })
}

/// Load a passphrase-protected age identity file.
///
/// The file is an age-encrypted container whose plaintext is itself an age
/// identity file.  We decrypt with the user-supplied passphrase (scrypt),
/// then parse the inner bytes as a plain identity file.
fn load_passphrase_identity_file(
  path: &Path,
) -> Result<Vec<Box<dyn age::Identity>>, IdentityError> {
  let path_str = path.to_string_lossy().into_owned();

  let file = std::fs::File::open(path).map_err(|e| IdentityError::Io {
    path: path_str.clone(),
    source: e,
  })?;

  // ArmoredReader::new wraps with BufReader, which implements BufRead.
  let reader = ArmoredReader::new(file);

  let decryptor =
    age::Decryptor::new_buffered(reader).map_err(|e| IdentityError::AgeDecrypt {
      path: path_str.clone(),
      message: e.to_string(),
    })?;

  if !decryptor.is_scrypt() {
    return Err(IdentityError::AgeDecrypt {
      path: path_str.clone(),
      message: "expected passphrase-encrypted identity file (scrypt), but got recipients-based file; \
                remove the .age extension or check your masterIdentities config".to_string(),
    });
  }

  let passphrase_str = prompt_password(format!(
    "Enter passphrase for identity file {}: ",
    path.display()
  ))
  .map_err(IdentityError::PassphraseRead)?;

  let passphrase = age::secrecy::SecretString::new(Box::from(passphrase_str));
  let scrypt_identity = age::scrypt::Identity::new(passphrase);

  let mut stream = decryptor
    .decrypt(std::iter::once(&scrypt_identity as &dyn age::Identity))
    .map_err(|e| IdentityError::AgeDecrypt {
      path: path_str.clone(),
      message: e.to_string(),
    })?;

  let mut decrypted = Vec::new();
  stream.read_to_end(&mut decrypted).map_err(|e| IdentityError::Io {
    path: path_str.clone(),
    source: e,
  })?;

  // Parse the decrypted identity text.
  age::IdentityFile::from_buffer(Cursor::new(decrypted))
    .map_err(|e| IdentityError::Io {
      path: path_str.clone(),
      source: e,
    })?
    .into_identities()
    .map_err(|e| IdentityError::AgeParse {
      path: path_str,
      message: e.to_string(),
    })
}

// ── Pubkey extraction ─────────────────────────────────────────────────────────

/// Scan an identity file for a `# public key: age1...` comment line.
fn extract_pubkey_comment(path: &Path) -> Result<Option<String>, IdentityError> {
  let content =
    std::fs::read_to_string(path).map_err(|e| IdentityError::Io {
      path: path.to_string_lossy().into_owned(),
      source: e,
    })?;

  for line in content.lines() {
    let trimmed = line.trim();

    // Standard age-keygen comment.
    if let Some(rest) = trimmed.strip_prefix("# public key: ") {
      let key = rest.trim();
      if key.starts_with("age1") {
        return Ok(Some(key.to_string()));
      }
    }

    // Plugin comments (e.g. age-plugin-yubikey "# Recipient: age1yubikey1...").
    if let Some(rest) = trimmed.strip_prefix("# Recipient: ") {
      let key = rest.trim();
      if key.starts_with("age1") {
        return Ok(Some(key.to_string()));
      }
    }
  }

  Ok(None)
}

// ── Recipient parsing ─────────────────────────────────────────────────────────

/// Parse a pubkey string or recipient file path into a boxed [`age::Recipient`].
///
/// Supports:
/// - Native age X25519 public keys (`age1...`)
/// - Absolute paths to recipient files (one pubkey per non-comment line)
pub fn parse_recipient_string(
  s: &str,
) -> Result<Box<dyn age::Recipient + Send>, IdentityError> {
  if s.starts_with("age1") {
    s.parse::<age::x25519::Recipient>()
      .map(|r| Box::new(r) as Box<dyn age::Recipient + Send>)
      .map_err(|e| IdentityError::InvalidPubkey {
        pubkey: s.to_string(),
        reason: e.to_string(),
      })
  } else if s.starts_with('/') {
    parse_first_recipient_from_file(Path::new(s))
  } else {
    Err(IdentityError::InvalidPubkey {
      pubkey: s.to_string(),
      reason: "unrecognized format (expected age1... or absolute path to recipient file)"
        .to_string(),
    })
  }
}

fn parse_first_recipient_from_file(
  path: &Path,
) -> Result<Box<dyn age::Recipient + Send>, IdentityError> {
  let content =
    std::fs::read_to_string(path).map_err(|e| IdentityError::Io {
      path: path.to_string_lossy().into_owned(),
      source: e,
    })?;

  for line in content.lines() {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
      continue;
    }
    return parse_recipient_string(trimmed);
  }

  Err(IdentityError::InvalidPubkey {
    pubkey: path.to_string_lossy().into_owned(),
    reason: "recipient file contains no keys".to_string(),
  })
}

// ── Cryptographic helpers ─────────────────────────────────────────────────────

/// Decrypt an age-encrypted file using the provided identities.
pub fn decrypt_file(
  path: &Path,
  identities: &[Box<dyn age::Identity>],
) -> Result<Vec<u8>, IdentityError> {
  let path_str = path.to_string_lossy().into_owned();
  let file = std::fs::File::open(path).map_err(|e| IdentityError::Io {
    path: path_str.clone(),
    source: e,
  })?;
  decrypt_bufread(BufReader::new(file), identities, &path_str)
}

/// Decrypt age-encrypted bytes using the provided identities.
pub fn decrypt_bytes(
  ciphertext: &[u8],
  identities: &[Box<dyn age::Identity>],
) -> Result<Vec<u8>, IdentityError> {
  decrypt_bufread(ciphertext, identities, "<in-memory>")
}

fn decrypt_bufread<R: Read>(
  reader: R,
  identities: &[Box<dyn age::Identity>],
  path_hint: &str,
) -> Result<Vec<u8>, IdentityError> {
  // ArmoredReader::new wraps R in BufReader, producing ArmoredReader<BufReader<R>>,
  // which implements BufRead, enabling new_buffered.
  let armored = ArmoredReader::new(reader);

  let decryptor =
    age::Decryptor::new_buffered(armored).map_err(|e| IdentityError::Decrypt {
      path: path_hint.to_string(),
      message: e.to_string(),
    })?;

  let refs: Vec<&dyn age::Identity> = identities.iter().map(|i| i.as_ref()).collect();

  let mut stream = decryptor
    .decrypt(refs.into_iter())
    .map_err(|e| IdentityError::Decrypt {
      path: path_hint.to_string(),
      message: e.to_string(),
    })?;

  let mut output = Vec::new();
  stream.read_to_end(&mut output).map_err(|e| IdentityError::Decrypt {
    path: path_hint.to_string(),
    message: e.to_string(),
  })?;

  Ok(output)
}

/// Encrypt plaintext to all recipients, returning ASCII-armored age output.
pub fn encrypt_to_recipients(
  plaintext: &[u8],
  recipients: &[Box<dyn age::Recipient + Send>],
) -> Result<Vec<u8>, IdentityError> {
  // Cast Box<dyn Recipient + Send> → &dyn Recipient (coercion needed by with_recipients).
  let refs: Vec<&dyn age::Recipient> =
    recipients.iter().map(|r| r.as_ref() as &dyn age::Recipient).collect();

  let encryptor = age::Encryptor::with_recipients(refs.into_iter())
    .map_err(|e| IdentityError::Encrypt(e.to_string()))?;

  let mut output = Vec::new();
  let armor = ArmoredWriter::wrap_output(&mut output, Format::AsciiArmor)
    .map_err(|e| IdentityError::Encrypt(e.to_string()))?;

  let mut writer =
    encryptor.wrap_output(armor).map_err(|e| IdentityError::Encrypt(e.to_string()))?;

  writer.write_all(plaintext).map_err(|e| IdentityError::Encrypt(e.to_string()))?;

  let armor = writer.finish().map_err(|e| IdentityError::Encrypt(e.to_string()))?;
  armor.finish().map_err(|e| IdentityError::Encrypt(e.to_string()))?;

  Ok(output)
}
