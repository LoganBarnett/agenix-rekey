//! Age identity loading and cryptographic helpers.
//!
//! Provides [`IdentitySession`] which holds all master identities for
//! decryption and their corresponding public-key recipients for encryption.
//! Loading happens once per session; passphrase-protected identity files
//! prompt the user exactly once.

use age::armor::{ArmoredReader, ArmoredWriter, Format};
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

      let (loaded_ids, implicit_pubkey) = if is_passphrase_protected {
        if no_prompt {
          return Err(IdentityError::PassphraseRequired {
            path: path.to_string_lossy().into_owned(),
          });
        }
        load_passphrase_identity_file(path)?
      } else {
        (load_plain_identity_file(path)?, None)
      };

      identities.extend(loaded_ids);

      // Collect the recipient for this identity (for encryption).
      // Priority: explicit pubkey > pubkey extracted from identity content.
      if let Some(ref pubkey) = mi.pubkey {
        let recipient = parse_recipient_string(pubkey)?;
        recipients.push(recipient);
      } else {
        // For passphrase-protected files: `implicit_pubkey` comes from scanning
        // the decrypted inner content.  For plain files: scan the file itself.
        // Never call extract_pubkey_comment on a binary .age file.
        let found = if is_passphrase_protected {
          implicit_pubkey
        } else {
          extract_pubkey_comment(path)?
        };
        if let Some(pubkey) = found {
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

// ── Passphrase reading ────────────────────────────────────────────────────────

/// Read a passphrase with terminal echo suppressed.
///
/// Tries the following sources in order:
/// 1. `/dev/tty` — works when the process has a controlling terminal.
/// 2. The actual terminal device via `ttyname(2)` on file descriptors 2
///    (stderr) and 1 (stdout) — works when `/dev/tty` returns ENXIO but
///    one of those fds is still a real terminal device (e.g. `/dev/ttys004`).
///    Opening the device path directly with O_RDWR bypasses the
///    controlling-terminal requirement while still supporting `tcsetattr`.
/// 3. `$SSH_ASKPASS` — if set, runs the named program with the prompt string
///    as its sole argument and reads the passphrase from its stdout.  This is
///    the canonical solution for tools launched by `nix run` or other
///    launchers that pipe stdout/stderr rather than connecting them to the
///    terminal (making all the tty approaches above fail).
/// 4. `stdin` — last resort.
fn read_passphrase(prompt: impl AsRef<str>) -> Result<String, std::io::Error> {
  use std::io::ErrorKind;
  match rpassword::prompt_password(prompt.as_ref()) {
    Ok(p) => return Ok(p),
    // ENXIO (errno 6): open of /dev/tty failed — no controlling terminal.
    // UnexpectedEof: /dev/tty opened but read returned EOF (e.g. nix run,
    //   CI environments, or sub-processes where stdin/tty is disconnected).
    // Both indicate no interactive terminal is available; try alternatives.
    Err(e)
      if e.raw_os_error() == Some(6)
        || e.kind() == ErrorKind::UnexpectedEof =>
    {
      // fall through to alternatives below
    }
    Err(e) => return Err(e),
  }

  // Try to find and open the real terminal device via ttyname(2).
  #[cfg(unix)]
  if let Some(tty_path) =
    terminal_path_from_fd(2).or_else(|| terminal_path_from_fd(1))
  {
    if let Ok(tty) = std::fs::OpenOptions::new().read(true).write(true).open(&tty_path) {
      use std::io::Write;
      if let Ok(mut w) = tty.try_clone() {
        let _ = write!(w, "{}", prompt.as_ref());
      }
      return rpassword::read_password_from_bufread(&mut std::io::BufReader::new(tty));
    }
  }

  // SSH_ASKPASS: standard mechanism for terminal-less passphrase entry.
  // Commonly set by graphical session managers or by the user for tools like
  // nix run that pipe stdout/stderr and leave no usable tty fd.
  if let Ok(askpass) = std::env::var("SSH_ASKPASS") {
    if !askpass.is_empty() {
      eprintln!(
        "[ragenix-rekey] no terminal available; using SSH_ASKPASS ({})",
        askpass
      );
      let out = std::process::Command::new(&askpass)
        .arg(prompt.as_ref())
        .stdin(std::process::Stdio::null())
        .output()?;
      let pass = String::from_utf8_lossy(&out.stdout);
      return Ok(pass.trim_end_matches('\n').to_string());
    }
  }

  // Final fallback: print prompt to stderr and read from stdin.
  // Useful when the caller pipes a passphrase for automation.
  eprint!("{}", prompt.as_ref());
  rpassword::read_password_from_bufread(&mut std::io::stdin().lock())
}

/// Return the path of the terminal device that file descriptor `fd` is
/// connected to, or `None` if it is not a terminal.
///
/// Uses `libc::ttyname` which is POSIX but not thread-safe; we call it only
/// from a single-threaded context during identity loading.
#[cfg(unix)]
fn terminal_path_from_fd(fd: i32) -> Option<String> {
  use std::ffi::CStr;
  // Safety: ttyname(3) returns a pointer to a static string valid until the
  // next call.  We copy it immediately into an owned String.
  let ptr = unsafe { libc::ttyname(fd) };
  if ptr.is_null() {
    return None;
  }
  unsafe { CStr::from_ptr(ptr) }.to_str().ok().map(|s| s.to_string())
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
///
/// Returns `(identities, pubkey)`.  `pubkey` is `Some` when the decrypted
/// identity text contains a `# public key: age1...` comment; `None` otherwise.
/// The caller uses this to register a recipient without requiring an explicit
/// `pubkey` field in the manifest.
fn load_passphrase_identity_file(
  path: &Path,
) -> Result<(Vec<Box<dyn age::Identity>>, Option<String>), IdentityError> {
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

  let passphrase_str = read_passphrase(format!(
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

  // Scan the decrypted text for a pubkey comment before consuming the bytes.
  // The decrypted content is UTF-8 identity text; lossy conversion is safe here
  // since we're just scanning comment lines.
  let implicit_pubkey = std::str::from_utf8(&decrypted)
    .ok()
    .and_then(scan_pubkey_lines);

  // Parse the decrypted identity text.
  let identities = age::IdentityFile::from_buffer(Cursor::new(decrypted))
    .map_err(|e| IdentityError::Io {
      path: path_str.clone(),
      source: e,
    })?
    .into_identities()
    .map_err(|e| IdentityError::AgeParse {
      path: path_str,
      message: e.to_string(),
    })?;

  Ok((identities, implicit_pubkey))
}

// ── Pubkey extraction ─────────────────────────────────────────────────────────

/// Scan identity file text for a `# public key: age1...` or `# Recipient: age1...` comment.
fn scan_pubkey_lines(content: &str) -> Option<String> {
  for line in content.lines() {
    let trimmed = line.trim();

    // Standard age-keygen comment.
    if let Some(rest) = trimmed.strip_prefix("# public key: ") {
      let key = rest.trim();
      if key.starts_with("age1") {
        return Some(key.to_string());
      }
    }

    // Plugin comments (e.g. age-plugin-yubikey "# Recipient: age1yubikey1...").
    if let Some(rest) = trimmed.strip_prefix("# Recipient: ") {
      let key = rest.trim();
      if key.starts_with("age1") {
        return Some(key.to_string());
      }
    }
  }

  None
}

/// Scan an identity file for a `# public key: age1...` comment line.
fn extract_pubkey_comment(path: &Path) -> Result<Option<String>, IdentityError> {
  let content =
    std::fs::read_to_string(path).map_err(|e| IdentityError::Io {
      path: path.to_string_lossy().into_owned(),
      source: e,
    })?;
  Ok(scan_pubkey_lines(&content))
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
  } else if s.starts_with("ssh-ed25519 ") || s.starts_with("ssh-rsa ") {
    // SSH public keys are valid age recipients (age native SSH support).
    // ParseRecipientKeyError doesn't implement Display; use Debug.
    s.parse::<age::ssh::Recipient>()
      .map(|r| Box::new(r) as Box<dyn age::Recipient + Send>)
      .map_err(|e| IdentityError::InvalidPubkey {
        pubkey: s.to_string(),
        reason: format!("{:?}", e),
      })
  } else if s.starts_with('/') {
    parse_first_recipient_from_file(Path::new(s))
  } else {
    Err(IdentityError::InvalidPubkey {
      pubkey: s.to_string(),
      reason: "unrecognized format (expected age1..., ssh-ed25519/ssh-rsa key, \
               or absolute path to recipient file)"
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
