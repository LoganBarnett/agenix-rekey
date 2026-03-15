use std::{path::PathBuf, process::Command};

fn binary_path() -> PathBuf {
  let mut path =
    std::env::current_exe().expect("Failed to get current executable path");
  path.pop(); // remove test executable name
  path.pop(); // remove deps dir
  path.push("ragenix-rekey");

  if !path.exists() {
    path.pop();
    path.pop();
    path.push("debug");
    path.push("ragenix-rekey");
  }

  path
}

#[test]
fn help_flag_succeeds() {
  let output = Command::new(binary_path())
    .arg("--help")
    .output()
    .expect("Failed to execute ragenix-rekey --help");

  assert!(
    output.status.success(),
    "Expected success exit code, got: {:?}",
    output.status.code()
  );
  let stdout = String::from_utf8_lossy(&output.stdout);
  assert!(
    stdout.contains("Usage:"),
    "Expected help text to contain 'Usage:', got: {}",
    stdout
  );
}

#[test]
fn version_flag_succeeds() {
  let output = Command::new(binary_path())
    .arg("--version")
    .output()
    .expect("Failed to execute ragenix-rekey --version");

  assert!(
    output.status.success(),
    "Expected success exit code, got: {:?}",
    output.status.code()
  );
  let stdout = String::from_utf8_lossy(&output.stdout);
  assert!(
    stdout.contains("ragenix-rekey"),
    "Expected version text to contain 'ragenix-rekey', got: {}",
    stdout
  );
}
