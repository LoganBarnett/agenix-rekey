# Roadmap

Work items for the fork's Rust runtime transition and related improvements.

## In progress

- **Rust runtime** (`app/`): Replace all bash subcommands with a single Rust
  binary. The binary receives a JSON manifest from Nix, prompts for passphrases
  once, holds identities in memory via the `age` crate, and performs all
  encrypt/decrypt operations without re-prompting.

  Subcommands to implement: `generate`, `rekey`, `edit`, `update-masterkeys`.

## Pending

- **Remove `apps/`** once the Rust binary handles all four subcommands
  end-to-end. Until then, `apps/` stays as a working reference and fallback.
  The replacement will be a single Nix expression wrapping the compiled binary
  instead of one `.nix` file per subcommand.

- **JSON manifest schema**: Finalize and document the schema that Nix serializes
  and the Rust binary deserializes. This is the exchange boundary between the
  two layers.

- **Passphrase caching**: The primary motivation for the Rust runtime. Prompt
  once per identity, hold `Box<dyn Identity>` in memory, feed it to all
  subsequent operations. Eliminates the double-prompt bug that appears with
  compound generators under the bash runtime.
