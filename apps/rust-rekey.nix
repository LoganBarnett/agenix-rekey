# Rust-based replacement for apps/rekey.nix.
#
# Builds the JSON manifest (apps/manifest.nix) at Nix eval time and wraps the
# ragenix-rekey binary in a shell script that passes the manifest path at
# runtime.  All flags ($@) are forwarded to `ragenix-rekey rekey`, so
# --force / --add-to-git / --dummy all work as expected.
{
  pkgs,
  ragenixBinary,
  ...
}@inputs:
let
  manifest = import ./manifest.nix inputs;
in
pkgs.writeShellScriptBin "agenix-rekey" ''
  exec ${ragenixBinary}/bin/ragenix-rekey \
    --manifest ${manifest} \
    rekey \
    "$@"
''
