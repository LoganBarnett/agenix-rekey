# tests/lib/agenix-stub.nix
#
# Minimal stub of the upstream agenix NixOS module.
#
# agenix-rekey's submodule `config` block assigns
#
#   config.age.secrets.<name>.file = mkIf (rekeyFile != null) (…);
#
# but `file` is an option declared by agenix itself, not by agenix-rekey.
# Without importing the real agenix module the NixOS module system throws
# "option `age.secrets.<name>.file' does not exist".
#
# Importing this stub alongside rekeyModule prevents that error.  Because
# these tests only access `config.age.secrets.<name>.settings`, the lazy
# thunks that reference real filesystem paths (in rekeyedLocalSecret) are
# never forced.
#
# Design note: both agenix and agenix-rekey declare `options.age.secrets`
# as `attrsOf (submodule …)`.  The NixOS module system merges multiple
# `attrsOf (submodule …)` declarations by concatenating their submodule
# lists – exactly how the two modules coexist in production.  This stub
# follows the same pattern.
{ lib, ... }:
{
  options.age.secrets = lib.mkOption {
    type = lib.types.attrsOf (
      lib.types.submodule (submod: {
        options = {
          # Declared by agenix; set by agenix-rekey's submodule config block.
          file = lib.mkOption {
            type = lib.types.nullOr lib.types.path;
            default = null;
            description = "Path to the decrypted secret on the target system (stub).";
          };

          # Declared by agenix; used by rekeyedLocalSecret as `secret.name`.
          name = lib.mkOption {
            type = lib.types.str;
            default = submod.config._module.args.name;
            description = "The name of this secret entry (stub).";
          };
        };
      })
    );
  };
}
