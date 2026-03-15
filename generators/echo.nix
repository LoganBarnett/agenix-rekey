# generators/echo.nix
#
# A minimal generator that stores an arbitrary string as a secret.
# Useful for bootstrapping, testing, and as a reference implementation of the
# settingsModule pattern.
#
# Usage:
#
#   let echoGenerator = import ./generators/echo.nix { inherit lib; };
#   in {
#     age.secrets.myPassword = {
#       generator = echoGenerator;
#       settings.message = "correct horse battery staple";
#       rekeyFile = ./secrets/my-password.age;
#     };
#   }
#
# The `message` is embedded into the generated shell script at Nix evaluation
# time, so the secret value is visible in your Nix configuration.  This
# generator is intentionally simple; for real secrets use a generator that
# produces random output.
_: {
  settingsModule =
    { lib, ... }:
    {
      options.message = lib.mkOption {
        type = lib.types.str;
        description = ''
          The plaintext string to store as the secret content.

          The value is embedded in the generated shell script at Nix evaluation
          time.  Do not use this for secrets that must not appear in the Nix
          store or in your configuration repository.
        '';
        example = "hunter2";
      };
    };

  # printf rather than echo to avoid a trailing newline, which many consumers
  # do not expect and which would change the encrypted output on each rekey.
  script = { settings, lib, ... }: "printf '%s' ${lib.escapeShellArg settings.message}";
}
