# Evaluation-time tests for the generator settingsModule feature.
#
# These tests run at Nix evaluation time, not inside a VM.  Each test is a Nix
# assertion: if it fails the expression throws and the derivation cannot be
# created, causing `nix flake check` to fail with a descriptive message.
#
# Usage (from flake.nix perSystem.checks):
#   checks.settings-module-tests =
#     import ./tests/settings-module.nix { inherit pkgs lib; nixpkgs = inputs.nixpkgs; };
{ pkgs, lib, nixpkgs }:
let
  rekeyModule = import ../modules/agenix-rekey.nix nixpkgs;

  # Minimal config that satisfies mandatory module assertions without requiring
  # any real files on disk.  The identity path only needs to be absolute
  # (existence is not checked at eval time).
  #
  # `rekey.secrets = {}` is required to satisfy the backward-compat shim that
  # reads `config.rekey.secrets` even when unused (to emit a migration warning).
  baseConfig = {
    age.rekey.masterIdentities = [ { identity = "/dev/null"; } ];
    age.rekey.storageMode = "local";
    age.rekey.localStorageDir = /tmp;
    age.rekey.generatedSecretsDir = /tmp;
    rekey.secrets = { };
  };

  # Evaluate the module with additional config and return config.age.secrets.
  # We use nixosSystem rather than bare lib.evalModules so the full NixOS base
  # module set (assertions, warnings, etc.) is present — the same environment
  # the module targets in production.
  evalSecrets =
    extraConfig:
    (nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        rekeyModule
        # Stub that declares agenix-owned options (e.g. age.secrets.<n>.file)
        # so the module system accepts agenix-rekey's config block without
        # importing all of agenix.  See tests/lib/agenix-stub.nix for details.
        ./lib/agenix-stub.nix
        baseConfig
        extraConfig
      ];
    }).config.age.secrets;

  # ── helpers ──────────────────────────────────────────────────────────────────

  # Returns "PASS: <msg>" on success, throws on failure.
  passIf = cond: msg: if cond then "PASS: ${msg}" else throw "FAIL: ${msg}";

  # ── tests ────────────────────────────────────────────────────────────────────

  # 1. Settings declared via settingsModule are accessible after evaluation.
  testSettingsAccessible =
    let
      secrets = evalSecrets {
        age.secrets.echoSecret = {
          generator.script = { settings, lib, ... }: "printf '%s' ${lib.escapeShellArg settings.message}";
          generator.settingsModule =
            { lib, ... }:
            {
              options.message = lib.mkOption { type = lib.types.str; };
            };
          settings.message = "hello world";
        };
      };
    in
    passIf (secrets.echoSecret.settings.message == "hello world") "settings are accessible after validation";

  # 2. Default values declared in settingsModule are applied when omitted.
  testDefaultValuesApplied =
    let
      secrets = evalSecrets {
        age.secrets.defaultSecret = {
          generator.script = {
            settings,
            lib,
            ...
          }: "echo ${toString settings.count}";
          generator.settingsModule =
            { lib, ... }:
            {
              options.count = lib.mkOption {
                type = lib.types.int;
                default = 42;
              };
            };
          # settings.count deliberately omitted — default should be 42.
        };
      };
    in
    passIf (secrets.defaultSecret.settings.count == 42) "default values from settingsModule are applied";

  # 3. Backward compatibility: a generator without settingsModule still accepts
  #    free-form attrs in settings (the current behaviour from PR #75).
  testBackwardCompatFreeformAttrs =
    let
      secrets = evalSecrets {
        age.secrets.legacySecret = {
          generator.script = { ... }: ''echo "hello"'';
          settings = {
            whatever = "value";
            someInt = 99;
          };
        };
      };
    in
    passIf (secrets.legacySecret.settings.whatever == "value")
      "generator without settingsModule accepts free-form attrs";

  # 4. When there is no settingsModule and settings is unset, it defaults to null.
  testDefaultNullWithoutSettingsModule =
    let
      secrets = evalSecrets {
        age.secrets.noSettingsSecret = {
          generator.script = { ... }: ''echo "hello"'';
          # settings deliberately not set.
        };
      };
    in
    passIf (secrets.noSettingsSecret.settings == null)
      "settings defaults to null when no settingsModule is declared";

  # 5. Multiple settings fields work together, including mixed required/optional.
  testMultipleSettingsFields =
    let
      secrets = evalSecrets {
        age.secrets.multiSecret = {
          generator.script =
            { settings, lib, ... }:
            "echo ${lib.escapeShellArg settings.subject} ${toString settings.count}";
          generator.settingsModule =
            { lib, ... }:
            {
              options = {
                subject = lib.mkOption { type = lib.types.str; };
                count = lib.mkOption {
                  type = lib.types.int;
                  default = 1;
                };
              };
            };
          settings = {
            subject = "world";
            count = 3;
          };
        };
      };
    in
    passIf
      (secrets.multiSecret.settings.subject == "world" && secrets.multiSecret.settings.count == 3)
      "multiple settings fields are accessible and defaults are overridable";

  # 6. The echo generator (generators/echo.nix) works end-to-end.
  testEchoGenerator =
    let
      echoGenerator = import ../generators/echo.nix { inherit lib; };
      secrets = evalSecrets {
        age.secrets.echoSecret2 = {
          generator = echoGenerator;
          settings.message = "hunter2";
        };
      };
    in
    passIf (secrets.echoSecret2.settings.message == "hunter2")
      "echo generator accepts and exposes settings.message";

  # ── run all tests ────────────────────────────────────────────────────────────

  allResults = [
    testSettingsAccessible
    testDefaultValuesApplied
    testBackwardCompatFreeformAttrs
    testDefaultNullWithoutSettingsModule
    testMultipleSettingsFields
    testEchoGenerator
  ];
in
# Build a derivation whose shell script is constructed by Nix string
# interpolation over allResults.  If any test throws, the interpolation fails
# at evaluation time and the derivation is never created.
pkgs.runCommand "settings-module-tests" { } (
  lib.concatMapStrings (r: "echo ${lib.escapeShellArg r}\n") allResults + "touch $out\n"
)
