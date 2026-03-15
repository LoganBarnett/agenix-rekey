# Generator Settings

Generators can declare a typed option schema for their settings using the NixOS
options system.  When a generator provides a `settingsModule`, the value of
`age.secrets.<name>.settings` is validated against that schema at Nix evaluation
time — giving you type errors, default values, and rendered documentation for
free, with no extra tooling.

## Quick example

```nix
let
  # Define a reusable generator with a typed settings schema.
  echoGenerator = {
    settingsModule = { lib, ... }: {
      options.message = lib.mkOption {
        type = lib.types.str;
        description = "The plaintext string to store as the secret.";
        example = "hunter2";
      };
    };

    # The script receives `settings` as a Nix attrset populated from the
    # validated, merged option values.  Embed them directly into the shell
    # script at Nix evaluation time.
    script = { settings, lib, ... }:
      "printf '%s' ${lib.escapeShellArg settings.message}";
  };
in {
  age.secrets.myPassword = {
    generator = echoGenerator;
    settings.message = "correct horse battery staple";
    rekeyFile = ./secrets/my-password.age;
  };
}
```

If you omit a required setting or provide a value of the wrong type you get a
descriptive Nix evaluation error, not a runtime failure inside a bash script.

## How it works

### `generator.settingsModule`

A standard NixOS module (the same kind you pass to `lib.evalModules` or
`imports = [ ... ]`).  It declares the options that consumers must or may
provide via `age.secrets.<name>.settings`.

```nix
settingsModule = { lib, ... }: {
  options = {
    # Required — no default, so omitting it is an evaluation error.
    subject = lib.mkOption {
      type = lib.types.str;
      description = "CN for the certificate.";
    };

    # Optional — has a default.
    validityDays = lib.mkOption {
      type = lib.types.int;
      default = 365;
      description = "Certificate validity in days.";
    };
  };
};
```

### `age.secrets.<name>.settings`

When the generator has a `settingsModule`, `settings` is typed as a submodule
evaluated against that module.  The NixOS module system handles:

- **Type checking** — wrong types are caught at eval time.
- **Defaults** — options with `default` are filled in automatically.
- **Merging** — multiple definitions of the same setting are merged by the
  option's `type.merge` function, just like any other NixOS option.
- **Documentation** — `nix eval .#nixosConfigurations.<host>.options.age.secrets`
  (or equivalent) renders the available settings for each generator.

When no `settingsModule` is provided, `settings` falls back to
`types.nullOr types.attrs` for backward compatibility — you may still pass
free-form attrs, but they are not validated.

### The `settings` argument in scripts

Generator scripts receive `settings` as a named argument:

```nix
script = { settings, pkgs, lib, name, file, deps, decrypt, ... }:
  ''
    echo "Generating for ${name}..."
    ${pkgs.openssl}/bin/openssl req \
      -newkey rsa:4096 -nodes \
      -days ${toString settings.validityDays} \
      -subj "/CN=${lib.escapeShellArg settings.subject}" \
      ...
  '';
```

`settings` is the fully-evaluated, validated attrset.  All defaults have been
applied.  You can use any attribute directly in Nix interpolation — it is
resolved at evaluation time, not at bash runtime.

## Generators without `settingsModule`

Generators that do not declare a `settingsModule` are unchanged:

```nix
age.secrets.myPassword = {
  # Script-name shorthand, looked up in age.generators registry.
  generator.script = "alnum";
  # settings may still be set as free-form attrs and accessed via
  # secret.settings inside compound generator scripts, but there is
  # no validation.
};
```

## Dependency settings

When a generator depends on another secret, it receives that secret's `settings`
through `deps`:

```nix
script = { deps, decrypt, lib, ... }:
  lib.flip lib.concatMapStrings (lib.attrValues deps) (dep:
    ''
      # dep.settings contains the validated settings of the dependency secret.
      ${decrypt} ${lib.escapeShellArg dep.file} \
        | transform --label ${lib.escapeShellArg dep.settings.label or dep.name}
    '');
```

## Shipping reusable generators

Because a generator is just a Nix attrset, you can package it in its own file
and share it across secrets or across hosts:

```nix
# generators/tls-cert.nix
{ lib }:
{
  settingsModule = { ... }: {
    options = {
      commonName = lib.mkOption { type = lib.types.str; };
      validityDays = lib.mkOption { type = lib.types.int; default = 365; };
    };
  };

  script = { settings, pkgs, lib, file, ... }:
    ''
      ${pkgs.openssl}/bin/openssl req \
        -newkey rsa:4096 -nodes \
        -days ${toString settings.validityDays} \
        -subj "/CN=${lib.escapeShellArg settings.commonName}" \
        -keyout ${lib.escapeShellArg (lib.removeSuffix ".age" file + ".key")} \
        -out    ${lib.escapeShellArg (lib.removeSuffix ".age" file + ".crt")}
      # stdout (stdin of the encryptor) receives the private key
      cat ${lib.escapeShellArg (lib.removeSuffix ".age" file + ".key")}
    '';
}
```

```nix
# In your NixOS configuration:
let
  tlsCert = import ./generators/tls-cert.nix { inherit lib; };
in {
  age.secrets.myTlsKey = {
    generator = tlsCert;
    settings = {
      commonName = "my.example.com";
      validityDays = 730;
    };
    rekeyFile = ./secrets/my-tls-key.age;
  };
}
```

## JSON manifest

When the Nix layer serialises configuration for the Rust runtime, `settings` is
included as a plain JSON object.  The Rust program receives fully-validated,
default-filled settings and does not need to re-validate them.

```json
{
  "secrets": [
    {
      "name": "myPassword",
      "rekeyFile": "./secrets/my-password.age",
      "settings": { "message": "correct horse battery staple" },
      ...
    }
  ]
}
```
