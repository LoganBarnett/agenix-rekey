# Produces a JSON manifest consumed by the `ragenix-rekey` Rust binary.
#
# The manifest is the contract between the Nix eval layer and the Rust runtime:
# - Nix evaluates all configuration, resolves paths, and serialises to JSON.
# - Rust reads the JSON, loads age identities (prompting for passphrases once),
#   and executes generator scripts / performs rekeying.
#
# Key difference vs apps/generate.nix: generator scripts receive
# `decrypt = "__RAGENIX_DECRYPT__"` instead of the real ageWrapper path.
# The Rust runtime substitutes the placeholder at runtime with a per-invocation
# wrapper script that maps dependency paths to pre-decrypted temp files.
{
  pkgs,
  nodes,
  ...
}@inputs:
let
  inherit (pkgs.lib)
    any
    assertMsg
    attrNames
    attrValues
    concatStringsSep
    filter
    filterAttrs
    flip
    foldl'
    hasAttr
    hasPrefix
    head
    length
    mapAttrs
    mapAttrsToList
    removePrefix
    removeSuffix
    stringsWithDeps
    warnIf
    ;

  inherit (import ../nix/lib.nix inputs)
    userFlakeDir
    mergedMasterIdentities
    mergedExtraEncryptionPubkeys
    ;

  relativeToFlake =
    filePath:
    let
      fileStr = builtins.unsafeDiscardStringContext (toString filePath);
    in
    assert assertMsg (hasPrefix userFlakeDir fileStr)
      "Cannot generate ${fileStr} as it isn't a direct subpath of the flake directory ${userFlakeDir}.";
    "." + removePrefix userFlakeDir fileStr;

  mapListOrAttrs = f: x: if builtins.isList x then map f x else mapAttrs (_: f) x;
  mapListOrAttrValues =
    f: x: if builtins.isList x then map f x else mapAttrsToList (_: f) x;
  filterListOrAttrValues =
    f: x: if builtins.isList x then filter f x else filterAttrs (_: f) x;

  findHost =
    secret:
    let
      matchingHosts = filter (
        host:
        any (s: s.id == secret.id && s.rekeyFile == secret.rekeyFile) (
          attrValues nodes.${host}.config.age.secrets
        )
      ) (attrNames nodes);
    in
    warnIf (length matchingHosts > 1)
      "Multiple hosts provide a secret with rekeyFile=${toString secret.rekeyFile}, which may have undesired side effects in secret generator dependencies."
      (head matchingHosts);

  # ── Collect secrets with generators ─────────────────────────────────────────

  addGeneratedSecretChecked =
    host: set: secretName:
    let
      secret = nodes.${host}.config.age.secrets.${secretName};
      sourceFile =
        assert assertMsg (
          secret.rekeyFile != null
        ) "Host ${host}: age.secrets.${secretName}: `rekeyFile` must be set when using a generator.";
        relativeToFlake secret.rekeyFile;

      # Generate the script string with __RAGENIX_DECRYPT__ as the placeholder.
      script = secret.generator._script {
        inherit secret pkgs;
        inherit (pkgs) lib;
        file = sourceFile;
        name = secretName;
        decrypt = "__RAGENIX_DECRYPT__";
        settings = if secret.settings != null then secret.settings else { };
        deps = flip mapListOrAttrs secret.generator.dependencies (dep: {
          host = findHost dep;
          name = dep.id;
          file = relativeToFlake dep.rekeyFile;
          settings = if dep.settings != null then dep.settings else { };
        });
      };
    in
    if secret.generator == null then
      set
    else
      assert assertMsg (hasAttr sourceFile set -> script == set.${sourceFile}.script)
        "Generator definition of ${secretName} on ${host} differs from definitions on other hosts: ${
          concatStringsSep "," set.${sourceFile}.defs
        }";
      set
      // {
        ${sourceFile} = {
          inherit
            secret
            sourceFile
            secretName
            script
            ;
          defs = (set.${sourceFile}.defs or [ ]) ++ [ "${host}:${secretName}" ];
        };
      };

  secretsWithContext = foldl' (
    set: host:
    foldl' (addGeneratedSecretChecked host) set (attrNames nodes.${host}.config.age.secrets)
  ) { } (attrNames nodes);

  # ── Topological ordering of generate entries ─────────────────────────────────
  #
  # Reuse stringsWithDeps: each "string" is the sourceFile path itself.
  # textClosureMap concatenates them with newlines in topological order.
  # Splitting gives the ordered path list.

  orderedPaths =
    let
      stages = flip mapAttrs secretsWithContext (
        sourceFile: contextSecret:
        stringsWithDeps.fullDepEntry sourceFile (
          filter (p: hasAttr p secretsWithContext) (
            mapListOrAttrValues (x: relativeToFlake x.rekeyFile) (
              filterListOrAttrValues (
                dep: dep.generator != null
              ) contextSecret.secret.generator.dependencies
            )
          )
        )
      );
      ordered = stringsWithDeps.textClosureMap (x: x) stages (attrNames stages);
    in
    filter (p: p != "") (pkgs.lib.splitString "\n" ordered);

  makeManifestEntry =
    sourceFile: contextSecret:
    let
      secret = contextSecret.secret;
    in
    {
      path = sourceFile;
      defs = contextSecret.defs;
      script = contextSecret.script;
      tags = secret.generator.tags;
      settings = secret.settings;
      dependencies = mapListOrAttrValues (dep: {
        name = dep.id;
        host = findHost dep;
        path = relativeToFlake dep.rekeyFile;
      }) secret.generator.dependencies;
    };

  orderedEntries = map (
    sourceFile: makeManifestEntry sourceFile secretsWithContext.${sourceFile}
  ) orderedPaths;

  # ── Per-host config (used by rekey / update-masterkeys) ──────────────────────

  makeHostConfig =
    hostname: node:
    let
      hostSecrets = filterAttrs (_: s: s.rekeyFile != null) node.config.age.secrets;
    in
    {
      pubkey = removeSuffix "\n" node.config.age.rekey.hostPubkey;
      storageMode = node.config.age.rekey.storageMode;
      localStorageDir =
        if node.config.age.rekey.localStorageDir != null then
          builtins.unsafeDiscardStringContext (toString node.config.age.rekey.localStorageDir)
        else
          null;
      secrets = mapAttrs (secretName: secret: {
        rekeyFile = relativeToFlake secret.rekeyFile;
        intermediary = secret.intermediary or false;
      }) hostSecrets;
    };

  # ── Assemble final manifest ───────────────────────────────────────────────────

  manifest = {
    flakeDir = userFlakeDir;

    masterIdentities = map (mi: {
      identity = builtins.unsafeDiscardStringContext (toString mi.identity);
      pubkey = mi.pubkey;
    }) mergedMasterIdentities;

    extraEncryptionPubkeys = mergedExtraEncryptionPubkeys;

    generate = orderedEntries;

    hosts = mapAttrs makeHostConfig nodes;
  };

in
pkgs.writeText "ragenix-manifest.json" (builtins.toJSON manifest)
