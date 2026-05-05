/*
  Integration test runner. Each scenario is a Nix attrset describing
  one or more `nftzones`-shaped tables; the runner compiles them
  via `mkTable`, renders to libnftables-JSON, and pipes the result
  through `nft -j --check` inside a Nix sandbox.

  `nft --check` ordinarily needs a netlink socket — unavailable in
  the build sandbox. The Linux Kernel Library (`lklWithFirewall`)
  + `libredirect` shim provides a userspace netlink that lets the
  command parse + validate without a running kernel. Lifted from
  the same trick `nixpkgs`' `networking.nftables.checkRuleset`
  uses.

  We validate the JSON form rather than the text form because
  JSON is the canonical libnftables wire format and isn't subject
  to text-renderer quirks in `nftypes` (chain-header trailing-`;`,
  set-reference `@name` syntax).
*/
{
  pkgs,
  nftzones,
  nftypes,
}:
let
  /*
    Compile a scenario body into libnftables-JSON.

    `body` may be:
      - A single attrset shaped like `mkRuleset`'s body — wrapped
        as one table named `name`.
      - A list of `{ name; body; }` records — one per table, all
        composed into a single ruleset.
  */
  renderScenario =
    name: body:
    if builtins.isList body then
      nftypes.toJson (nftypes.dsl.ruleset (map (entry: nftzones.mkTable entry.name entry.body) body))
    else
      nftypes.toJson (nftzones.mkRuleset name body);

  /*
    Run `nft -j --check` on a rendered ruleset inside the sandbox.
    Returns a derivation that builds iff the parse succeeds.
  */
  mkScenarioCheck =
    name: body:
    let
      rulesetFile = builtins.toFile "${name}.json" (renderScenario name body);
    in
    pkgs.runCommand "nftzones-integration-${name}"
      {
        nativeBuildInputs = [
          pkgs.buildPackages.nftables
          pkgs.buildPackages.libredirect
          pkgs.buildPackages.lklWithFirewall
        ];
      }
      ''
        LD_PRELOAD="${pkgs.buildPackages.libredirect}/lib/libredirect.so ${pkgs.buildPackages.lklWithFirewall.lib}/lib/liblkl-hijack.so" \
          nft -j --check --file ${rulesetFile}
        touch $out
      '';
in
{
  inherit renderScenario mkScenarioCheck;
}
