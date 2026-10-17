/*
  Check a libnftables JSON ruleset with `nft -j --check` inside the
  build sandbox.

  `nft --check` needs a netlink socket, which the sandbox lacks. The
  Linux Kernel Library (`lklWithFirewall`) and the `libredirect` shim
  provide a userspace netlink, the same trick nixpkgs'
  `networking.nftables.checkRuleset` uses. The JSON form is the
  canonical libnftables wire format and avoids quirks of the text
  renderer.

  Takes the package set `pkgs`, then a derivation `name` and the
  ruleset JSON. Returns a derivation that builds when `nft` accepts
  the ruleset.
*/
{ pkgs }:
name: rulesetJson:
let
  inherit (pkgs.buildPackages) libredirect lklWithFirewall nftables;
  rulesetPath = builtins.toFile "${name}.json" rulesetJson;
  preloadLibraries = "${libredirect}/lib/libredirect.so ${lklWithFirewall.lib}/lib/liblkl-hijack.so";
in
pkgs.runCommand name
  {
    nativeBuildInputs = [
      libredirect
      lklWithFirewall
      nftables
    ];
  }
  ''
    LD_PRELOAD="${preloadLibraries}" \
      nft -j --check --file ${rulesetPath}
    touch "$out"
  ''
