# Check that the flake's public outputs expose the same code that
# `testContext` imports from source, so the source imports the other
# suites test are the code consumers receive.
{
  fixtures,
  helpers,
  lib,
  nftypes,
  nftzones,
  self,
  ...
}:
let
  inherit (fixtures.scenarios.filter-basic) body;

  # A minimal valid NixOS system with the nftzones `body` as table `fw`.
  firewallConfiguration = {
    boot.loader.grub.enable = false;
    fileSystems."/" = {
      device = "none";
      fsType = "tmpfs";
    };
    system.stateVersion = lib.trivial.release;
    networking = {
      hostName = "test";
      firewall.enable = false;
      nftables.enable = true;
      nftzones = {
        enable = true;
        tables.fw = body;
      };
    };
  };

  renderedTable = config: config.networking.nftables.tables.fw.content;
in
{
  testLibExportsSourceNames = {
    expr = builtins.attrNames self.lib;
    expected = builtins.attrNames nftzones;
  };

  testLibVersionMatchesSource = {
    expr = self.lib.version;
    expected = nftzones.version;
  };

  testLibTypesMatchSource = {
    expr = builtins.attrNames self.lib.types;
    expected = builtins.attrNames nftzones.types;
  };

  testLibCompilesLikeSource = {
    expr = nftypes.toJson (self.lib.mkRuleset "fw" body);
    expected = nftypes.toJson (nftzones.mkRuleset "fw" body);
  };

  testNixosModuleRendersLikeSource = {
    expr = renderedTable (
      helpers.evalNixosSystem [
        self.nixosModules.default
        firewallConfiguration
      ]
    );
    expected = renderedTable (helpers.evalNixosModule firewallConfiguration);
  };
}
