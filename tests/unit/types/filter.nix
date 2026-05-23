/*
  Unit tests for `lib/types/filter.nix` (exposed as
  `nftzones.types.{filter,filterName,filterRule,
  filterPriority,filterComment}`). Same
  `testFoo = { expr; expected; }` shape as every other unit test;
  aggregated by `tests/unit/default.nix`.
*/
{
  pkgs,
  nftzones,
  nftypes,
  ...
}:
let
  inherit (import ../helpers.nix { inherit pkgs nftzones; }) evalTable evalFails;

  inherit (nftypes.dsl) eq accept;
  inherit (nftypes.dsl.fields) tcp;

  basicBody = {
    from = [ "wan" ];
    to = [ "local" ];
    rule = [
      (eq tcp.dport 22)
      accept
    ];
  };

  filterIn =
    body:
    (evalTable {
      filters.allow-ssh = body;
    }).filters.allow-ssh;
in
{
  # ===== filter.name — derives from attrset key =====

  testFilterNameDerivedFromKey = {
    expr = (filterIn basicBody).name;
    expected = "allow-ssh";
  };

  # ===== filter.from / to — required, non-empty zone lists =====

  testFilterFromAccepted = {
    expr = (filterIn basicBody).from;
    expected = [ "wan" ];
  };

  testFilterFromMultiZone = {
    expr =
      (filterIn (
        basicBody
        // {
          from = [
            "lan"
            "guest"
          ];
        }
      )).from;
    expected = [
      "lan"
      "guest"
    ];
  };

  testFilterFromEmptyRejected = {
    # nonEmptyListOf rejects [].
    expr = evalFails (filterIn (basicBody // { from = [ ]; })).from;
    expected = true;
  };

  testFilterToEmptyRejected = {
    expr = evalFails (filterIn (basicBody // { to = [ ]; })).to;
    expected = true;
  };

  # ===== filter.rule — list of nftypes statements (rejects raw shapes) =====

  testFilterRuleAccepted = {
    expr = (filterIn basicBody).rule;
    expected = [
      (eq tcp.dport 22)
      accept
    ];
  };

  testFilterRuleRejectsBogusStatement = {
    # primitives.rule = listOf nftypes.types.statement; a list
    # element that doesn't pass nftypes' attrTag validation is
    # rejected. (Note: `{ accept = null; }` is the *actual* shape
    # nftypes.dsl.accept produces, so it would pass — pick a tag
    # nftypes doesn't recognize.)
    expr = evalFails (filterIn (basicBody // { rule = [ "not-a-statement" ]; })).rule;
    expected = true;
  };

  # ===== filter.priority — entryPriority symbol-or-int, default "default" =====

  testFilterPriorityDefault = {
    expr = (filterIn basicBody).priority;
    expected = "default";
  };

  testFilterPrioritySymbolFirst = {
    expr = (filterIn (basicBody // { priority = "first"; })).priority;
    expected = "first";
  };

  testFilterPriorityInt = {
    expr = (filterIn (basicBody // { priority = 250; })).priority;
    expected = 250;
  };

  testFilterPriorityRejectsUnknownSymbol = {
    expr = evalFails (filterIn (basicBody // { priority = "asap"; })).priority;
    expected = true;
  };

  # ===== filter.chain — null default; submodule when set =====

  testFilterChainDefaultNull = {
    expr = (filterIn basicBody).chain;
    expected = null;
  };

  testFilterChainAccepted = {
    expr =
      (filterIn (
        basicBody
        // {
          chain = {
            hook = "prerouting";
            priority = "raw";
          };
        }
      )).chain;
    expected = {
      hook = "prerouting";
      priority = "raw";
    };
  };

  testFilterChainHookRequired = {
    # Both hook and priority are required when chain is non-null.
    # Force evaluation of the missing field — accessing `.chain`
    # alone returns a lazy submodule without checking `hook`.
    expr =
      evalFails
        (filterIn (
          basicBody
          // {
            chain = {
              priority = "raw";
            };
          }
        )).chain.hook;
    expected = true;
  };

  testFilterChainPriorityRequired = {
    expr =
      evalFails
        (filterIn (
          basicBody
          // {
            chain = {
              hook = "prerouting";
            };
          }
        )).chain.priority;
    expected = true;
  };

  # ===== filter.comment — optional, null default =====

  testFilterCommentDefault = {
    expr = (filterIn basicBody).comment;
    expected = null;
  };

  testFilterCommentAccepted = {
    expr = (filterIn (basicBody // { comment = "ssh from anywhere"; })).comment;
    expected = "ssh from anywhere";
  };
}
