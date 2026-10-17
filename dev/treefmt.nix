{
  programs = {
    nixfmt.enable = true;
    deadnix.enable = true;
    actionlint.enable = true;
    prettier = {
      enable = true;
      settings = {
        proseWrap = "preserve";
        printWidth = 100;
      };
    };
    ruff-format.enable = true;
    ruff-check.enable = true;
  };
}
