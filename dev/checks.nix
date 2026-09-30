{
  formatter,
  inputs,
  pkgs,
  system,
}:
import ../tests {
  inherit
    formatter
    inputs
    pkgs
    system
    ;
}
