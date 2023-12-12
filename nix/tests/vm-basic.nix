{ pkgs, wstModule, ... }:
let
  utils = import ./utils.nix { inherit pkgs wstModule; };
  inherit (utils) mkVMTest;
in
{
  vm-basic = mkVMTest { name = "basic"; };
}
