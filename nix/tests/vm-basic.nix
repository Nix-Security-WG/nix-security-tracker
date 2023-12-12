{ pkgs, wstModule, ... }:
let
  utils = pkgs.callPackage ./utils.nix { inherit wstModule; };
  inherit (utils) mkVMTest;
in
{
  vm-basic = mkVMTest {
    name = "basic";
    nodes.machine = { };
  };
}
