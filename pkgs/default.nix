{ pkgs, python3 }:

let
  inherit (pkgs) lib;

  callPackage =
    lib.callPackageWith (pkgs // { inherit python3; } // pythonPackages);

  mkPackages = dir:
    builtins.listToAttrs (builtins.map (name: {
      inherit name;
      value = callPackage (dir + "/${name}") { };
    }) (builtins.attrNames (builtins.readDir dir)));

  pythonPackages = mkPackages ./python;
in { inherit pythonPackages; }
