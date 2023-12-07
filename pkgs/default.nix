{ pkgs, python3 }:

let
  inherit (pkgs) lib;

  callPackage =
    lib.callPackageWith (pkgs // { inherit python3; } // pythonPackages);

  mkPackages = dir:
    with builtins;
    listToAttrs (map (name: {
      inherit name;
      value = callPackage (dir + "/${name}") { };
    }) (attrNames (readDir dir)));

  pythonPackages = mkPackages ./python;
in pythonPackages
