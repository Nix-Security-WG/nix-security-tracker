{ pkgs, python3 }:

let
  callPackage = pkgs.lib.callPackageWith (
    pkgs // { inherit python3; } // python3.pkgs // python3Packages
  );

  python3Packages = mkPackages ./.;
  mkPackages =
    dir:
    with builtins;
    listToAttrs (
      map
        (name: {
          inherit name;
          value = callPackage (dir + "/${name}") { };
        })
        (attrNames (readDir dir))
    );
in
python3Packages
