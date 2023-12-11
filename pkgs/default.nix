{ pkgs, python3 }:

{

  # place more custom packages here
  python3Packages = pkgs.callPackage ./python { inherit python3; };
}
