{
  sources ? import ../npins,
  system ? builtins.currentSystem,
  pkgs ? import sources.nixpkgs {
    config = { };
    overlays = [ ];
    inherit system;
  },
}:

pkgs.mkShell { buildInputs = with pkgs; [ opentofu ]; }
