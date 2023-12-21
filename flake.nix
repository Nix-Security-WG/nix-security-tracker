# SPDX-FileCopyrightText: 2023 Arnout Engelen <arnout@bzzt.net>
# SPDX-FileCopyrightText: 2023 Dylan Green <dylan.green@obsidian.systems>
#
# SPDX-License-Identifier: MIT

{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    sbomnix = {
      url = "github:tiiuae/sbomnix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs: let
    lib = inputs.nixpkgs.lib;
    project = self: self.callCabal2nix "LocalSecurityScanner" ./. {};
    haskellPackages = pkgs: pkgs.haskell.packages.ghc947.override {
      overrides = self: super: {
        LocalSecurityScanner = pkgs.haskell.lib.overrideCabal (project self) (drv: {
          libraryHaskellDepends = (drv.libraryHaskellDepends or []) ++ [
            inputs.sbomnix.packages."${pkgs.system}".sbomnix
          ];
        });
      };
    };
    supportedSystems = lib.genAttrs
      [ "x86_64-linux"
        "aarch64-linux"
      ];
  in {
    packages = supportedSystems (system: let
      pkgs = inputs.nixpkgs.legacyPackages."${system}";
    in { default = (haskellPackages pkgs).LocalSecurityScanner; });

    devShells = supportedSystems (system: let
      pkgs = inputs.nixpkgs.legacyPackages."${system}";
      hsPkgs = haskellPackages pkgs;
    in {
      default = hsPkgs.shellFor {
        packages = ps: with ps; [ LocalSecurityScanner ]; buildInputs = with hsPkgs; [ cabal-install ];
        propagatedBuildInputs = [ inputs.sbomnix.packages."${system}".sbomnix ];
        shellHook = let
          ghcidWrapped = pkgs.writeShellScriptBin "ghcid" ''
            ${hsPkgs.ghcid.bin}/bin/ghcid --command "cabal repl"
          '';
          ghcidUnwrapped = pkgs.writeShellScriptBin "ghcid-unwrapped" ''
            ${hsPkgs.ghcid.bin}/bin/ghcid
          '';
        in ''
          # To find freshly-`cabal install`ed executables
          export PATH=~/.local/bin:${ghcidWrapped}/bin:${ghcidUnwrapped}/bin:$PATH
        '';
      };
      LocalSecurityScanner = hsPkgs.shellFor { packages = ps: with ps; [ LocalSecurityScanner ]; buildInputs = with hsPkgs; [ cabal-install ghcid multi-containers ]; };
    });
  };
}
