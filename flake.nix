{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = inputs: let
    lib = inputs.nixpkgs.lib;
    project = self: self.callCabal2nix "CVENix" ./. {};
    haskellPackages = pkgs: pkgs.haskell.packages.ghc947.override {
      overrides = self: super: {
        CVENix = project self;
      };
    };
    supportedSystems = lib.genAttrs
      [ "x86_64-linux"
        "aarch64-linux"
      ];
  in {
    packages = supportedSystems (system: let
      pkgs = inputs.nixpkgs.legacyPackages."${system}";
    in { default = (haskellPackages pkgs).CVENix; });

    devShells = supportedSystems (system: let
      pkgs = inputs.nixpkgs.legacyPackages."${system}";
      hsPkgs = haskellPackages pkgs;
    in { default = hsPkgs.shellFor { packages = ps: with ps; [ CVENix ]; buildInputs = with hsPkgs; [ cabal-install ]; }; });
    };
}
