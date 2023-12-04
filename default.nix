{ sources ? import ./npins, overlay ? import ./nix/overlay.nix
, pkgs ? import sources.nixpkgs { overlays = [ overlay ]; } }: rec {
  python = pkgs.python3;
  localPkgs = import ./pkgs {
    inherit pkgs;
    python3 = python;
  };
  package = pkgs.web-security-tracker;

  pre-commit-check = (import sources.pre-commit-hooks).run {
    src = ./.;

    hooks = {
      # Nix setup
      nixfmt.enable = true;
      statix.enable = true;
      deadnix.enable = true;

      # Python setup
      ruff.enable = true;
      black.enable = true;
      pyright.enable = true;

      # Global setup
      prettier = {
        enable = true;
        excludes = [ "\\.min.css$" "\\.html$" ];
      };
      commitizen.enable = true;
    };
  };
  shell = pkgs.mkShell {
    packages = [ package pkgs.commitizen ];
    shellHook = ''
      ${pre-commit-check.shellHook}

      mkdir -p .credentials
      export CREDENTIALS_DIRECTORY=${builtins.toString ./.credentials}
    '';
  };

  tests = import ./nix/tests/vm-basic.nix {
    inherit pkgs;
    wstModule = ./nix/web-security-tracker.nix;
  };
}
