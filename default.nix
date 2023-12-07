{ sources ? import ./npins, overlay ? import ./nix/overlay.nix
, pkgs ? import sources.nixpkgs { overlays = [ overlay ]; } }: rec {
  inherit (pkgs) python3;
  localPythonPackages = import ./pkgs { inherit pkgs python3; };

  # For exports.
  overlays = [ overlay ];
  package = pkgs.web-security-tracker;
  module = import ./nix/web-security-tracker.nix;

  pre-commit-check = (import sources.pre-commit-hooks).run {
    src = ./.;

    hooks = {
      # Nix setup
      nixfmt.enable = true;
      statix.enable = true;
      deadnix.enable = true;

      # Python setup
      # TODO: ruff.enable = true; -- re-enable only when F403 is disabled. It is too noisy otherwise.
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
    packages = [ package pkgs.nix-eval-jobs pkgs.commitizen ];
    shellHook = ''
      ${pre-commit-check.shellHook}

      mkdir -p .credentials
      export CREDENTIALS_DIRECTORY=${builtins.toString ./.credentials}
      export DATABASE_URL="sqlite:///tracker.sqlite3"
    '';
  };

  tests = import ./nix/tests/vm-basic.nix {
    inherit pkgs;
    wstModule = module;
  };
}
