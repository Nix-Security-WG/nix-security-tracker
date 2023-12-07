{ sources ? import ./npins
, overlay ? import ./nix/overlay.nix
, pkgs ? import sources.nixpkgs { overlays = [ overlay ]; }
,
}:
rec {
  python = pkgs.python3;
  localPkgs = import ./pkgs {
    inherit pkgs;
    python3 = python;
  };

  # For exports.
  overlays = [ overlay ];
  package = pkgs.web-security-tracker;
  module = import ./nix/web-security-tracker.nix;

  pre-commit-check = pkgs.pre-commit-hooks {
    src = ./.;

    settings.statix.ignore = [
      "/staging"
      "/nix/web-security-tracker.nix"
    ];

    hooks = {
      # Nix setup
      nixfmt.enable = true;
      statix.enable = true;
      deadnix.enable = true;

      # Python setup
      ruff.enable = true;
      ruff-format = {
        enable = true;
        name = "Format python code with ruff";
        types = [ "text" "python" ];
        entry = "${pkgs.lib.getExe pkgs.ruff} format";
      };
      pyright.enable = true;

      # Global setup
      prettier = {
        enable = true;
        excludes = [
          "\\.min.css$"
          "\\.html$"
        ];
      };
      commitizen.enable = true;
    };
  };

  shell = pkgs.mkShell {
    DATA_CACHE_DIRECTORY = toString ./. + "/.data_cache";

    packages = [
      package
      pkgs.nix-eval-jobs
      pkgs.commitizen
      pkgs.npins
      pkgs.nixfmt
    ];

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
