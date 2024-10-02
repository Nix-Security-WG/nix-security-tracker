{
  system ? builtins.currentSystem,
  sources ? import ./npins,
  overlay ? import ./nix/overlay.nix,
  pkgs ? import sources.nixpkgs {
    config = { };
    overlays = [ overlay ];
    inherit system;
  },
  lib ? import "${sources.nixpkgs}/lib",
}:
rec {
  inherit pkgs;
  inherit (pkgs) python3;
  localPythonPackages = import ./pkgs { inherit pkgs python3; };

  # For exports.
  overlays = [ overlay ];
  package = pkgs.web-security-tracker;
  module = import ./nix/web-security-tracker.nix;
  dev-container = import ./staging/container.nix;
  dev-setup = import ./nix/dev-setup.nix;

  pre-commit-check = pkgs.pre-commit-hooks {
    src = ./.;

    hooks =
      let
        pythonExcludes = [
          "/migrations/" # auto-generated code
        ];
      in
      {
        # Nix setup
        nixfmt-rfc-style.enable = true;
        statix = {
          enable = true;
          settings.ignore = [ "staging" ];
        };
        deadnix.enable = true;

        # Python setup
        ruff = {
          enable = true;
          excludes = pythonExcludes;
        };
        ruff-format = {
          enable = true;
          name = "Format python code with ruff";
          types = [
            "text"
            "python"
          ];
          entry = "${pkgs.lib.getExe pkgs.ruff} format";
          excludes = pythonExcludes;
        };

        pyright =
          let
            pyEnv = pkgs.python3.withPackages (_: pkgs.web-security-tracker.propagatedBuildInputs);
            wrappedPyright = pkgs.runCommand "pyright" { nativeBuildInputs = [ pkgs.makeWrapper ]; } ''
              makeWrapper ${pkgs.pyright}/bin/pyright $out \
                --set PYTHONPATH ${pyEnv}/${pyEnv.sitePackages} \
                --prefix PATH : ${pyEnv}/bin \
                --set PYTHONHOME ${pyEnv}
            '';
          in
          {
            enable = true;
            entry = lib.mkForce (builtins.toString wrappedPyright);
            excludes = pythonExcludes;
          };

        # Global setup
        prettier = {
          enable = true;
          excludes = [
            "\\.min.css$"
            "\\.html$"
          ] ++ pythonExcludes;
        };
        commitizen.enable = true;
      };
  };

  shell =
    let
      manage = pkgs.writeScriptBin "manage" ''
        ${python3}/bin/python ${toString ./src/website/manage.py} $@
      '';
      create-credentials = pkgs.writeShellApplication {
        name = "create-credentials";
        text = ''
          if [ ! -d .credentials ]; then
            mkdir .credentials
            echo foo > .credentials/SECRET_KEY
            echo bar > .credentials/GH_CLIENT_ID
            echo baz > .credentials/GH_SECRET
            echo qux > .credentials/GH_WEBHOOK_SECRET
          fi
        '';
      };
    in
    pkgs.mkShell {
      env = {
        REDIS_SOCKET_URL = "unix:///run/redis/redis.sock";
        DATABASE_URL = "postgres://nix-security-tracker@/nix-security-tracker";
        # psql doesn't take DATABASE_URL
        PGDATABASE = "nix-security-tracker";
        PGUSER = "nix-security-tracker";
      };

      # `./src/website/tracker/settings.py` by default looks for LOCAL_NIXPKGS_CHECKOUT
      # in the root of the repo. Make it the default here for local development.
      LOCAL_NIXPKGS_CHECKOUT = toString ./. + "/nixpkgs";

      packages = [
        manage
        package
        pkgs.nix-eval-jobs
        pkgs.npins
        pkgs.hivemind
      ] ++ pre-commit-check.enabledPackages;

      shellHook = ''
        ${pre-commit-check.shellHook}
        ${lib.getExe create-credentials}

        mkdir -p .credentials
        export CREDENTIALS_DIRECTORY=${builtins.toString ./.credentials}
      '';
    };

  tests = import ./nix/tests/vm-basic.nix {
    inherit pkgs;
    wstModule = module;
  };
}
