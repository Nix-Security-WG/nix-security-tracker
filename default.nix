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
  dev-container = import ./infra/container.nix;
  dev-setup = import ./nix/dev-setup.nix;

  pre-commit-check = pkgs.pre-commit-hooks {
    src = ./.;
    # Do not run at pre-commit time, it prevent the workflow where
    # we just absorb things up.
    default_stages = [
      "pre-push"
    ];

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
            "npins/sources\\.json$"
          ] ++ pythonExcludes;
        };
        commitizen = {
          enable = true;
          # This should check the commit message, so better warn early.
          stages = [ "commit-msg" ];
        };
      };
  };

  # shell environment for continuous integration runs
  ci =
    let
      deploy = pkgs.writeShellApplication {
        name = "deploy";
        text = builtins.readFile ./infra/deploy.sh;
        runtimeInputs = with pkgs; [
          nixos-rebuild
          coreutils
        ];
        # TODO: satisfy shellcheck
        checkPhase = "";
      };
    in
    pkgs.mkShellNoCC {
      packages = [
        pkgs.npins
        deploy
      ];
    };

  shell =
    let
      manage = pkgs.writeScriptBin "manage" ''
        exec ${python3}/bin/python ${toString ./src/website/manage.py} $@
      '';
      deploymentSources = import ./infra/npins;
    in
    pkgs.mkShellNoCC {
      env = {
        REDIS_SOCKET_URL = "unix:///run/redis/redis.sock";
        DATABASE_URL = "postgres://nix-security-tracker@/nix-security-tracker";
        # psql doesn't take DATABASE_URL
        PGDATABASE = "nix-security-tracker";
        PGUSER = "nix-security-tracker";
        CREDENTIALS_DIRECTORY = toString ./.credentials;
        DJANGO_SETTINGS = builtins.toJSON {
          DEBUG = true;
          SYNC_GITHUB_STATE_AT_STARTUP = false;
          GH_ISSUES_PING_MAINTAINERS = false;
          GH_ORGANIZATION = "Nix-Security-WG";
          GH_ISSUES_REPO = "sectracker-testing";
          GH_SECURITY_TEAM = "setracker-testing-security";
          GH_COMMITTERS_TEAM = "sectracker-testing-committers";
          STATIC_ROOT = "${toString ./src/website/static}";
          REVISION = "Development - ${
            (builtins.fetchGit {
              url = ./.;
              shallow = true;
            }).rev
          }";
        };
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
        pkgs.awscli
        (import deploymentSources.agenix { inherit pkgs; }).agenix
      ] ++ pre-commit-check.enabledPackages;

      shellHook = ''
        ${pre-commit-check.shellHook}

        ln -sf ${sources.htmx}/dist/htmx.js src/website/webview/static/htmx.min.js

        mkdir -p $CREDENTIALS_DIRECTORY
        # TODO(@fricklerhandwerk): move all configuration over to pydantic-settings
        touch .settings.py
        export USER_SETTINGS_FILE=${builtins.toString ./.settings.py}
      '';
    };

  tests = pkgs.callPackage ./nix/tests.nix { };
}
