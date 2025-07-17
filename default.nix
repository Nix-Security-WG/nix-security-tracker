{
  system ? builtins.currentSystem,
  sources ? import ./npins,
  overlay ? import ./nix/overlay.nix,
  pkgs ? import sources.nixpkgs {
    config = { };
    overlays = [ overlay ];
    inherit system;
  },
}:
rec {
  inherit pkgs;

  # For exports.
  overlays = [ overlay ];
  package = pkgs.web-security-tracker;
  module = import ./nix/web-security-tracker.nix;
  dev-container = import ./infra/container.nix;
  dev-setup = import ./nix/dev-setup.nix;

  git-hooks = pkgs.pre-commit-hooks {
    src = ./.;
    imports = [ ./nix/git-hooks.nix ];
  };

  format = pkgs.writeShellApplication {
    name = "format";
    runtimeInputs = git-hooks.enabledPackages ++ [ git-hooks.config.package ];
    text = ''
      pre-commit run --all-files --hook-stage manual
    '';
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
        exec ${pkgs.python3}/bin/python ${toString ./src/manage.py} $@
      '';
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
          PRODUCTION = false;
          SYNC_GITHUB_STATE_AT_STARTUP = false;
          GH_ISSUES_PING_MAINTAINERS = false;
          GH_ORGANIZATION = "Nix-Security-WG";
          GH_ISSUES_REPO = "sectracker-testing";
          GH_SECURITY_TEAM = "setracker-testing-security";
          GH_COMMITTERS_TEAM = "sectracker-testing-committers";
          STATIC_ROOT = "${toString ./src/static}";
          REVISION =
            let
              git = builtins.fetchGit {
                url = ./.;
                shallow = true;
              };
            in
            if git ? dirtyRev then git.dirtyShortRev else git.shortRev;
        };
      };

      # `./src/project/settings.py` by default looks for LOCAL_NIXPKGS_CHECKOUT
      # in the root of the repo. Make it the default here for local development.
      LOCAL_NIXPKGS_CHECKOUT = toString ./. + "/nixpkgs";

      packages = [
        manage
        package
        pkgs.nix-eval-jobs
        pkgs.npins
        pkgs.hivemind
        pkgs.awscli
        (import sources.agenix { inherit pkgs; }).agenix
        format
      ] ++ git-hooks.enabledPackages;

      shellHook = ''
        ${(pkgs.pre-commit-hooks {
          src = ./.;
          imports = [ ./nix/git-hooks.nix ];
          hooks.commitizen = {
            enable = true;
            stages = [ "commit-msg" ];
          };
        }).shellHook
        }

        ln -sf ${sources.htmx}/dist/htmx.js src/webview/static/htmx.min.js

        mkdir -p $CREDENTIALS_DIRECTORY
        # TODO(@fricklerhandwerk): move all configuration over to pydantic-settings
        touch .settings.py
        export USER_SETTINGS_FILE=${builtins.toString ./.settings.py}
      '';
    };

  tests = pkgs.callPackage ./nix/tests.nix { };
}
