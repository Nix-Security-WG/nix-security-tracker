{ config, pkgs, lib, ... }:
let
  inherit (lib) types mkIf mkEnableOption mkPackageOptionMD mkOption;
  cfg = config.services.web-security-tracker;
  pythonEnv = pkgs.python3.withPackages (ps: with ps; [ cfg.package daphne ]);
  wstManageScript = with pkgs;
    (writeScriptBin "wst-manage" ''
      #!${stdenv.shell}
      export PYTHONPATH=${cfg.package.pythonPath}
      sudo -u web-security-tracker ${cfg.package}/bin/manage.py "$@"
    '');
in {
  options.services.web-security-tracker = {
    enable =
      mkEnableOption "web security tracker for Nixpkgs and similar monorepo";

    package = mkPackageOptionMD pkgs "web-security-tracker" { };
    port = mkOption {
      type = types.port;
      default = 8000;
    };
    unixSocket = mkOption {
      type = types.nullOr types.str;
      default = null;
    };
  };

  config = mkIf cfg.enable {
    environment.systemPackages = [ wstManageScript ];
    users.users.web-security-tracker = {
      isSystemUser = true;
      group = "web-security-tracker";
    };
    users.groups.web-security-tracker = { };
    services.postgresql = {
      enable = true;
      ensureUsers = [{
        name = "web-security-tracker";
        ensureDBOwnership = true;
      }];
      ensureDatabases = [ "web-security-tracker" ];
    };

    systemd.services.web-security-tracker-server = {
      description = "A web security tracker ASGI server";
      after = [ "network.target" "systemd-tmpfiles-setup.service" ];
      wantedBy = [ "multi-user.target" ];
      path = [ pythonEnv ];
      serviceConfig = {
        User = "web-security-tracker";
        Restart = "always";
        WorkingDirectory = "/var/lib/web-security-tracker";
        StateDirectory = "web-security-tracker";
        RuntimeDirectory = "web-security-tracker";
      };
      environment = { DATABASE_URL = "postgres:///web-security-tracker"; };
      preStart = ''
        # Auto-migrate on first run or if the package has changed
        versionFile="/var/lib/web-security-tracker/package-version"
        if [[ $(cat "$versionFile" 2>/dev/null) != ${cfg.package} ]]; then
          wst-manage migrate --no-input
          wst-manage collectstatic --no-input --clear
          echo ${cfg.package} > "$versionFile"
        fi
      '';
      script = let
        networking = if cfg.unixSocket != null then
          "-u ${cfg.unixSocket}"
        else
          "-b 127.0.0.1 -p ${toString cfg.port}";
      in ''
        daphne ${networking} \
          tracker.asgi:application
      '';
    };
  };
}
