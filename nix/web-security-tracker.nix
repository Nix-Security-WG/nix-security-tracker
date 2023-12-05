{ config, pkgs, lib, ... }:
let
  inherit (lib)
    types mkIf mkEnableOption mkPackageOptionMD mkOption mapAttrsToList
    mkDefault concatStringsSep optional;
  inherit (pkgs) writeScriptBin stdenv;
  cfg = config.services.web-security-tracker;
  pythonFmt = pkgs.formats.pythonVars { };

  settingsFile = pythonFmt.generate "wst-settings.py" cfg.settings;
  extraConfigFile = pkgs.writeTextFile {
    name = "wst-extraConfig.py";
    text = cfg.extraConfig;
  };

  configFile =
    pkgs.concatText "configuration.py" [ settingsFile extraConfigFile ];
  pythonEnv = pkgs.python3.withPackages (ps: with ps; [ cfg.package daphne ]);
  wstManageScript = writeScriptBin "wst-manage" ''
    #!${stdenv.shell}
    sudo=exec
    if [[ "$USER" != "web-security-tracker" ]]; then
      sudo='exec /run/wrappers/bin/sudo -u web-security-tracker --preserve-env --preserve-env=PYTHONPATH'
    fi
    export PYTHONPATH=${toString cfg.package.pythonPath}
    $sudo ${cfg.package}/bin/manage.py "$@"
  '';
  credentials =
    mapAttrsToList (name: secretPath: "${name}:${secretPath}") cfg.secrets;
  databaseUrl = "postgres:///web-security-tracker";
  # This script has access to the credentials, no matter where it is.
  wstExternalManageScript = writeScriptBin "wst-manage" ''
    #!${stdenv.shell}
    echo "${concatStringsSep " " credentials}"
    systemd-run --pty \
      --same-dir \
      --wait \
      --collect \
      --service-type=exec \
      --unit "wst-manage.service" \
      --property "User=web-security-tracker" \
      --property "Group=web-security-tracker" \
      ${
        concatStringsSep "\n"
        (map (cred: "--property 'LoadCredential=${cred}' \\") credentials)
      }
      --property "Environment=DATABASE_URL=${databaseUrl} USER_SETTINGS_FILE=${settingsFile}" \
      "${wstManageScript}/bin/wst-manage" "$@"
  '';
in {
  options.services.web-security-tracker = {
    enable =
      mkEnableOption "web security tracker for Nixpkgs and similar monorepo";

    package = mkPackageOptionMD pkgs "web-security-tracker" { };
    domain = mkOption {
      type = types.nullOr types.str;
      default = null;
    };
    port = mkOption {
      type = types.port;
      default = 8000;
    };
    unixSocket = mkOption {
      type = types.nullOr types.str;
      default = null;
    };
    settings = mkOption {
      type = types.attrsOf types.anything;
      default = { };
    };
    extraConfig = mkOption {
      type = types.lines;
      default = "";
    };
    secrets = mkOption {
      type = types.attrsOf types.path;
      default = { };
    };
  };

  config = mkIf cfg.enable {
    environment.systemPackages = [ wstExternalManageScript ];
    services.web-security-tracker.settings = {
      STATIC_ROOT = mkDefault "/var/lib/web-security-tracker/static";
      DEBUG = mkDefault false;
      ALLOWED_HOSTS = mkDefault ((optional (cfg.domain != null) cfg.domain)
        ++ [ "localhost" "127.0.0.1" "[::1]" ]);
    };

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

    services.nginx.virtualHosts = lib.mkIf (cfg.domain != null) {
      "${cfg.domain}" = {
        enableACME = true;
        forceSSL = true;
        locations."/".proxyPass = "http://localhost:${toString cfg.port}";
        locations."/static/".alias = "/var/lib/web-security-tracker/static/";
      };
    };

    systemd.services.web-security-tracker-server = {
      description = "A web security tracker ASGI server";
      after = [ "network.target" "postgresql.service" ];
      requires = [ "postgresql.service" ];
      wantedBy = [ "multi-user.target" ];
      path = [ pythonEnv wstManageScript ];
      serviceConfig = {
        User = "web-security-tracker";
        Restart = "always";
        WorkingDirectory = "/var/lib/web-security-tracker";
        StateDirectory = "web-security-tracker";
        RuntimeDirectory = "web-security-tracker";
        LoadCredential = credentials;
      };
      environment = {
        DATABASE_URL = databaseUrl;
        USER_SETTINGS_FILE = "${configFile}";
      };
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
