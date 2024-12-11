{
  config,
  pkgs,
  lib,
  ...
}:
let
  inherit (lib)
    types
    mkIf
    mkEnableOption
    mkPackageOption
    mkOption
    mapAttrs
    mapAttrsToList
    mkDefault
    concatStringsSep
    recursiveUpdate
    optionalString
    ;
  inherit (pkgs) writeScriptBin writeShellApplication stdenv;
  cfg = config.services.web-security-tracker;
  pythonFmt = pkgs.formats.pythonVars { };

  settingsFile = pythonFmt.generate "wst-settings.py" cfg.settings;
  extraConfigFile = pkgs.writeTextFile {
    name = "wst-extraConfig.py";
    text = cfg.extraConfig;
  };

  configFile = pkgs.concatText "configuration.py" [
    settingsFile
    extraConfigFile
  ];
  pythonEnv = pkgs.python3.withPackages (
    ps: with ps; [
      cfg.package
      daphne
    ]
  );
  wstManageScript = writeShellApplication {
    name = "wst-manage";

    runtimeInputs = [ pkgs.git ];

    text = ''
      sudo="exec"
      if [[ "$USER" != "web-security-tracker" ]]; then
        sudo='exec /run/wrappers/bin/sudo -u web-security-tracker --preserve-env --preserve-env=PYTHONPATH'
      fi
      export PYTHONPATH=${toString cfg.package.pythonPath}
      $sudo ${cfg.package}/bin/manage.py "$@"
    '';
  };
  credentials = mapAttrsToList (name: secretPath: "${name}:${secretPath}") cfg.secrets;
  databaseUrl = "postgres:///web-security-tracker";
  # This script has access to the credentials, no matter where it is.
  wstExternalManageScript = writeScriptBin "wst-manage" ''
    #!${stdenv.shell}
    echo "${concatStringsSep " " credentials}"
    systemd-run --pty \
      --wait \
      --collect \
      --service-type=exec \
      --unit "wst-manage.service" \
      --property "User=web-security-tracker" \
      --property "Group=web-security-tracker" \
      --property "WorkingDirectory=/var/lib/web-security-tracker" \
      ${concatStringsSep "\n" (map (cred: "--property 'LoadCredential=${cred}' \\") credentials)}
      --property "Environment=DATABASE_URL=${databaseUrl} USER_SETTINGS_FILE=${settingsFile}" \
      "${wstManageScript}/bin/wst-manage" "$@"
  '';
in
{
  options.services.web-security-tracker = {
    enable = mkEnableOption "web security tracker for Nixpkgs and similar monorepo";

    package = mkPackageOption pkgs "web-security-tracker" { };
    production = mkOption {
      type = types.bool;
      default = true;
    };
    restart = mkOption {
      description = "systemd restart behavior";
      type = types.str;
      default = "always";
    };
    domain = mkOption { type = types.str; };
    wsgi-port = mkOption {
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
    cve.startDate = mkOption {
      type = types.nullOr types.str;
      default = null;
      defaultText = "the application default: January 1st of the prior year";
      description = ''
        The ingestion start date for CVE, most operators will care about CVEs of their last year until now.
        Hence, this is the default.

        If you need to obtain older CVEs for any reason, change this value.
      '';
      example = "2024-11-01";
    };
    maxJobProcessors = mkOption {
      description = ''
        How many channels to evaluate in parallel.

        Each evaluation of Nixpkgs peaks at ~6GB of required RAM.
      '';
      type = types.int;
      default = 2;
    };
  };

  config = mkIf cfg.enable {
    environment.systemPackages = [ wstExternalManageScript ];
    services = {
      web-security-tracker.settings = {
        STATIC_ROOT = mkDefault "/var/lib/web-security-tracker/static";
        DEBUG = mkDefault false;
        ALLOWED_HOSTS = mkDefault [
          (with cfg; if production then domain else "*")
          "localhost"
          "127.0.0.1"
          "[::1]"
        ];
        CSRF_TRUSTED_ORIGINS = mkDefault [ "https://${cfg.domain}" ];
        EVALUATION_GC_ROOTS_DIRECTORY = mkDefault "/var/lib/web-security-tracker/gc-roots";
        EVALUATION_LOGS_DIRECTORY = mkDefault "/var/log/web-security-tracker/evaluation";
        LOCAL_NIXPKGS_CHECKOUT = mkDefault "/var/lib/web-security-tracker/nixpkgs-repo";
        CVE_CACHE_DIR = mkDefault "/var/lib/web-security-tracker/cve-cache";
        ACCOUNT_DEFAULT_HTTP_PROTOCOL = mkDefault (with cfg; if production then "https" else "http");
      };

      nginx.enable = true;
      nginx.virtualHosts = {
        ${cfg.domain} =
          {
            locations = {
              "/".proxyPass = "http://localhost:${toString cfg.wsgi-port}";
              "/static/".alias = "/var/lib/web-security-tracker/static/";
            };
          }
          // lib.optionalAttrs cfg.production {
            enableACME = true;
            forceSSL = true;
          };
      };

      postgresql.enable = true;
      postgresql = {
        ensureUsers = [
          {
            name = "web-security-tracker";
            ensureDBOwnership = true;
          }
        ];
        ensureDatabases = [ "web-security-tracker" ];
      };
    };

    users.users.web-security-tracker = {
      isSystemUser = true;
      group = "web-security-tracker";
    };
    users.groups.web-security-tracker = { };

    systemd.services =
      let
        defaults = {
          path = [
            pythonEnv
            wstManageScript
            pkgs.nix-eval-jobs
          ];
          serviceConfig = {
            User = "web-security-tracker";
            WorkingDirectory = "/var/lib/web-security-tracker";
            StateDirectory = "web-security-tracker";
            RuntimeDirectory = "web-security-tracker";
            LogsDirectory = "web-security-tracker";
            LoadCredential = credentials;
          };
          environment = {
            DATABASE_URL = databaseUrl;
            USER_SETTINGS_FILE = "${configFile}";
          };
        };
      in
      mapAttrs (_: recursiveUpdate defaults) {
        web-security-tracker-server = {
          description = "A web security tracker ASGI server";
          after = [
            "network.target"
            "postgresql.service"
          ];
          requires = [ "postgresql.service" ];
          wantedBy = [ "multi-user.target" ];
          serviceConfig = {
            Restart = cfg.restart;
            TimeoutStartSec = lib.mkDefault "10m";
            Environment = [
              "SYNC_GITHUB_STATE_AT_STARTUP=true"
            ];
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
          script =
            let
              networking =
                if cfg.unixSocket != null then
                  "-u ${cfg.unixSocket}"
                else
                  "-b 127.0.0.1 -p ${toString cfg.wsgi-port}";
            in
            ''
              daphne ${networking} \
                tracker.asgi:application
            '';
        };

        web-security-tracker-worker = {
          description = "Web security tracker - background job processor";
          after = [
            "network.target"
            "postgresql.service"
            "web-security-tracker-server.service"
          ];
          requires = [ "postgresql.service" ];
          wantedBy = [ "multi-user.target" ];

          script = ''
            # Before starting, crash all the in-progress evaluations.
            # This will prevent them from being stalled forever, since workers would not pick up evaluations marked as in-progress.
            wst-manage crash_all_evaluations
            wst-manage listen --recover --processes ${toString cfg.maxJobProcessors}
          '';
        };

        web-security-tracker-fetch-all-channels = {
          description = "Web security tracker - refresh all channels and start nixpkgs evaluation";

          after = [
            "network.target"
            "postgresql.service"
            "web-security-tracker-server.service"
          ];
          requires = [ "postgresql.service" ];

          serviceConfig.Type = "oneshot";

          script = ''
            wst-manage fetch_all_channels
          '';

          # Ideally, start at whatever night means.
          startAt = "*-*-* 04:00:00";
        };

        web-security-tracker-delta = {
          description = "Web security tracker catch up with CVEs";
          after = [
            "network.target"
            "postgresql.service"
            "web-security-tracker-server.service"
          ];
          requires = [ "postgresql.service" ];
          serviceConfig.Type = "oneshot";

          script = ''
            wst-manage ingest_delta_cve "$(date --date='yesterday' --iso)" ${
              optionalString (cfg.cve.startDate != null) "--default-start-ingestion ${cfg.cve.startDate}"
            }
          '';

          # Start at 03h so that the data will have been published
          startAt = "*-*-* 03:00:00";
        };
      };
  };
}
