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
  # TODO: make it somehow configurable from the outside... modular services anyone?
  application = "web-security-tracker";
  inherit (pkgs) writeScriptBin writeShellApplication stdenv;
  cfg = config.services.${application};
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
    runtimeEnv = environment;
    excludeShellChecks = [
      "SC2089"
      "SC2090"
    ];

    text = ''
      sudo="exec"
      if [[ "$USER" != "${application}" ]]; then
        sudo='exec /run/wrappers/bin/sudo -u ${application} --preserve-env --preserve-env=PYTHONPATH'
      fi
      export PYTHONPATH=${toString cfg.package.pythonPath}
      $sudo ${cfg.package}/bin/manage.py "$@"
    '';
  };
  credentials = mapAttrsToList (name: secretPath: "${name}:${secretPath}") cfg.secrets;
  databaseUrl = "postgres:///${application}";

  environment = {
    DATABASE_URL = databaseUrl;
    USER_SETTINGS_FILE = "${configFile}";
    DJANGO_SETTINGS = builtins.toJSON cfg.env;
  };

  # This script has access to the credentials, no matter where it is.
  wstExternalManageScript = writeScriptBin "wst-manage" ''
    #!${stdenv.shell}
    echo "${concatStringsSep " " credentials}"
    systemd-run --pty \
      --wait \
      --collect \
      --service-type=exec \
      --unit "wst-manage.service" \
      --property "User=${application}" \
      --property "Group=${application}" \
      --property "WorkingDirectory=${cfg.stateDir}/${application}" \
      ${concatStringsSep "\n" (map (cred: "--property 'LoadCredential=${cred}' \\") credentials)}
      --property "Environment=${
        toString (lib.mapAttrsToList (name: value: "${name}=${value}") environment)
      }" \
      "${wstManageScript}/bin/wst-manage" "$@"
  '';
in
{
  options.services.${application} = {
    enable = mkEnableOption "web security tracker for Nixpkgs and similar monorepo";

    # TODO: `callPackage` the derivation here instead of splicing through overlays, it's needlessly hard to follow
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
    stateDir = mkOption {
      description = "directory for keeping file system state";
      type = types.path;
      default = "/var/lib";
    };
    env = mkOption rec {
      description = ''
        Django configuration via environment variables, see `settings.py` for options.
      '';
      type = types.attrsOf types.anything;
      default = {
        STATIC_ROOT = "${cfg.stateDir}/${application}/static/";
      };
      # only override defaults with explicit values
      apply = lib.recursiveUpdate default;
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
      # TODO(@fricklerhandwerk): move all configuration over to pydantic-settings
      ${application}.settings = {
        ALLOWED_HOSTS = mkDefault [
          (with cfg; if production then domain else "*")
          "localhost"
          "127.0.0.1"
          "[::1]"
        ];
        CSRF_TRUSTED_ORIGINS = mkDefault [ "https://${cfg.domain}" ];
        EVALUATION_GC_ROOTS_DIRECTORY = mkDefault "${cfg.stateDir}/${application}/gc-roots";
        EVALUATION_LOGS_DIRECTORY = mkDefault "${cfg.stateDir}/${application}/evaluation";
        LOCAL_NIXPKGS_CHECKOUT = mkDefault "${cfg.stateDir}/${application}/nixpkgs-repo";
        CVE_CACHE_DIR = mkDefault "${cfg.stateDir}/${application}/cve-cache";
        ACCOUNT_DEFAULT_HTTP_PROTOCOL = mkDefault (with cfg; if production then "https" else "http");
      };

      nginx.enable = true;
      nginx.virtualHosts = {
        ${cfg.domain} =
          {
            locations = {
              "/".proxyPass = "http://localhost:${toString cfg.wsgi-port}";
              "/static/".alias = cfg.env.STATIC_ROOT;
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
            name = application;
            ensureDBOwnership = true;
          }
        ];
        ensureDatabases = [ application ];
      };
    };

    users.users.${application} = {
      isSystemUser = true;
      group = application;
    };
    users.groups.${application} = { };

    systemd.services =
      let
        defaults = {
          path = [
            pythonEnv
            wstManageScript
            pkgs.nix-eval-jobs
          ];
          serviceConfig = {
            User = application;
            WorkingDirectory = "${cfg.stateDir}/${application}";
            StateDirectory = application;
            RuntimeDirectory = application;
            LogsDirectory = application;
            LoadCredential = credentials;
          };
          inherit environment;
        };
      in
      mapAttrs (_: recursiveUpdate defaults) {
        "${application}-server" = {
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
          };
          preStart = ''
            # Auto-migrate on first run or if the package has changed
            versionFile="${cfg.stateDir}/${application}/package-version"
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

        "${application}-worker" = {
          description = "Web security tracker - background job processor";
          after = [
            "network.target"
            "postgresql.service"
            "${application}-server.service"
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

        "${application}-fetch-all-channels" = {
          description = "Web security tracker - refresh all channels and start nixpkgs evaluation";

          after = [
            "network.target"
            "postgresql.service"
            "${application}-server.service"
          ];
          requires = [ "postgresql.service" ];

          serviceConfig.Type = "oneshot";

          script = ''
            wst-manage fetch_all_channels
          '';

          # Ideally, start at whatever night means.
          startAt = "*-*-* 04:00:00";
        };

        "${application}-delta" = {
          description = "Web security tracker catch up with CVEs";
          after = [
            "network.target"
            "postgresql.service"
            "${application}-server.service"
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
