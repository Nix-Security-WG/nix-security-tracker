{
  config,
  pkgs,
  lib,
  ...
}:
let
  cfg = config.services.s3-revproxy;
  settingsGenerator = pkgs.formats.yaml { };
  # Needs to be in a directory, so we might as well implement autoreload, why not!
  configFile = settingsGenerator.generate "config.yaml" cfg.settings;

  inherit (lib) types;
in
{
  options.services.s3-revproxy = {
    enable = lib.mkEnableOption "s3 reverse proxy";
    package = lib.mkPackageOption pkgs "s3-revproxy" { };
    settings = lib.mkOption {
      default = { };
      type = settingsGenerator.type;
      description = ''
        Settings to use for the service. See the documentation at https://oxyno-zeta.github.io/s3-proxy/configuration/structure/
      '';
    };

    environmentFile = lib.mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        Environment file to use for s3-revproxy.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    environment.etc."s3-revproxy/config.yaml".source = configFile;
    systemd.services.s3-revproxy = {
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} --config /etc/s3-revproxy";

        DynamicUser = true;
        CapabilityBoundingSet = "";
        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateUsers = true;
        PrivateDevices = true;
        ProtectHome = true;
        ProtectClock = true;
        ProtectProc = "noaccess";
        ProcSubset = "pid";
        UMask = "0077";
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectControlGroups = true;
        ProtectHostname = true;
        RestrictSUIDSGID = true;
        RestrictRealtime = true;
        RestrictNamespaces = true;
        LockPersonality = true;
        RemoveIPC = true;
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
        ];
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
        ];
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";

        EnvironmentFile = lib.optionals (cfg.environmentFile != null) [ cfg.environmentFile ];
      };
    };
  };
}
