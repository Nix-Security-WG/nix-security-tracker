# A module to ease setting up a local PostgreSQL database to start with development.
# This lets you specify your local unix user as which you run the tracker and
# gives it full access to the nix-security-tracker database user.

{
  config,
  lib,
  ...
}:
let
  cfg = config.nix-security-tracker-dev-environment;
in
{

  options.nix-security-tracker-dev-environment = {
    enable = lib.mkEnableOption (lib.mdDoc "development environment for nix-security-tracker");
    user = lib.mkOption {
      type = lib.types.str;
      description = "Unix user that runs the nix-security-tracker to connect to the database";
    };
  };

  config = lib.mkIf cfg.enable {
    services.postgresql = {
      enable = true;
      ensureDatabases = [ "nix-security-tracker" ];
      ensureUsers = [
        {
          name = "nix-security-tracker";
          ensureDBOwnership = true;
          ensureClauses.createdb = true;
        }
      ];
      identMap = ''
        map-nix-security-tracker ${cfg.user} nix-security-tracker
      '';
      authentication = ''
        local all nix-security-tracker ident map=map-nix-security-tracker
      '';
    };
  };
}
