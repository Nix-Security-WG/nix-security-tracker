{
  config,
  lib,
  pkgs,
  ...
}:
let
  sectracker = import ../. { };
  secretsPath = "/etc/secrets";
  secretsGuestPath = "/mnt/secrets";
  secretsHostPath = toString ../.credentials;
  cfg = config.containers.nix-security-tracker;
in
{
  /**
    Run the service in a container, without optimisations.
    It will be accessible at http://172.31.100.1

    The container can be managed at runtime with [`nixos-container`](https://nixos.org/manual/nixos/unstable/#sec-imperative-containers).
  */
  users.users.web-security-tracker = {
    isSystemUser = true;
    group = "web-security-tracker";
  };
  users.groups.web-security-tracker = { };
  containers.nix-security-tracker = {
    autoStart = true;
    privateNetwork = true;
    # local address range that is unlikely to collide with something else
    hostAddress = "172.31.100.1";
    localAddress = "172.31.100.2";
    forwardPorts = [
      {
        containerPort = cfg.config.services.nginx.defaultHTTPListenPort;
        hostPort = config.services.nginx.defaultHTTPListenPort;
        protocol = "tcp";
      }
    ];
    bindMounts.${secretsGuestPath} = {
      hostPath = toString secretsHostPath;
      isReadOnly = true;
    };

    config =
      { ... }:
      {
        system.stateVersion = "24.11";
        users.mutableUsers = false;
        users.allowNoPasswordLogin = true;
        # work around that the credential files are owned by a user on the host
        # which almost certainly won't be the same as the user under which the service runs
        boot.postBootCommands = ''
          cp -r ${secretsGuestPath} ${secretsPath}
          chown web-security-tracker ${secretsPath}
        '';
        networking.firewall.allowedTCPPorts = map (forward: forward.containerPort) (
          lib.filter (forward: forward.protocol == "tcp") cfg.forwardPorts
        );
        nixpkgs = {
          inherit (sectracker) pkgs overlays;
        };
        imports = [
          sectracker.module
        ];
        services.web-security-tracker = {
          enable = true;
          domain = "sectracker.local";
          production = false;
          settings = {
            DEBUG = true;
            CSRF_TRUSTED_ORIGINS = lib.mkAfter [ "http://${cfg.hostAddress}" ];
          };
          secrets =
            with builtins;
            mapAttrs (name: _: "${secretsGuestPath}/${name}") (readDir secretsHostPath);
        };
      };
  };
}
