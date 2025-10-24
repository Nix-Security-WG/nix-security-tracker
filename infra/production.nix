{
  config,
  pkgs,
  ...
}:
let
  sectracker = import ../. { inherit pkgs; };
in
{
  imports = [
    sectracker.module
    ./configuration.nix
  ];
  networking.hostName = "sectracker";

  fileSystems."/" = {
    device = "/dev/disk/by-partlabel/disk-main-root";
    fsType = "ext4";
  };
  fileSystems."/boot" = {
    device = "/dev/disk/by-partlabel/disk-main-ESP";
    fsType = "vfat";
  };

  systemd.network.networks."10-wan" = {
    matchConfig.MACAddress = "96:00:04:64:8e:77";
    address = [
      "91.99.31.214/32"
      "2a01:4f8:1c1b:6921::1/64"
    ];
    routes = [
      # create default routes for both IPv6 and IPv4
      { Gateway = "fe80::1"; }
      # or when the gateway is not on the same network
      {
        Gateway = "172.31.1.1";
        GatewayOnLink = true;
      }
    ];
    # make the routes on this interface a dependency for network-online.target
    linkConfig.RequiredForOnline = "routable";
  };

  nixpkgs.overlays = sectracker.overlays;
  services = {
    nginx = {
      enable = true;
      recommendedTlsSettings = true;
      recommendedProxySettings = true;
      recommendedGzipSettings = true;
      recommendedOptimisation = true;
    };
    postgresql = {
      enableJIT = true;
      settings = {
        # Derived using PGTune for an 8 core, 16GB RAM host
        max_connections = 200;
        shared_buffers = "4GB";
        effective_cache_size = "12GB";
        maintenance_work_mem = "1GB";
        checkpoint_completion_target = "0.9";
        wal_buffers = "16MB";
        default_statistics_target = "100";
        random_page_cost = "1.1";
        effective_io_concurrency = "200";
        work_mem = "5242kB";
        huge_pages = "off";
        min_wal_size = "1GB";
        max_wal_size = "4GB";
        max_worker_processes = "8";
        max_parallel_workers_per_gather = "4";
        max_parallel_workers = "8";
        max_parallel_maintenance_workers = "4";
      };
      authentication = ''
        local all all trust
      '';
    };
  };
  security.acme.acceptTerms = true;
  security.acme.defaults.email = "infra@nixos.org";
  networking.firewall.allowedTCPPorts = [
    80
    443
  ];
  services.web-security-tracker = {
    enable = true;
    production = true;
    domain = "tracker.security.nixos.org";
    env = {
      SYNC_GITHUB_STATE_AT_STARTUP = true;
      # set to `true` when going live
      GH_ISSUES_PING_MAINTAINERS = false;
      GH_ORGANIZATION = "nixos";
      GH_ISSUES_REPO = "nixpkgs";
      GH_SECURITY_TEAM = "security";
      GH_COMMITTERS_TEAM = "nixpkgs-committers";
      GH_ISSUES_COMMITTERS_ONLY = true;
    };

    secrets = {
      SECRET_KEY = config.age.secrets.django-secret-key.path;
      GH_CLIENT_ID = config.age.secrets.gh-client.path;
      GH_SECRET = config.age.secrets.gh-secret.path;
      GH_WEBHOOK_SECRET = config.age.secrets.gh-webhook-secret.path;
      GH_APP_PRIVATE_KEY = config.age.secrets.gh-app-private-key.path;
      GH_APP_INSTALLATION_ID = config.age.secrets.gh-app-installation-id.path;
    };
    maxJobProcessors = 1;
  };

  age.secrets = {
    django-secret-key.file = ./secrets/django-secret-key.age;
    gh-client.file = ./secrets/gh-client.age;
    gh-secret.file = ./secrets/gh-secret.age;
    gh-webhook-secret.file = ./secrets/gh-webhook-secret.age;
    gh-app-private-key.file = ./secrets/nixpkgs-security-tracker.private-key.pem.age;
    gh-app-installation-id.file = ./secrets/gh-app-installation-id.age;
  };

  nix.optimise.automatic = true;
}
