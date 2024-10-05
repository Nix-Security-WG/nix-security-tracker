{
  config,
  pkgs,
  lib,
  ...
}:
let
  sectracker = import ../. { inherit pkgs; };
  obfuscate =
    email: lib.strings.concatStrings (lib.reverseList (lib.strings.stringToCharacters email));
in
{
  imports = [ sectracker.module ];

  nixpkgs.overlays = sectracker.overlays;
  services.nginx = {
    enable = true;
    recommendedTlsSettings = true;
    recommendedProxySettings = true;
    recommendedGzipSettings = true;
    recommendedOptimisation = true;
  };
  services.postgresql = {
    enableJIT = true;
    settings = {
      # DB Version: 15
      # OS Type: linux
      # DB Type: dw
      # Total Memory (RAM): 16 GB
      # CPUs num: 8
      # Data Storage: hdd

      max_connections = 40;
      shared_buffers = "4GB";
      effective_cache_size = "12GB";
      maintenance_work_mem = "2GB";
      checkpoint_completion_target = "0.9";
      wal_buffers = "16MB";
      default_statistics_target = "500";
      random_page_cost = "4";
      effective_io_concurrency = "2";
      work_mem = "13107kB";
      huge_pages = "off";
      min_wal_size = "4GB";
      max_wal_size = "16GB";
      max_worker_processes = "8";
      max_parallel_workers_per_gather = "4";
      max_parallel_workers = "8";
      max_parallel_maintenance_workers = "4";
    };
  };
  security.acme.acceptTerms = true;
  security.acme.defaults.email = obfuscate "zyx.afhal@emca-cilbup";
  networking.firewall.allowedTCPPorts = [
    80
    443
  ];
  services.web-security-tracker = {
    enable = true;
    domain = "sectracker.nixpkgs.lahfa.xyz";
    settings.DEBUG = true;
    secrets = {
      SECRET_KEY = config.age.secrets.django-secret-key.path;
      GH_CLIENT_ID = config.age.secrets.gh-client.path;
      GH_SECRET = config.age.secrets.gh-secret.path;
      GH_WEBHOOK_SECRET = config.age.secrets.gh-webhook-secret.path;
      GH_APP_PRIVATE_KEY = config.age.secrets.gh-app-private-key.path;
      GH_APP_INSTALLATION_ID = config.age.secrets.gh-app-installation-id.path;
      GLITCHTIP_DSN = config.age.secrets.glitchtip-dsn.path;
    };
    maxJobProcessors = 3;
  };

  age.secrets = {
    django-secret-key.file = ./secrets/django-secret-key.age;
    gh-client.file = ./secrets/gh-client.age;
    gh-secret.file = ./secrets/gh-secret.age;
    gh-webhook-secret.file = ./secrets/gh-webhook-secret.age;
    gh-app-private-key.file = ./secrets/dev-nixpkgs-security-tracker.2024-10-04.private-key.pem.age;
    gh-app-installation-id.file = ./secrets/gh-app-installation-id.age;
    glitchtip-dsn.file = ./secrets/glitchtip-dsn.age;
  };
}
