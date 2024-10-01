{ pkgs, lib, ... }:
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
      SECRET_KEY = "/etc/secrets/django-secret-key";
      GH_CLIENT_ID = "/etc/secrets/gh-client";
      GH_SECRET = "/etc/secrets/gh-secret";
      GH_WEBHOOK_SECRET = "/etc/secrets/gh-webhook-secret";
    };
    maxJobProcessors = 3;
  };
}
