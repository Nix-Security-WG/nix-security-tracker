{ pkgs, lib, ... }:
let
  sources = import ../npins;
in
{
  imports = [
    "${sources.agenix}/modules/age.nix"
  ];

  boot = {
    loader.grub = {
      enable = true;
      device = "/dev/sda";
    };
    initrd.availableKernelModules = [
      "ahci"
      "xhci_pci"
      "virtio_pci"
      "virtio_scsi"
      "sd_mod"
      "sr_mod"
      "ext4"
    ];
  };

  nix.settings.experimental-features = [
    "nix-command"
    "flakes"
  ];

  # Propagate `inputs` everywhere in our NixOS module signatures.
  _module.args.inputs = {
    inherit sources;
  };

  zramSwap.enable = true;
  security.sudo.wheelNeedsPassword = false;

  services = {
    openssh = {
      enable = true;
      settings.PasswordAuthentication = false;
    };
    qemuGuest.enable = true;
  };

  users.mutableUsers = false;
  users.users.root = {
    openssh.authorizedKeys.keyFiles =
      with lib;
      map (n: ./keys/${n}) (attrNames (builtins.readDir ./keys));
    # We're using both keys and keyFiles here in order to keep some alignment
    # with github:nixos/infra
    openssh.authorizedKeys.keys = (import "${sources.infra}/ssh-keys.nix").infra;
  };

  environment.systemPackages = with pkgs; [
    curl
    file
    git
    htop
    lsof
    nano
    openssl
    pciutils
    pv
    tmux
    tree
    unar
    vim_configurable
    wget
    zip
  ];

  # Lifted from https://github.com/NixOS/nixos-wiki-infra/blob/ac9dfe854f748bf8acedf394750d404aaa8dd075/targets/nixos-wiki.nixos.org/configuration.nix#L40
  # and https://wiki.nixos.org/wiki/Install_NixOS_on_Hetzner_Cloud#Network_configuration
  systemd.network.enable = true;

  services.prometheus.exporters.node = {
    enable = true;
    openFirewall = true;
  };

  services.prometheus.exporters.postgres = {
    enable = true;
    openFirewall = true;
  };

  services.prometheus.exporters.sql = {
    enable = true;
    openFirewall = true;
    configuration.jobs.sectracker = {
      queries = {
        users = {
          query = "select count(*) from auth_user;";
          values = [ "count" ];
        };
        delta = {
          query = "select extract(EPOCH from timestamp) AS unix_timestamp from shared_cveingestion where delta = 't' order by timestamp desc limit 1;";
          values = [ "unix_timestamp" ];
        };
        matching = {
          query = "select extract(EPOCH from created_at) AS unix_timestamp from shared_cvederivationclusterproposal order by created_at desc limit 1;";
          values = [ "unix_timestamp" ];
        };
        cves = {
          query = "select count(*) from shared_cverecord where state='PUBLISHED';";
          values = [ "count" ];
        };
        derivations = {
          query = "select count(*) from shared_nixderivation;";
          values = [ "count" ];
        };
        evaluations = {
          query = "select count(*) from shared_nixevaluation;";
          values = [ "count" ];
        };
      };
      connections = [ "postgres://postgres@/web-security-tracker?host=/run/postgresql" ];
      interval = "1h";
    };
  };

  system.stateVersion = "24.05";
}
