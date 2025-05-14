{ pkgs, lib, ... }:
let
  # Note: this might be surprising not to reuse the parent npins/ directory.
  # The rationale is that the staging environment's sources are decorrelated from the development's sources.
  # Sources here are managed on a different lifecycle and have different acceptance tests than the development.
  # Also, the focus in the staging environment is a secure deployment, which trumps over dirty hacks.
  sources = import ./npins;
in
{
  imports = [
    "${sources.agenix}/modules/age.nix"
    ./sectracker.nix
  ];
  networking.hostName = "sectracker";

  fileSystems."/" = {
    device = "/dev/disk/by-label/nixos";
    fsType = "ext4";
  };
  fileSystems."/boot" = {
    device = "/dev/disk/by-label/boot";
    fsType = "ext4";
  };
  swapDevices = [ { device = "/dev/disk/by-label/swap"; } ];

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
    # We're using both keys and keyFiles here in order to keep some alignment with github:nixos/infra since ssh-keys.nix is copy pasted from that repo.
    openssh.authorizedKeys.keys = with import ./ssh-keys.nix; infra;
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
  systemd.network.networks."10-wan" = {
    matchConfig.MACAddress = "96:00:03:d9:7c:85";
    address = [
      "188.245.41.195/32"
      "2a01:4f8:1c1b:b87b::1/64"
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
      };
      connections = [ "postgres://postgres@/${application}?host=/run/postgresql" ];
      interval = "1h";
    };
  };

  system.stateVersion = "24.05";
}
