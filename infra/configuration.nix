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

  boot.loader.grub.enable = true;
  boot.loader.grub.device = "/dev/sda";
  boot.initrd.availableKernelModules = [
    "ahci"
    "xhci_pci"
    "virtio_pci"
    "virtio_scsi"
    "sd_mod"
    "sr_mod"
    "ext4"
  ];

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

  services.openssh.enable = true;
  services.qemuGuest.enable = true;

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

  services.prometheus.exporters.node = {
    enable = true;
  };

  system.stateVersion = "24.05";
}
