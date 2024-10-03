# My personal defaults for any VM I host in my infrastructure.
{ lib, config, ... }:
let
  cfg = config.infra.hardware.raito-vm;
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    ;
in
{
  options.infra.hardware.raito-vm = {
    enable = mkEnableOption "Raito's VM hardware defaults";

    networking = {
      nat-lan-mac = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "MAC address for the NAT-LAN interface, autoconfigured via DHCP";
      };

      wan = {
        address = mkOption {
          type = types.str;
          description = "IPv6 prefix for WAN. Ask Raito when in doubt.";
        };
        mac = mkOption {
          type = types.str;
          description = "MAC address for the WAN interface.";
        };
      };
    };
  };

  config = mkIf cfg.enable {
    services.qemuGuest.enable = true;
    systemd.network.enable = true;
    networking.useDHCP = lib.mkDefault false;

    systemd.network.networks."10-nat-lan" = {
      matchConfig.Name = "nat-lan";
      linkConfig.RequiredForOnline = true;
      DHCP = "yes";
    };

    systemd.network.links."10-nat-lan" = {
      matchConfig.MACAddress = cfg.networking.nat-lan-mac;
      linkConfig.Name = "nat-lan";
    };

    systemd.network.networks."10-wan" = {
      matchConfig.Name = "wan";
      linkConfig.RequiredForOnline = true;
      networkConfig.Address = [ cfg.networking.wan.address ];
    };

    systemd.network.links."10-wan" = {
      matchConfig.MACAddress = cfg.networking.wan.mac;
      linkConfig.Name = "wan";
    };

    boot.loader.systemd-boot.enable = true;

    boot.initrd.kernelModules = [
      "virtio_balloon"
      "virtio_console"
      "virtio_rng"
    ];

    boot.initrd.availableKernelModules = [
      "9p"
      "9pnet_virtio"
      "ata_piix"
      "nvme"
      "sr_mod"
      "uhci_hcd"
      "virtio_blk"
      "virtio_mmio"
      "virtio_net"
      "virtio_pci"
      "virtio_scsi"
      "xhci_pci"
    ];

    fileSystems."/boot" = {
      device = "/dev/disk/by-label/BOOT";
      fsType = "vfat";
    };

    swapDevices = [ { device = "/dev/disk/by-label/swap"; } ];

    boot.initrd.luks.devices.root = {
      device = "/dev/disk/by-label/root";

      # WARNING: Leaks some metadata, see cryptsetup man page for --allow-discards.
      # allowDiscards = true;

      # Set your own key with:
      # cryptsetup luksChangeKey /dev/disk/by-label/root --key-file=/dev/zero --keyfile-size=1
      # You can then delete the rest of this block.
      keyFile = "/dev/zero";
      keyFileSize = 1;

      fallbackToPassword = true;
    };

    fileSystems."/" = {
      device = "/dev/mapper/root";
      fsType = "btrfs";
      options = [
        "subvol=root"
        "compress=zstd"
        "noatime"
      ];
    };

    fileSystems."/home" = {
      device = "/dev/mapper/root";
      fsType = "btrfs";
      options = [
        "subvol=home"
        "compress=zstd"
        "noatime"
      ];
    };

    fileSystems."/nix" = {
      device = "/dev/mapper/root";
      fsType = "btrfs";
      options = [
        "subvol=nix"
        "compress=zstd"
        "noatime"
      ];
      neededForBoot = true;
    };

    fileSystems."/etc" = {
      device = "/dev/mapper/root";
      fsType = "btrfs";
      options = [
        "subvol=etc"
        "compress=zstd"
        "noatime"
      ];
    };

    fileSystems."/var" = {
      device = "/dev/mapper/root";
      fsType = "btrfs";
      options = [
        "subvol=var"
        "compress=zstd"
        "noatime"
      ];
      neededForBoot = true;
    };
  };
}
