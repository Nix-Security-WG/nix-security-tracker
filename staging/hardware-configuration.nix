_: {
  boot.loader.systemd-boot.enable = true;

  boot.initrd.kernelModules =
    [ "virtio_balloon" "virtio_console" "virtio_rng" ];

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

  swapDevices = [{ device = "/dev/disk/by-label/swap"; }];

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
    options = [ "subvol=root" "compress=zstd" "noatime" ];
  };

  fileSystems."/home" = {
    device = "/dev/mapper/root";
    fsType = "btrfs";
    options = [ "subvol=home" "compress=zstd" "noatime" ];
  };

  fileSystems."/nix" = {
    device = "/dev/mapper/root";
    fsType = "btrfs";
    options = [ "subvol=nix" "compress=zstd" "noatime" ];
    neededForBoot = true;
  };

  fileSystems."/etc" = {
    device = "/dev/mapper/root";
    fsType = "btrfs";
    options = [ "subvol=etc" "compress=zstd" "noatime" ];
  };

  fileSystems."/var" = {
    device = "/dev/mapper/root";
    fsType = "btrfs";
    options = [ "subvol=var" "compress=zstd" "noatime" ];
    neededForBoot = true;
  };

}
