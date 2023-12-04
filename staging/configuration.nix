{ pkgs, ... }: {
  imports =
    [ ./hardware-configuration.nix ./kurisu-proxy.nix ./sectracker.nix ];

  nixpkgs.config.allowUnfree = true;

  zramSwap.enable = true;
  services.logind.lidSwitch = "ignore";

  security.sudo.wheelNeedsPassword = false;

  networking.hostName = "staging";

  services.openssh.enable = true;
  services.qemuGuest.enable = true;

  users.mutableUsers = false;
  users.users.root = { openssh.authorizedKeys.keyFiles = [ ./raito.keys ]; };

  # IPv4 connectivity.
  networking.interfaces.enp6s19.useDHCP = true;
  # Fixed IPv6.
  networking.interfaces.enp6s18.ipv6.addresses = [{
    address = "2001:bc8:38ee:100:a862:3eff:fe8a:54c8";
    prefixLength = 56;
  }];

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

  system.stateVersion = "24.05";
}
