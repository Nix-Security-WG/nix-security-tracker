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
    ./kurisu-proxy.nix
    ./sectracker.nix
    ./raito-datacenter.nix
    ./s3-revproxy
  ];

  # Propagate `inputs` everywhere in our NixOS module signatures.
  _module.args.inputs = {
    inherit sources;
  };

  zramSwap.enable = true;
  security.sudo.wheelNeedsPassword = false;

  networking.hostName = "staging";

  services.openssh.enable = true;
  services.qemuGuest.enable = true;

  users.mutableUsers = false;
  users.users.root = {
    openssh.authorizedKeys.keyFiles =
      with lib;
      map (n: ./keys/${n}) (attrNames (builtins.readDir ./keys));
  };

  infra.hardware.raito-vm = {
    enable = true;
    networking.nat-lan-mac = "AE:93:5E:21:FA:C1";
    networking.wan = {
      address = "2001:bc8:38ee:100:a862:3eff:fe8a:54c8/56";
      mac = "AA:62:3E:8A:54:C8";
    };
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

  system.stateVersion = "24.05";
}
