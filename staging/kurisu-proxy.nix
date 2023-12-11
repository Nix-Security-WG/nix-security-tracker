# This enable the IPv4 support for the logs in NGINX
# even though the machine is IPv6-only
# For more information, read https://ryan.lahfa.xyz/en/one-trick-to-build-a-tls-enabled-ipv6-only-empire-with-only-one-legacy-ip.html
{ lib, ... }:
let
  withFirewall = true;
  allowedUpstream = "2001:bc8:38ee:99::1/128";
in
{
  services.nginx = {
    # IPv6-only server
    defaultListen = [
      {
        addr = "[::0]";
        proxyProtocol = true;
        port = 444;
        ssl = true;
      }
      {
        addr = "[::0]";
        port = 443;
        ssl = true;
      }
      {
        addr = "[::0]";
        port = 80;
        ssl = false;
      }
      # Private networking
      {
        addr = "127.0.0.1";
        port = 80;
        ssl = false;
      }
      {
        addr = "[::1]";
        port = 80;
        ssl = false;
      }
    ];

    appendHttpConfig = ''
      # Kurisu node
      set_real_ip_from ${allowedUpstream};
      real_ip_header proxy_protocol;
    '';
  };

  # Move to nftables if firewall is enabled.
  networking.nftables.enable = withFirewall;
  networking.firewall.allowedTCPPorts = lib.mkIf (!withFirewall) [ 444 ];
  networking.firewall.extraInputRules = lib.mkIf withFirewall ''
    ip6 saddr ${allowedUpstream} tcp dport 444 accept
  '';
}
