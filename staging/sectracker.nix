{ pkgs, lib, ... }:
let
  sectracker = import ../. { inherit pkgs; };
  obfuscate = email:
    lib.strings.concatStrings
    (lib.reverseList (lib.strings.stringToCharacters email));
in {
  imports = [ sectracker.module ];

  nixpkgs.overlays = sectracker.overlays;
  services.nginx.enable = true;
  security.acme.acceptTerms = true;
  security.acme.defaults.email = obfuscate "zyx.afhal@emca-cilbup";
  networking.firewall.allowedTCPPorts = [ 443 ];
  services.web-security-tracker = {
    enable = true;
    domain = "sectracker.nixpkgs.lahfa.xyz";
    secrets = {
      SECRET_KEY = "/etc/secrets/django-secret-key";
      GH_CLIENT_ID = "/etc/secrets/gh-client";
      GH_SECRET = "/etc/secrets/gh-secret";
    };
  };
}
