{ pkgs, ... }:
let sectracker = import ../. { inherit pkgs; };
in {
  imports = [ sectracker.module ];

  nixpkgs.overlays = sectracker.overlays;
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
