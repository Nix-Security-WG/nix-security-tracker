{ pkgs, wstModule }:
let
  nixos-lib = import (pkgs.path + "/nixos/lib") { };
in
{
  mkVMTest =
    test:
    (nixos-lib.runTest {
      # speed-up evaluation
      hostPkgs = pkgs;
      globalTimeout = 60 * 1024;
      testScript = pkgs.lib.mkBefore ''
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("web-security-tracker-server.service")
        machine.wait_for_unit("web-security-tracker-worker.service")
        machine.wait_for_open_port(8000)
        machine.succeed("curl --fail -H 'Host: example.org' http://127.0.0.1:80/static/style.css")
        machine.succeed("wst-manage test")
      '';
      defaults = {
        nixpkgs.pkgs = pkgs;
        documentation.enable = pkgs.lib.mkDefault false;

        virtualisation = {
          memorySize = 2048;
          cores = 2; # github runner comes with 2 cores
        };

        imports = [ wstModule ];
        services.web-security-tracker = {
          enable = true;
          production = false;
          domain = "example.org";
          secrets = {
            SECRET_KEY = pkgs.writeText "secret.key" "aaaaaaaaaaaaaaaaaaaa";
            GH_CLIENT_ID = pkgs.writeText "gh_client" "bonjour";
            GH_SECRET = pkgs.writeText "gh_secret" "secret";
          };
        };
      };
      imports = [ test ];
    }).config.result;
}
