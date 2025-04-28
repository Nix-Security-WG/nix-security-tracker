{ lib, pkgs }:
let
  # TODO: specify project/service name globally
  application = "web-security-tracker";
  defaults = {
    documentation.enable = lib.mkDefault false;

    virtualisation = {
      memorySize = 2048;
      cores = 2;
    };

    services.${application} = {
      enable = true;
      production = false;
      restart = "no"; # fail fast
      domain = "example.org";
      env = {
        SYNC_GITHUB_STATE_AT_STARTUP = false;
        GH_ISSUES_PING_MAINTAINERS = true;
        DEBUG = true;
      };
      secrets = {
        SECRET_KEY = pkgs.writeText "SECRET_KEY" "secret";
        GH_CLIENT_ID = pkgs.writeText "gh_client" "bonjour";
        GH_SECRET = pkgs.writeText "gh_secret" "secret";
        GH_WEBHOOK_SECRET = pkgs.writeText "gh_secret" "webhook-secret";
      };
    };
  };
in
lib.mapAttrs (name: test: pkgs.testers.runNixOSTest (test // { inherit name defaults; })) {
  basic = {
    nodes.server = _: { imports = [ ./web-security-tracker.nix ]; };
    testScript = ''
      server.wait_for_unit("${application}-server.service")
      server.wait_for_unit("${application}-worker.service")

      with subtest("Django application tests"):
        # https://docs.djangoproject.com/en/5.0/topics/testing/overview/
        server.succeed("wst-manage test shared")
        server.succeed("wst-manage test webview")

      with subtest("Check that stylesheet is served"):
        machine.succeed("curl --fail -H 'Host: example.org' http://localhost/static/style.css")

      with subtest("Check that admin interface is served"):
        server.succeed("curl --fail -L -H 'Host: example.org' http://localhost/admin")
    '';
  };
}
