{ pkgs, wstModule, defaultTimeout ? 60 * 1024 }: {
  mkVMTest = { name, machine ? { }, testScript ? "", ... }:
    pkgs.nixosTest {
      inherit name;
      globalTimeout = defaultTimeout;

      testScript = ''
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("web-security-tracker-server.service")
        machine.wait_for_open_port(8000)
        machine.succeed("curl http://127.0.0.1:8000")
        ${testScript}
      '';

      nodes.machine = { ... }: {
        imports = [ wstModule machine ];

        services.web-security-tracker = {
          enable = true;
          secrets = {
            SECRET_KEY = pkgs.writeText "secret.key" "aaaaaaaaaaaaaaaaaaaa";
            GH_CLIENT_ID = pkgs.writeText "gh_client" "bonjour";
            GH_SECRET = pkgs.writeText "gh_secret" "secret";
          };
        };
      };
    };
}

