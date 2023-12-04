{ pkgs, wstModule, defaultTimeout ? 60 * 1024 }: {
  mkVMTest = { name, machine ? { }, testScript ? "", ... }:
    pkgs.nixosTest {
      inherit name;
      globalTimeout = defaultTimeout;

      testScript = ''
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("web-security-tracker-server.service")
        machine.succeed("curl http://127.0.0.1:8000")
        ${testScript}
      '';

      nodes.machine = { ... }: {
        imports = [ wstModule machine ];

        services.web-security-tracker = { enable = true; };
      };
    };
}

