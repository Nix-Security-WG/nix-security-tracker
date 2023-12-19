{
  sources ? import ./npins,
  overlay ? import ./nix/overlay.nix,
  pkgs ? import sources.nixpkgs { overlays = [ overlay ]; },
}:
let
  self = rec {
    inherit (pkgs) python3;
    localPythonPackages = import ./pkgs { inherit pkgs python3; };

    # For exports.
    overlays = [ overlay ];
    package = pkgs.web-security-tracker;
    module = import ./nix/web-security-tracker.nix;

    pre-commit-check = pkgs.pre-commit-hooks {
      src = ./.;

      settings.statix.ignore = [ "staging" ];

      hooks =
        let
          pythonExcludes = [
            "/migrations/" # auto-generated code
          ];
        in
        {
          # Nix setup
          nixfmt = {
            enable = true;
            entry = pkgs.lib.mkForce "${pkgs.lib.getExe pkgs.nixfmt}";
          };
          statix.enable = true;
          deadnix.enable = true;

          # Python setup
          ruff = {
            enable = true;
            excludes = pythonExcludes;
          };
          ruff-format = {
            enable = true;
            name = "Format python code with ruff";
            types = [
              "text"
              "python"
            ];
            entry = "${pkgs.lib.getExe pkgs.ruff} format";
            excludes = pythonExcludes;
          };

          pyright =
            let
              pyEnv = pkgs.python3.withPackages (_: pkgs.web-security-tracker.propagatedBuildInputs);
              wrappedPyright = pkgs.runCommand "pyright" { nativeBuildInputs = [ pkgs.makeWrapper ]; } ''
                makeWrapper ${pkgs.pyright}/bin/pyright $out \
                  --set PYTHONPATH ${pyEnv}/${pyEnv.sitePackages} \
                  --prefix PATH : ${pyEnv}/bin \
                  --set PYTHONHOME ${pyEnv}
              '';
            in
            {
              enable = true;
              entry = pkgs.lib.mkForce (builtins.toString wrappedPyright);
              excludes = pythonExcludes;
            };

          # Global setup
          prettier = {
            enable = true;
            excludes = [
              "\\.min.css$"
              "\\.html$"
            ];
          };
          commitizen.enable = true;
        };
    };

    shell =
      let
        manage = pkgs.writeScriptBin "manage" ''
          ${python3}/bin/python ${toString ./src/website/manage.py} $@
        '';
      in
      pkgs.mkShell {
        DATA_CACHE_DIRECTORY = toString ./. + "/.data_cache";

        packages = [
          manage
          package
          pkgs.nix-eval-jobs
          pkgs.commitizen
          pkgs.npins
          pkgs.nixfmt
        ];

        shellHook = ''
          ${pre-commit-check.shellHook}

          mkdir -p .credentials
          export DATABASE_URL=postgres:///nix-security-tracker
          export CREDENTIALS_DIRECTORY=${builtins.toString ./.credentials}
        '';
      };

    tests = import ./nix/tests/vm-basic.nix {
      inherit pkgs;
      wstModule = module;
    };
  };
in
self // self.tests
