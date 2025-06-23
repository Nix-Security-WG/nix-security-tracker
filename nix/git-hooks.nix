{ lib, pkgs, ... }:
{
  src = ../.;
  default_stages = [
    "manual"
    "pre-push"
  ];
  hooks =
    let
      # XXX(@fricklerhandwerk): these need to be tacked onto the `pre-commit` configuration file,
      # which seems to ignore per-tool configuration
      excludes = [
        "\\.min.css$"
        "\\.html$"
        "npins"
        "migrations"
      ];
      # XXX(@fricklerhandwerk): due to implementation details of pre-commit.nix this is
      # required for running in CI when building the hooks as a derivation
      stages = [ "manual" ];
    in
    lib.mapAttrs (_: v: v // { inherit excludes stages; }) {
      # Nix setup
      nixfmt-rfc-style.enable = true;
      statix = {
        enable = true;
        # XXX(@fricklerhandwerk): statix for some reason needs its own ignores repeated...
        settings.ignore = excludes;
      };
      deadnix.enable = true;

      # Python setup
      ruff.enable = true;
      ruff-format = {
        enable = true;
        types = [
          "text"
          "python"
        ];

        entry = "${pkgs.lib.getExe pkgs.ruff} format";
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
          entry = lib.mkForce (builtins.toString wrappedPyright);
        };

      # Global setup
      prettier = {
        enable = true;
      };
    };
}
