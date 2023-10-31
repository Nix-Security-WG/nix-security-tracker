let
  sources = import ./npins;
  pkgs = import sources.nixpkgs { };

  # Select current python version
  python3 = pkgs.python311;

  local = import ./pkgs { inherit pkgs python3; };

  pre-commit-check = (import sources.pre-commit-hooks).run {
    src = ./.;

    hooks = {
      # Nix setup
      nixfmt.enable = true;
      statix.enable = true;
      deadnix.enable = true;

      # Python setup
      ruff.enable = true;
      black.enable = true;
      pyright.enable = true;

      # HTML setup
      html-tidy.enable = true;

      # Global setup
      prettier.enable = true;
      commitizen.enable = true;
    };
  };

  pyEnv = python3.withPackages (ps:
    (with local.pythonPackages;
      [
        # Local Python packages
        pyngo
      ]) ++ (with ps; [
        # Nix python packages
        django-types
        django_4
        requests
      ]));

in pkgs.mkShell {
  packages = [ pyEnv ] ++ (with pkgs; [ commitizen ]);

  shellHook = ''
    ${pre-commit-check.shellHook}
  '';
}
