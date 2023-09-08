let
  sources = import ./npins;
  pkgs = import sources.nixpkgs { };

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

in pkgs.mkShell {
  packages = with pkgs; [ commitizen ];

  shellHook = ''
    ${pre-commit-check.shellHook}
  '';
}
