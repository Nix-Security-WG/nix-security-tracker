final: prev:
let
  inherit (final) python3;
  extraPython3Packages = import ../pkgs {
    pkgs = prev;
    inherit python3;
  };
  sources = import ../npins;
in
{
  python3 = prev.lib.attrsets.recursiveUpdate prev.python3 { pkgs = extraPython3Packages; };

  # RFC 166
  nixfmt = (import sources.nixfmt).default;

  # go through the motions to make a flake-incompat project use the build
  # inputs we want
  pre-commit-hooks = final.callPackage "${sources.pre-commit-hooks}/nix/run.nix" {
    tools = import "${sources.pre-commit-hooks}/nix/call-tools.nix" final;
    gitignore-nix-src = sources.gitignore;
    isFlakes = false;
  };

  web-security-tracker = python3.pkgs.buildPythonPackage rec {
    pname = "web-security-tracker";
    version = "0.0.1";
    pyproject = true;

    src = final.nix-gitignore.gitignoreSourcePure [ ../.gitignore ] ../src/website;

    propagatedBuildInputs = with python3.pkgs; [
      # Nix python packages
      dataclass-wizard
      dj-database-url
      django-allauth
      django-compressor
      django-debug-toolbar
      django-libsass
      django-types
      django_4
      djangorestframework
      ipython
      psycopg2
      pygithub
      requests
      tqdm
      # Custom dependencies injected via overlay
      pyngo
      django-ninja
    ];

    postInstall = ''
      mkdir -p $out/bin
      cp -v ${src}/manage.py $out/bin/manage.py
      chmod +x $out/bin/manage.py
      wrapProgram $out/bin/manage.py --prefix PYTHONPATH : "$PYTHONPATH"
    '';
  };
}
