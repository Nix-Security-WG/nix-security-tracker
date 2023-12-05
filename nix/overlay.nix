final: prev:
let
  python = final.python3;
  extraPkgs = import ../pkgs {
    pkgs = prev;
    python3 = python;
  };
in extraPkgs // {
  web-security-tracker = python.pkgs.buildPythonPackage rec {
    pname = "web-security-tracker";
    version = "0.0.1";
    pyproject = true;

    src = ../src/website;

    propagatedBuildInputs = with python.pkgs; [
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
