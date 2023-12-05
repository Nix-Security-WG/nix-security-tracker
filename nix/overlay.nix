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
      django-allauth
      django-types
      django_4
      djangorestframework
      dj-database-url
      psycopg2
      ipython
      pygithub
      requests
      dataclass-wizard
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
