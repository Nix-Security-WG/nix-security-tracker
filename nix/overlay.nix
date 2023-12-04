final: prev:
let
  python = final.python3;
  extraPkgs = import ../pkgs {
    pkgs = prev;
    python3 = python;
  };
in extraPkgs // {
  web-security-tracker = python.pkgs.buildPythonPackage {
    pname = "web-security-tracker";
    version = "0.0.1";
    pyproject = true;

    src = ../.;

    propagatedBuildInputs = with python.pkgs; [
      # Nix python packages
      django-allauth
      django-types
      django_4
      djangorestframework
      ipython
      pygithub
      requests
      # Custom dependencies injected via overlay
      pyngo
      django-ninja
    ];
  };
}
