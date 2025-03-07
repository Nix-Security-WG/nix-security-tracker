final: prev:
let
  inherit (final) python3;
  extraPackages = import ../pkgs {
    pkgs = prev;
    inherit python3;
  };
  extraPython3Packages = extraPackages.python3Packages;
  sources = import ../npins;
in
{
  python3 = prev.lib.attrsets.recursiveUpdate prev.python3 { pkgs = extraPython3Packages; };

  # go through the motions to make a flake-incompat project use the build
  # inputs we want
  pre-commit-hooks = final.callPackage "${sources.pre-commit-hooks}/nix/run.nix" {
    tools = import "${sources.pre-commit-hooks}/nix/call-tools.nix" final;
    # wat
    gitignore-nix-src = {
      lib = import sources.gitignore { inherit (final) lib; };
    };
    isFlakes = false;
  };

  web-security-tracker = python3.pkgs.buildPythonPackage rec {
    pname = "web-security-tracker";
    version = "0.0.1";
    pyproject = true;

    src = final.nix-gitignore.gitignoreSourcePure [ ../.gitignore ] ../src/website;

    postPatch = ''
      cat <<EOF >> tracker/settings.py

      APP_VERSION = "${version}"
      APP_REVISION = "${(builtins.fetchGit { url = ../.; shallow = true; }).rev}"
      EOF
    '';

    propagatedBuildInputs = with python3.pkgs; [
      # Nix python packages
      dataclass-wizard
      dj-database-url
      django-allauth
      django-debug-toolbar
      django-filter
      django-types
      django_4
      djangorestframework
      httpretty
      ipython
      psycopg2
      pygithub
      requests
      tqdm
      pyngo
      django-ninja
      django-pgpubsub
      daphne
      channels
      aiofiles
      sentry-sdk
      django-pghistory
      django-pgtrigger
    ];

    postInstall = ''
      mkdir -p $out/bin
      cp -v ${src}/manage.py $out/bin/manage.py
      chmod +x $out/bin/manage.py
      wrapProgram $out/bin/manage.py --prefix PYTHONPATH : "$PYTHONPATH"
      cp ${sources.htmx}/dist/htmx.min.js* $out/${python3.sitePackages}/webview/static/
    '';
  };
}
