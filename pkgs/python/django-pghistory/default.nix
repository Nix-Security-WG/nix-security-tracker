{
  lib,
  fetchFromGitHub,
  buildPythonPackage,
  django_4,
  django-pgtrigger,
  poetry-core,
}:

buildPythonPackage rec {
  pname = "django-pghistory";
  version = "3.5.0";
  pyproject = true;

  src = fetchFromGitHub {
    owner = "Opus10";
    repo = "django-pghistory";
    rev = "${version}";
    hash = "sha256-5e0vORTG9vOr8zf9MTDH1CUevwtRgnCg6qBSOcJ7WF0=";
  };

  propagatedBuildInputs = [
    django_4
    django-pgtrigger
    poetry-core
  ];

  pythonImportsCheck = [ "pghistory" ];

  meta = with lib; {
    changelog = "https://github.com/Opus10/django-pghistory/releases/tag/${version}";
    description = "History tracking for Django and Postgres.";
    homepage = "https://django-pghistory.readthedocs.io";
    maintainers = with maintainers; [ ];
    license = licenses.bsd3;
  };
}
