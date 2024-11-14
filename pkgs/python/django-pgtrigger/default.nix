{
  lib,
  buildPythonPackage,
  fetchFromGitHub,
  poetry-core,
  django,
  psycopg2,
}:

buildPythonPackage rec {
  pname = "django-pgtrigger";
  version = "4.13.1";
  pyproject = true;

  src = fetchFromGitHub {
    owner = "Opus10";
    repo = "django-pgtrigger";
    rev = version;
    hash = "sha256-UnStoUslriZ30ax7OSb8fRaJHzJEO3iG/er5dBHXbno=";
  };

  nativeBuildInputs = [ poetry-core ];

  propagatedBuildInputs = [
    django
    psycopg2
  ];

  pythonImportsCheck = [ "pgtrigger" ];

  meta = with lib; {
    description = "";
    homepage = "https://github.com/Opus10/django-pgtrigger";
    changelog = "https://github.com/Opus10/django-pgtrigger/blob/${src.rev}/CHANGELOG.md";
    license = licenses.bsd3;
    maintainers = with maintainers; [ raitobezarius ];
  };
}
