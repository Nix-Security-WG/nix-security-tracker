{
  lib,
  buildPythonPackage,
  fetchFromGitHub,
  poetry-core,
  django,
  django-pgtrigger,
}:

buildPythonPackage rec {
  pname = "django-pgpubsub";
  version = "1.3.1";
  pyproject = true;

  src = fetchFromGitHub {
    owner = "PaulGilmartin";
    repo = "django-pgpubsub";
    rev = version;
    hash = "sha256-Gl6NfBaoj3WKLHwJElbb27CYVQ83s3f86NUOZE7lHCk=";
  };

  postPatch = ''
    substituteInPlace pyproject.toml \
    --replace 'poetry.masonry.api' 'poetry.core.masonry.api' \
    --replace 'poetry>=1.1.13' 'poetry-core>=1.0.0' \
  '';

  nativeBuildInputs = [ poetry-core ];

  propagatedBuildInputs = [
    django
    django-pgtrigger
  ];

  pythonImportsCheck = [ "pgpubsub" ];

  meta = with lib; {
    description = "Lightweight background tasks using Django Channels and PostgreSQL NOTIFY/LISTEN";
    homepage = "https://github.com/PaulGilmartin/django-pgpubsub";
    changelog = "https://github.com/PaulGilmartin/django-pgpubsub/blob/${src.rev}/CHANGELOG.md";
    license = licenses.bsd3;
    maintainers = with maintainers; [ raitobezarius ];
  };
}
