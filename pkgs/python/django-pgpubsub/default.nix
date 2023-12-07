{ lib, buildPythonPackage, fetchFromGitHub, python3 }:

buildPythonPackage rec {
  pname = "django-pgpubsub";
  version = "1.1.2";
  pyproject = true;

  src = fetchFromGitHub {
    owner = "Opus10";
    repo = "django-pgpubsub";
    rev = version;
    hash = "sha256-TXyojZ7EHOlAdC0/QqTspCAsI4G55fnfsZfH5JUp5D0=";
  };

  nativeBuildInputs = with python3.pkgs; [ poetry poetry-core ];

  propagatedBuildInputs = with python3.pkgs; [ django django-pgtrigger ];

  pythonImportsCheck = [ "django_pgpubsub" ];

  meta = with lib; {
    description =
      "Lightweight background tasks using Django Channels and PostgreSQL NOTIFY/LISTEN";
    homepage = "https://github.com/Opus10/django-pgpubsub";
    changelog =
      "https://github.com/Opus10/django-pgpubsub/blob/${src.rev}/CHANGELOG.md";
    license = licenses.bsd3;
    maintainers = with maintainers; [ raitobezarius ];
  };
}
