{ lib, python3, fetchFromGitHub }:

python3.pkgs.buildPythonPackage rec {
  pname = "django-permission2";
  version = "2.1.0";
  pyproject = true;

  src = fetchFromGitHub {
    owner = "JanMalte";
    repo = "django-permission2";
    rev = "v${version}";
    hash = "sha256-TCVyZTBIgJkk+TlU+8gFd/RK4WbaqIzbVn/Cq7VgYAo=";
  };

  nativeBuildInputs = [ ];

  propagatedBuildInputs = with python3.pkgs; [ poetry-core django_4 ];

  meta = with lib; {
    description =
      "A simple permission system which supports object permission in Django ";
    homepage = "https://github.com/JanMalte/django-permission2";
    license = licenses.mit;
    maintainers = with maintainers; [ ];
  };
}
