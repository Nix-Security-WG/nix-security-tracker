{
  lib,
  buildPythonPackage,
  flit-core,
  pydantic,
  django_4,
  fetchFromGitHub,
}:

buildPythonPackage rec {
  pname = "django-ninja";
  version = "0.22.2";
  pyproject = true;

  src = fetchFromGitHub {
    owner = "vitalik";
    repo = "django-ninja";
    rev = "v${version}";
    hash = "sha256-oeisurp9seSn3X/5jFF9DMm9nU6uDYIU1b6/J3o2be0=";
  };

  nativeBuildInputs = [ flit-core ];

  propagatedBuildInputs = [
    pydantic
    django_4
  ];

  doCheck = false;

  meta = with lib; {
    description = "Fast, Async-ready, Openapi, type hints based framework for building APIs";
    homepage = "https://github.com/vitalik/django-ninja";
    license = licenses.mit;
    maintainers = with maintainers; [ ];
  };
}
