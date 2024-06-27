{
  lib,
  buildPythonPackage,
  fetchFromGitHub,
  setuptools,
  django,
  pandas,
  six,
}:

buildPythonPackage rec {
  pname = "django-pandas";
  version = "0.6.7";
  pyproject = true;

  src = fetchFromGitHub {
    owner = "chrisdev";
    repo = "django-pandas";
    rev = version;
    hash = "sha256-GJb9qNlaxOz/q2yyQP2UDslT6y8xFjMX+W5EJdK3dEs=";
  };

  nativeBuildInputs = [ setuptools ];

  propagatedBuildInputs = [
    django
    pandas
    six
  ];

  pythonImportsCheck = [ "django_pandas" ];

  meta = with lib; {
    description = "";
    homepage = "https://github.com/chrisdev/django-pandas";
    # no changelog provided
    license = licenses.bsd3;
    maintainers = with maintainers; [ ];
  };
}
