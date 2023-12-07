{ lib, python3, fetchFromGitHub }:

python3.pkgs.buildPythonPackage rec {
  pname = "pyngo";
  version = "1.6.0";
  pyproject = true;

  src = fetchFromGitHub {
    owner = "yezz123";
    repo = "pyngo";
    rev = version;
    hash = "sha256-qOY1ILMDqSguLnbhuu5JJVMvG3uA08Lv2fB70TgrKqI=";
  };

  nativeBuildInputs = with python3.pkgs; [ hatchling ];

  propagatedBuildInputs = with python3.pkgs; [
    django_4
    pydantic
    typing-extensions
  ];

  pythonImportsCheck = [ "pyngo" ];

  meta = with lib; {
    description = "Pydantic model support for Django & Django-Rest-Framework";
    homepage = "https://github.com/yezz123/pyngo";
    license = licenses.mit;
    maintainers = with maintainers; [ ];
  };
}
