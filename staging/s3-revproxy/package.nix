{
  lib,
  buildGoModule,
  fetchFromGitHub,
}:
buildGoModule rec {
  pname = "s3-revproxy";
  version = "4.15.0";

  src = fetchFromGitHub {
    owner = "oxyno-zeta";
    repo = "s3-proxy";
    rev = "v${version}";
    hash = "sha256-q0cfAo8Uz7wtKljmSDaJ320bjg2yXydvvxubAsMKzbc=";
  };

  vendorHash = "sha256-dOwNQtTfOCQcjgNBV/FeWdwbW9xi1OK5YD7PBPPDKOQ=";

  ldflags = [
    "-X github.com/oxyno-zeta/s3-proxy/pkg/s3-proxy/version.Version=${version}"
    "-X github.com/oxyno-zeta/s3-proxy/pkg/s3-proxy/version.Metadata="
  ];

  postPatch = ''
    # Refer to the included templates in the package instead of cwd-relative
    sed -i "s#Path = \"templates/#Path = \"$out/share/s3-revproxy/templates/#" pkg/s3-proxy/config/config.go
  '';

  postInstall = ''
    mkdir -p $out/share/s3-revproxy
    cp -r templates/ $out/share/s3-revproxy/templates
  '';

  meta = {
    description = "S3 Reverse Proxy with GET, PUT and DELETE methods and authentication (OpenID Connect and Basic Auth)";
    homepage = "https://oxyno-zeta.github.io/s3-proxy";
    # hm, not having a maintainers entry is kind of inconvenient
    maintainers = [ ];
    licenses = lib.licenses.asl20;
    mainProgram = "s3-proxy";
  };
}
