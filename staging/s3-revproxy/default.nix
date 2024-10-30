## All credits to Jade Lovelace (https://github.com/lf-) for this code, used initially in the Lix infrastructure.
{ config, ... }:
let
  domain = "s3.dc1.lahfa.xyz";
  mkTarget =
    {
      name,
      bucket ? name,
    }:
    {
      mount = {
        host = name;
        path = [ "/" ];
      };
      actions.GET = {
        enabled = true;
        config = {
          # e.g. /2.90 will 404, so it will redirect to /2.90/ if it is a directory
          redirectWithTrailingSlashForNotFoundFile = true;
          indexDocument = "index.html";
        };
      };

      bucket = {
        name = bucket;
        region = "garage";
        s3Endpoint = "https://${domain}";
        credentials = {
          accessKey.env = "AWS_ACCESS_KEY_ID";
          secretKey.env = "AWS_SECRET_KEY";
        };
      };
    };
  # Makes a subdomain that gets proxied through s3-proxy to provide directory
  # listings and reasonable 404 pages.
  mkProxiedSubdomain = _: {
    enableACME = true;
    forceSSL = true;
    locations."/" = {
      recommendedProxySettings = true;
      proxyPass = "http://127.0.0.1:${toString config.services.s3-revproxy.settings.server.port}/";
      extraConfig = ''
        # Disable buffering to a temporary file.
        proxy_max_temp_file_size 0;
      '';
    };
  };
in
{
  imports = [
    ./module.nix
  ];

  nixpkgs.overlays = [
    (self: _: {
      s3-revproxy = self.callPackage ./package.nix { };
    })
  ];

  age.secrets.s3-revproxy-api-key-env.file = ../secrets/s3-revproxy-env.age;

  services.s3-revproxy = {
    enable = true;
    settings = {
      templates = {
        helpers = [ ./templates/_helpers.tpl ];
        notFoundError = {
          headers = {
            "Content-Type" = "{{ template \"main.headers.contentType\" . }}";
          };
          status = "404";
        };
        folderList = {
          path = ./templates/folder-list.tpl;
          headers = {
            "Content-Type" = "{{ template \"main.headers.contentType\" . }}";
          };
          # empty s3 directories are not real and cannot hurt you.
          # due to redirectWithTrailingSlashForNotFoundFile, garbage file names
          # get redirected as folders, which then appear as empty, yielding
          # poor UX.
          status = ''
            {{- if eq (len .Entries) 0 -}}
              404
            {{- else -}}
              200
            {{- end -}}
          '';
        };
      };
      server = {
        listenAddr = "127.0.0.1";
        port = 10652;

        # it's going right into nginx, so no point
        compress.enabled = false;
        cors = {
          enabled = true;
          allowMethods = [ "GET" ];
          allowOrigins = [ "*" ];
        };
      };
      targets = {
        staging-sectracker-db = mkTarget {
          name = "dumps.sectracker.nixpkgs.lahfa.xyz";
          bucket = "staging-sectracker-db";
        };
      };
    };
    environmentFile = config.age.secrets.s3-revproxy-api-key-env.path;
  };

  services.nginx = {
    enable = true;
    virtualHosts."dumps.sectracker.nixpkgs.lahfa.xyz" = mkProxiedSubdomain "staging-sectracker-db";
  };
}
