let
  prod = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEHib5Kk39PzPEheOf8fwIyeVbVgSzUiqUN2vSIXHO7N";
in
{
  "secrets/django-secret-key.age".publicKeys = [ prod ];
  "secrets/gh-client.age".publicKeys = [ prod ];
  "secrets/gh-secret.age".publicKeys = [ prod ];
  "secrets/gh-webhook-secret.age".publicKeys = [ prod ];
  "secrets/gh-app-installation-id.age".publicKeys = [ prod ];
  "secrets/nixpkgs-security-tracker.2024-12-09.private-key.pem.age".publicKeys = [ prod ];
}
