let
  staging = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEHib5Kk39PzPEheOf8fwIyeVbVgSzUiqUN2vSIXHO7N";
in
{
  "secrets/staging-django-secret-key.age".publicKeys = [ staging ];
  "secrets/staging-gh-client.age".publicKeys = [ staging ];
  "secrets/staging-gh-secret.age".publicKeys = [ staging ];
  "secrets/staging-gh-webhook-secret.age".publicKeys = [ staging ];
  "secrets/staging-gh-app-installation-id.age".publicKeys = [ staging ];
  "secrets/staging-nixpkgs-security-tracker.2024-12-09.private-key.pem.age".publicKeys = [ staging ];
}
