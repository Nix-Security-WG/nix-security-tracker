let
  staging = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEA4k049dr0feLkZsSAcG64MxWHYLbG77ydBokW8xo4q";
  admins = [
    # Raito
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICaw9ihTG7ucB8P38XdalEWev8+q96e2yNm4B+/I9IJp raito@Thors"
  ];
in
{
  "secrets/django-secret-key.age".publicKeys = admins ++ [ staging ];
  "secrets/gh-client.age".publicKeys = admins ++ [ staging ];
  "secrets/gh-secret.age".publicKeys = admins ++ [ staging ];
  "secrets/gh-webhook-secret.age".publicKeys = admins ++ [ staging ];
  "secrets/dev-nixpkgs-security-tracker.2024-10-04.private-key.pem.age".publicKeys = admins ++ [
    staging
  ];
}
