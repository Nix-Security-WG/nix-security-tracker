To avoid rate limiting, request an NVD API key at https://nvd.nist.gov/developers/start-here . Then run the scanner:

```
$ nix shell github:tiiuae/sbomnix
$ export NVD_API_KEY=...
$ nix run github:nix-security-wg/nix-security-tracker/local-security-scanner -- --path /nix/var/nix/profiles/system
```

For development notes see [CONTRIBUTING.md](./CONTRIBUTING.md)
