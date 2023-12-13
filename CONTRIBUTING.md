To get all development prerequisites enter `nix develop`.

Then run the process for a given derivation path with:

```
cabal run LocalSecurityScanner -- --path /nix/var/nix/profiles/system
```

Or to skip the inventory collection and only run the advisory matching:

```
cabal run LocalSecurityScanner -- --sbom ./sbom.cdx.json
```

To also show debug information on unmatched advisories:

```
cabal run LocalSecurityScanner -- --debug --sbom ./sbom.cdx.json
```
