To get all development prerequisites enter `nix develop`.

You can `./scan.sh /nix/var/nix/profiles/system` to run the entire process,
but for fast(er) development round-trips you can also run part of the
process described in that shell, such as:

```
cabal run CVENix ./sbom.cdx.json
```
