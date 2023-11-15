To get into the proper env

```bash
nix-shell -p "haskellPackages.ghcWithPackages (p: with p; [ haskell-src-exts ghci text network cabal-install cassava split aeson lens ])"
```
