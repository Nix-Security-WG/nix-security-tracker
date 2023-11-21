To get started running the process:

```
nix develop
export PATH=~/.local/bin:$PATH
cabal install --overwrite-policy=always

./scan.sh /nix/var/nix/profiles/system
```
