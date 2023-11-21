To get started running the process:

```
nix develop
cabal install --overwrite-policy=always

./scan.sh /nix/var/nix/profiles/system
```

We plan to make the above move 'user-friendly' in [#26](https://github.com/Nix-Security-WG/nix-security-tracker/issues/26)

For development notes see [CONTRIBUTING.md](./CONTRIBUTING.md)
