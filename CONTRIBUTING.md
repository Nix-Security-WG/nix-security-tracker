<!--
SPDX-FileCopyrightText: 2023 Arnout Engelen <arnout@bzzt.net>
SPDX-FileCopyrightText: 2023 Dylan Green <dylan.green@obsidian.systems>

SPDX-License-Identifier: MIT
-->

To get all development prerequisites enter `nix develop` or alternatively run `direnv allow` if you have direnv installed.

Then run the process for a given derivation path with:

```bash
cabal run LocalSecurityScanner -- --path /nix/var/nix/profiles/system
```

Or to skip the inventory collection and only run the advisory matching:

```bash
cabal run LocalSecurityScanner -- --sbom ./sbom.cdx.json
```

To also show debug information on unmatched advisories:

```bash
cabal run LocalSecurityScanner -- --debug --sbom ./sbom.cdx.json
```

For easier debugging you can use:

```bash
ghcid
```

[ghcid](https://github.com/ndmitchell/ghcid) is aliased to `ghcid --command "cabal repl"`.

To access the unwrapped ghcid plase use `ghcid-unwrapped`
