<!--
SPDX-FileCopyrightText: 2023 Arnout Engelen <arnout@bzzt.net>
SPDX-FileCopyrightText: 2023 Dylan Green <dylan.green@obsidian.systems>

SPDX-License-Identifier: MIT
-->

To get all development prerequisites enter `nix develop`.

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
ghcid --command "cabal repl"
```

Which will open up a cabal repl in ghcid, so that you can see new warnings/errors on code changes
