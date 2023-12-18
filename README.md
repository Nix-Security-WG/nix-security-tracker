<!--
SPDX-FileCopyrightText: 2023 Arnout Engelen <arnout@bzzt.net>
SPDX-FileCopyrightText: 2023 Dylan Green <dylan.green@obsidian.systems>

SPDX-License-Identifier: MIT
-->

# Nix local security scanner

Reports on which security advisories may be relevant for a given system or derivation.

## Running

To avoid rate limiting, request an NVD API key at https://nvd.nist.gov/developers/start-here . Then run the scanner:

```
$ export NVD_API_KEY=...
$ nix run github:nix-security-wg/nix-security-tracker/local-security-scanner -- --path /nix/var/nix/profiles/system
```

For development notes see [CONTRIBUTING.md](./CONTRIBUTING.md)
