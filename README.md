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

### False positives

When the tool reports advisories that, after analysis, turn out to be false
positives for your particular usage scenario, you can filter them out of the
output by providing a `VEX` file with the `--vex` parameter:

```
{
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "vulnerabilities": [
        {
            "id": "CVE-2023-38468",
            "analysis": {
                "state": "false_positive",
                "detail": "https://github.com/Nix-Security-WG/nix-security-tracker/issues/75"
            }
        },
...
 ```



## Development

For development notes see [CONTRIBUTING.md](./CONTRIBUTING.md)
