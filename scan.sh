#!/usr/bin/env sh

if [ "$#" -ne 1 ] || ! [ -d "$1" ]; then
  echo "Usage: $0 [store path]" >&2
  echo "" >&2
  echo "Examples:" >&2
  echo "  $0 /nix/var/nix/profiles/system" >&2
  exit 1
fi

# https://github.com/Nix-Security-WG/nix-security-tracker/issues/17
echo "Taking inventory runtime dependencies..."
sbomnix $1 --type runtime

# https://github.com/Nix-Security-WG/nix-security-tracker/issues/4
echo "Ingesting advisories..."

if [ -d "CVE/cves" ]; then
    pushd CVE; git pull; popd
else
    git clone https://github.com/CVEProject/cvelistV5 CVE
fi

CVENix ./sbom.cdx.json
