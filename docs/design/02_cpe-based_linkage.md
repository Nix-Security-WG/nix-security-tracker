# CPE-based record linkage design

## Context

Refer to [the high-level overview](./01_linkage.md).

We assume that we are looking at a `CveRecord` with a container containing at least one affected product which itself contain at least one CPE string.

## CPE parsing

Following spec XYZ, we parse CPE strings in a structured fashion into a CPE WFN, see [1] for terminology.

[1]: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf

## Candidates generation

### Matching algorithm

Derivation names are usually: `$product-name-$version`.

On our end, if we can first cut the version, which is possible if we can retrieve the `version` parameter so that we can trim it, we can obtain the `$product-name`.

Given all product names in nixpkgs, we are reduced to a string matching problem:

- exact matches are prioritized
- in case of no exact matches, very low bigram similarity can be proposed as well (tuning is TBD).

Once product names are obtained, we can look again at versions and try to match them over V.

_Future work_ :

Once versions are matched, we could look into the target hardware field `TH` and match it over or display to the user this information, this is non trivial because we would need probably to support the predicates form of platform support in nixpkgs.

_Areas of improvements_ :

We do not make use of the vendor at all and we could have multi-vendor albeit generic product names in nixpkgs.

### Models

When a matching is deemed as fit, it is inserted as a `CVEDerivationClusterProposals`.

### Validation of matchings

The security team can then review the new proposed matching of the day based on the new CVEs and can review also unmatched CVEs to triage them successfully as well.

When a matching is validated, `CVEDerivationClusterProposal` moves its status to `ACCEPTED`, this generates in turn a Nixpkgs security issue and the rest of the workflow is the one for a manual linkage.

The novelty here is that `CVEDerivationClusterProposal` can be reviewed to improve the matching accuracy and develop new ways to automate the matchings.

### When does the matching occur?

Every time, a delta CVE archive is ingested, new CveRecord models are inserted.

As soon as one new CveRecord model is inserted, it's immediately run through the matching algorithm for the current channels and new matchings can occur or not.

### Manually run a matching

For a day range (the last 30 days, last 90 days, last 365 days), you can rerun the matching algorithm manually:

```
manage propose_cve_links $day_range # e.g. 95 for last 95 days.
```

### Debug linkage decisions

Linkage decisions are logged, as long as these logs are preserved, we can review why a link was made or not.
