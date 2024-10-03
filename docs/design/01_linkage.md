# Record linkage design

## Context

When a CVE comes, we have various metadata, not _ALL_ metadata are filled by authorities.

What we expect to find is:

- a description

What we hope to find is:

- a CPE

## Goal

Our goal is to match a CVE record with a set of derivations which we know about in all our supported channels.

For this, it is sufficient to consider the latest evaluation of a given channel.

We have all the derivations known in an evaluation of a given channel on one hand and the other hand a CVE record.

### With CPEs

Assuming we do have CPEs, we need a function to go from CPE URI to CPE WFNs.

Assuming we have a CPE WFN of the following form `wfn:[part=X, vendor=Y, product=Z, version=V, target_hw=TH, target_sw=TS]`.

We would like to find derivations which correspond to product `Z` and vendor `Y` in nixpkgs.

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

[1]: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf

### Without CPEs

To make it simple, we should do the work to attach CPEs to CVEs themselves when they are missing them.

We reduce this problem to predict or infer a valid CPE -- possibly wrong -- from a text description.

This is a CPE proposal that a security team has to validate, if it's wrong, the security team can edit it.

_Future work_ :

- Plug in the CPE dictionary and provide ways to expand our CPE dictionary with our own CPE taxonomy.

# Technical details

## How many CVE is there without any structured data?

```python-session
In [38]: CveRecord.objects.filter(container=None).count()
Out[38]: 0
```

Good, we can assume the existence of at least one container.

## How many CVE is there with a container containing an affected product at least?

```
In [84]: CveRecord.objects.filter(container__in=Container.objects.filter(affected=None).values_list('id', flat=True)).distinct().count()
Out[84]: 261332
```

That is, 98 % of the CVEs.

## How many affected products do we have without CPEs?

```python-session
In [33]: AffectedProduct.objects.filter(cpes=None).count()
Out[33]: 299806

In [34]: 299806/407168
Out[34]: 0.7363201430367808
```

73 % of the affected products in the database, at the time of writing, have no CPEs.

## Conclusion

71 % of the CVE have a CPE string.

An automatic regeneration of missing CPE is possible.
