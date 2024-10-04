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

Assuming we have a CPE WFN [1] of the following form `wfn:[part=X, vendor=Y, product=Z, version=V, target_hw=TH, target_sw=TS]`.

We would like to find derivations which correspond to product `Z` and vendor `Y` in nixpkgs, details on the matching are defined in [the CPE-based linkage document](./02_cpe-based_linkage.md).

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

## Conclusion

98 % of the CVE have a recoverable CPE as the affected product model contain the vendor, product name, and sometimes even package name.

An automatic regeneration of missing CPE is possible.
