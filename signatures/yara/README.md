# StageHawk YARA Rule Workspace

This directory contains StageHawk local YARA collections for defensive
malware-analysis orchestration. YARA files with `.yar` or `.yara` extensions
are discovered recursively from this directory by the current scanner
configuration.

The starter generic rules currently live in:

- `generic/stagehawk_generic_suspicious_pe.yar`

These rules are heuristic triage signals only. They may identify suspicious PE
indicators, but they do not confirm malware and they do not provide family
attribution.

Scanner output includes a `signature_catalog` section derived from
`METADATA.json` when available. Reports use this catalog to explain whether a
match came from `generic`, `known_families`, or `experimental` sources.

## Collections

- `generic/`: Broad suspicious PE or static indicators. Matches may be noisy
  and should be reviewed alongside Ghidra, CAPE, reputation, artifact triage,
  and graph evidence.
- `known_families/`: Verified known malware-family rules only. Keep this
  directory empty until a rule has trusted provenance, attribution basis, and
  documented false-positive review.
- `experimental/`: Research or testing rules. Matches from this collection are
  not strong evidence alone and should not drive family attribution.

## Rule Handling

- Track source, author or origin, review date, and intended scope for each rule.
- Prefer small, auditable rules with clear metadata.
- Avoid broad strings or conditions that would create common false positives.
- Do not download or add external rule packs without review and attribution.
- Do not use local signatures to imply malware-family attribution unless the
  rule is verified and belongs in `known_families/`.
