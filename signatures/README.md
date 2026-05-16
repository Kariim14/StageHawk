# StageHawk Local Signatures

This directory is the defensive local-signature workspace for StageHawk.
It is intended for malware-analysis evidence collection and triage, not for
malware creation or offensive payload development.

StageHawk currently discovers local YARA rules recursively from
`signatures/yara` through the configured `signature_rules_dirs` setting.
Rules placed under that tree are evaluated against submitted samples without
executing them on the controller host.

## Rule Quality Levels

- `generic`: Broad suspicious PE or static-analysis patterns. These can be
  useful for triage, but they may be noisy and should not be treated as strong
  attribution by themselves.
- `known_families`: Verified and attributed known malware-family rules only.
  Rules here must have clear provenance, review notes, and false-positive
  considerations.
- `experimental`: Research and testing rules. These are useful while developing
  detection ideas, but they are not strong evidence alone.

## Policy

- Keep every rule source-tracked with clear provenance and review context.
- Consider false positives before treating a rule match as meaningful evidence.
- Do not import external YARA or antivirus rule packs blindly.
- Do not add unverified family attribution rules.
- Keep local signatures defensive, static, and analysis-focused.

