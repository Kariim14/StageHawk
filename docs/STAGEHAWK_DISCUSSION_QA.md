# StageHawk Discussion Q&A

## What problem does StageHawk solve?

StageHawk organizes malware-analysis evidence for suspected multi-stage droppers. Instead of manually collecting disconnected static, sandbox, signature, artifact, graph, and reputation outputs, it creates one structured case and report that an analyst can review.

## What is a multi-stage dropper?

A multi-stage dropper is malware that starts with an initial file and then drops, downloads, decrypts, or launches later payloads. The important analysis question is not only "is the first file suspicious?" but also "what later stages did it produce and how are they related?"

## Why use static and dynamic analysis?

Static analysis examines the file without running it, which is safer and useful for strings, imports, structure, and code indicators. Dynamic analysis observes behavior in a sandbox, such as dropped files, processes, network activity, and sandbox signatures. Combining both gives better context than either method alone.

## Why Ghidra?

Ghidra is a strong open-source reverse-engineering framework. StageHawk uses Ghidra headless mode so static analysis can run automatically as part of the pipeline.

## Why CAPE?

CAPE Sandbox is designed for malware detonation in an isolated VM. It provides task submission, behavior reports, signatures, dropped artifacts, process information, and exported reports. That makes it a safer and more practical dynamic backend for this project.

## Why is x64dbg not active now?

x64dbg is useful for manual debugging, but safe automated debugger tracing needs stable VM control, snapshot handling, ASLR-safe breakpoints, memory-dump validation, and robust scripts. Those are future-work items. Keeping x64dbg inactive avoids overstating an unstable feature.

## What is recursive analysis?

Recursive analysis means StageHawk can take supported child artifacts, such as dropped PE/MZ-like files, and run static analysis on them too. This helps reveal later stages rather than stopping at the original sample.

## What is stage graph reconstruction?

Stage graph reconstruction builds a relationship graph from the original sample to extracted or dropped artifacts. It helps show how the initial file relates to later suspected stages.

## What are IOCs?

IOCs, or Indicators of Compromise, are evidence items that can support detection or investigation. Examples include hashes, URLs, domains, IPs, file paths, registry keys, and suspicious strings. StageHawk extracts available IOCs but avoids overclaiming their meaning.

## What is the difference between Evidence Score and Maliciousness Likelihood?

Evidence Score measures how much useful evidence StageHawk collected. Maliciousness Likelihood estimates how suspicious the collected evidence is. A high Evidence Score does not automatically mean malware; it can mean the system collected a lot of analyzable data.

## Are YARA matches proof of malware?

No. StageHawk's generic YARA rules are heuristic triage signals. They can highlight suspicious patterns, but they do not prove malware and do not provide family attribution. Known-family attribution should only come from verified `known_families` rules or trusted reputation sources.

## Why can a benign installer look suspicious?

Installers often create many files, modify registry keys, start processes, use scripts, or contact update servers. Those behaviors can resemble malware techniques in a sandbox, so StageHawk includes caution wording and avoids treating noisy behavior as automatic proof.

## How do you avoid false positives?

StageHawk separates evidence from interpretation. It labels generic signatures as heuristic, reports ClamAV unavailability honestly, uses reputation as supporting evidence, shows limitations, and keeps analyst review in the loop.

## What safety controls prevent malware running on the host?

The controller host performs orchestration, static analysis, hashing, and reporting. It does not execute samples directly. Dynamic execution is routed through CAPE and the isolated Windows VM. Real malware mode is disabled by default, and upload/API hardening controls reduce accidental misuse.

## What are the project limitations?

StageHawk depends on local Ghidra and CAPE configuration. Static-only analysis cannot prove a file is safe. Generic YARA rules can be noisy. x64dbg automation is not active. IP/domain enrichment is future work. Production deployment would need authentication, stronger isolation, and centralized job/rate-limit storage.

## What would you improve next?

Good next steps are curated known-family YARA rules with provenance, safer IP/domain enrichment, stronger user authentication, richer CAPE artifact correlation, better recursive analysis coverage, and optional future x64dbg-assisted memory validation inside a controlled VM.

## Why are hash and URL reputation implemented, but IP/domain enrichment deferred?

Hash and URL checks are direct and bounded lookups. IP/domain enrichment is more ambiguous because infrastructure can be shared, reused, parked, or benign. Deferring it prevents weak infrastructure signals from being presented as strong evidence.

## What should a reader trust most in the report?

They should trust the raw evidence paths, hashes, timestamps, CAPE artifacts, Ghidra/static outputs, and clear source labels. Final verdicts are evidence-based summaries, not absolute truth, and should be reviewed by an analyst.

