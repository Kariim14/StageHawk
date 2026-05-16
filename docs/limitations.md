# Limitations

Current limitations are intentionally explicit:

- Live Ghidra is disabled by default.
- Live x64dbg execution is disabled by default.
- Fake-sample fixtures are used for reproducible development runs.
- Memory dump extraction is not implemented.
- CAPE integration is implemented, but CAPE execution remains disabled by default.
- Recursive static analysis of extracted child artifacts is scaffolded but disabled by default.
- Stage graph edges are only marked observed when supported by collected runtime output.
