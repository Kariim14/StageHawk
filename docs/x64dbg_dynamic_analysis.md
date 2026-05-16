# x64dbg Dynamic Analysis

The current x64dbg automation can prepare scripts, launch through a Windows VM helper, and collect runtime evidence.

Important correction:

- `hit_*.bin` files are API hit markers.
- They are not payload dumps.
- The backend labels them as `api_hit_marker`.

Real payload extraction currently means collecting actual dropped files such as `dropped_stage2.bin` and `dropped_stage3.bin` if they exist in configured safe runtime output locations.

Memory dump collection is represented by `orchestrator.integrations.memory_dump_collector`, but it is a TODO stub. Reports explicitly state that memory dumping is not implemented yet.
