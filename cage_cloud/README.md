# cage_cloud

This package contains the main CAGE-Cloud runtime.

- `orchestrator.py`: planner/generator loop with tentative execution, verifier
  gating, and authoritative state commit.
- `verifier.py`: deterministic objective handlers that classify outcomes as
  `verified`, `partial`, or `unverified`.
- `graph.py`: state-derived graph projection and canonical progress signature.
- `scope_guard.py`: command, target, and budget checks for controlled execution.
- `state_commit.py`: extract-to-verify-to-commit transition logic.
- `skill_router.py`: eight-family contextual example router.
- `schema.py`: shared typed records.

The authoritative source of truth is the committed runner state, not the graph.
