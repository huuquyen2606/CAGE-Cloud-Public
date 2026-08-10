# testbed

This folder contains the evaluation-control helpers used by the public release.

- `flag_issuer.py`: mints run-specific protected flags using scenario secrets.
- `provision.py`: writes the control-plane manifest and per-run environment.
- `target_event.py`: records target-side provenance when the protected
  condition is actually satisfied.
- `flag_oracle.py`: checks the Eq. 27 external outcome predicates.
- `inject_flags.py`: rewrites lab files so static flags are replaced by
  runtime-provided protected flags.

The random-flag flow is implemented here: each run gets a fresh protected flag,
the target only reveals it behind the security condition, and scoring requires
exact recovery plus target-side provenance.
