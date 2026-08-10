# evaluation

This folder contains post-hoc scoring and reporting code for the public
paper-aligned evaluation protocol.

- `compute_metrics.py`: loads manifest-backed run records, applies the external
  outcome oracle, and computes FRR, telemetry, efficiency, matched tests, and
  scenario-cluster bootstrap intervals.
- `__init__.py`: module summary.

The external outcome comes from `testbed.flag_oracle`, not from parser matches,
command activity, or internal verifier labels alone.
