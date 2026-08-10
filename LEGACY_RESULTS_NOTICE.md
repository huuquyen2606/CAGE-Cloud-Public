# Legacy Results Notice

Historical benchmark outputs produced before the paper-version-11 protocol are
not treated in this repository as paper-valid external successes.

## Why

Paper version 11 requires all three Eq. 27 conditions for a counted positive:

1. exact recovery of the run-specific expected flag;
2. a matching target-side issuance provenance event; and
3. confirmation of the scenario-defined security condition.

Earlier internal benchmark runs used predictable static flags and did not retain
the target-side provenance needed to validate Eq. 27. Those historical records
can still be useful for engineering diagnostics, but they are not sufficient to
restate the paper's FRR under the final protocol.

## Release Rule

- Do not package old success counts as paper-valid positives.
- Do not merge historical static-flag outputs into new Eq. 27 evaluation tables.
- If historical engineering traces are shared at all, label them clearly as
  legacy or diagnostic artifacts outside the final paper protocol.
