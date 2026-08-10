# tests

This folder contains focused validation for paper-aligned behavior in the
public release.

Current tests cover:

- typed verifier/oracle integration;
- rejection of command-only flag matches;
- Eq. 27 provenance requirements; and
- dynamic protected-flag injection.

Additional tests should stay focused on release-critical semantics rather than
attempting to replay the unavailable full 1,548-run paper benchmark.
