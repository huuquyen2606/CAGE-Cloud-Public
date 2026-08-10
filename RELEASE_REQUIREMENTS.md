# Release Requirements

This document defines the minimum requirements for describing this repository
as an artifact accompanying paper version 11:

> CAGE-Cloud: Evidence-Grounded Autonomous Cloud Penetration Testing with
> Authoritative Structured State

## Current Artifact Boundary

This repository contains framework source code, adapted baseline source code,
testbed flag utilities, evaluation utilities, and 18 static planner few-shot
examples.

It does **not** contain:

- the 86 validated Docker scenarios used for the paper evaluation;
- the 328-record Planner-specialisation corpus (296 train, 32 validation);
- the per-run evidence and telemetry for the 1,548 reported evaluation runs;
- model weights or specialised Planner checkpoints; or
- the control-plane secrets, expected flags, and unredacted execution logs used
  during evaluation.

Consequently, this repository alone cannot independently reproduce the paper's
quantitative tables. It must be described as a code release, not as a complete
replication package.

Toy Flask CVE emulators referenced by testbed conversion utilities are not
included in this repository. If distributed separately, they must be labelled
as toy emulators. They are not the validated paper testbed and must not be used
as evidence for the paper's reported 1,548 runs.

## Required Release Gates

A release may be called "paper-aligned" only after all applicable gates below
pass.

### Claims and Documentation

- Use the paper title, metric names, outcome definitions, and bounded claims
  exactly as stated in paper version 11.
- Keep externally verified Flag Recovery Rate (FRR) separate from internal
  operational telemetry.
- Do not present command activity, parser matches, verifier status, or a
  locally generated flag-like string as externally verified success.
- State which paper artifacts are included and which are unavailable.
- Label adapted baselines as adaptations; do not claim exact reproduction of
  the original PentestAgent or VulnBot implementations.

### External Outcome Protocol

For each counted positive run, retain independently auditable fields for:

1. exact recovery of the run-specific expected flag;
2. a matching target-side issuance provenance event; and
3. confirmation of the scenario-defined security condition.

The assessed pipeline must not be able to read scenario secrets, expected
flags, derivation nonces, control-plane manifests, or validation metadata.
Every architecture-backbone-scenario execution must have a unique run ID.

### Scenario Package

A complete replication package must provide, for each of the 86 scenarios:

- provider context and recorded CVSS severity;
- affected software and vulnerable version or configuration;
- immutable image or build-input digests;
- a scenario-specific canonical validation procedure;
- a protected-state initialisation procedure;
- a target-side provenance and security-condition recorder; and
- evidence that the scenario remains reproducible after a clean rebuild.

Mock endpoints or Flask applications that imitate an API surface do not satisfy
these requirements unless the paper and release are explicitly revised to
evaluate emulation rather than reconstructed vulnerable configurations.

### Evaluation Records

To reproduce the reported results, publish a redacted run table with 1,548
rows: 86 scenarios x 3 architectures x 6 backbones. Each row must identify the
scenario, architecture, backbone, unique run ID or public pseudonym, the three
external outcome predicates, retained/excluded status, request count, recorded
input/output tokens, and operational telemetry used by the paper.

The analysis package must implement:

- FRR, ABFC, and ALBFC using the paper definitions;
- VIDR, VIY@T, ECAR, ECY@T, SDR, SY@T, CAR, and CY@T as operational telemetry;
- mean requests per target and median token use with first/third quartiles;
- pooled Tok@Req, Req@F, Tok@F, FPMT, and FPkR;
- Wilson 95% intervals for per-backbone FRR;
- two-sided exact McNemar tests with Holm correction; and
- the 10,000-replicate CVE-cluster bootstrap described in the paper.

Estimated token counts must not replace recorded provider or local-server token
telemetry in a paper replication package.

### Security and Privacy

- Run secret scanning and adjudicate every finding before publication.
- Never publish API keys, cloud credentials, scenario HMAC keys, expected
  run-specific flags, private endpoints, or unredacted execution output.
- Bind intentionally vulnerable services to loopback or an isolated network.
- Enforce target scope, permitted tools, command auditing, timeouts, and resource
  limits before executing model-generated commands.
- Keep the evaluation control plane outside the assessed process namespace and
  working directory.
- Follow [SECURITY.md](SECURITY.md) for vulnerability disclosure.

### Reproducibility and Integrity

- Pin Python dependencies and container images; record model identifiers and
  serving configuration.
- Run unit, integration, clean-build, and end-to-end smoke tests on a clean host.
- Verify that every documented command resolves to a shipped path and succeeds
  under the stated prerequisites.
- Generate `SHA256SUMS` and a machine-readable release manifest containing the
  paper PDF hash, Git commit, file hashes, sizes, licenses, and creation time.
- Keep generated results, secrets, caches, model weights, and local indexes out
  of the source archive unless explicitly documented and safely redacted.

## Release Sign-Off

Release sign-off must record the exact Git commit and identify the reviewers for
claims, scenario validation, statistical reproduction, and secret scanning. A
partially complete checklist must be reported as such; it is not evidence that
the paper results were reproduced.
