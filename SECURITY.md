# Security Policy

## Intended Use

CAGE-Cloud is dual-use security research software. Use it only against isolated
systems that you own or systems for which you have explicit written
authorisation. Do not expose intentionally vulnerable services to public or
untrusted networks.

This code release is not a safety boundary for production cloud assessments.
Model-generated commands, credentials, targets, and tool permissions require
independent operator controls.

## Supported Versions

Security fixes are applied to the default branch. Historical commits, research
snapshots, external lab bundles, model checkpoints, and forks are not supported
unless a release explicitly states otherwise.

## Reporting a Vulnerability

Do not disclose a vulnerability, credential, expected flag, private endpoint,
or exploit transcript in a public issue.

Use GitHub's private vulnerability reporting or Security Advisory workflow for
this repository. Include:

- the affected commit and file;
- prerequisites and a minimal reproduction;
- the security impact and affected trust boundary;
- whether any credential or sensitive artifact was exposed; and
- a proposed mitigation, if available.

If private GitHub reporting is unavailable, contact the corresponding author at
`haupv@uit.edu.vn` with the subject `CAGE-Cloud security report`. Encrypt or
redact sensitive material before sending it. A maintainer should acknowledge a
complete report within seven days; remediation timing depends on severity and
the need to coordinate disclosure.

## High-Priority Report Classes

- Escape from target, command, network, or tool scope.
- Access by the assessed pipeline to control-plane secrets or expected flags.
- Leakage of API keys, cloud credentials, tokens, private endpoints, or raw
  execution artifacts.
- False external-success decisions caused by missing target provenance or
  missing confirmation of the scenario-defined security condition.
- Command injection in orchestration, evaluation, or provisioning code.
- Unsafe default network exposure of intentionally vulnerable services.
- Dependency or container-image compromise affecting released artifacts.

## Artifact Boundary

This repository does not include the paper's 86 validated evaluation scenarios
or evidence from its 1,548 runs. Toy Flask CVE emulators referenced by conversion
utilities are not the paper testbed. Vulnerabilities in separately distributed
emulators should be reported to their distributor, unless the issue also affects
code in this repository.

The testbed flag utilities record issuance data, but a paper-valid positive
outcome additionally requires exact recovery, matching target-side issuance
provenance, and independent confirmation of the scenario-defined security
condition. A token match alone must not be interpreted as a production security
finding.

## Handling Secrets and Evaluation Data

- Keep `testbed/control_plane/`, scenario keys, nonces, expected flags, and
  validation metadata outside the assessed process namespace and working tree.
- Use unique run IDs for every architecture-backbone-scenario execution.
- Redact raw state, command output, prompts, and provider responses before
  sharing them.
- Rotate a credential immediately if there is any possibility it is real.
- Treat secret-scanner findings as unresolved until a human has verified and
  documented each false positive.

## Safe Development

- Bind lab ports to loopback or an isolated container network.
- Pin dependencies and images, and verify their checksums.
- Apply deterministic scope checks before executing generated commands.
- Run tests with synthetic credentials and non-production accounts.
- Do not add destructive, persistence, denial-of-service, or out-of-scope
  behavior to default workflows.
