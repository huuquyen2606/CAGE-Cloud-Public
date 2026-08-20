# Data Card

## Summary

This public repository is primarily a source-code release. Its only bundled
data-like artifact is:

- `cage_cloud/fewshot/planner_examples.json`: 18 static examples used by the
  skill router to condition planner output.

The examples contain synthetic or illustrative assessment state, tasks, and
reasoning for AWS, Azure, GCP, and generic web-security contexts. They are not
evaluation outcomes and must not be used to calculate the paper's metrics.

## Relationship to Paper Version 11

The paper reports:

- a Planner-specialisation corpus of 328 cloud-related CVE records, split into
  296 training and 32 validation records;
- 86 validated Docker-based cloud-related evaluation scenarios; and
- 1,548 matched architecture-backbone-scenario runs.

None of those three datasets is included in this repository. This repository
also does not include the raw or redacted run records needed to reconstruct
Tables 6-9. The reported aggregate values in documentation are claims from the
paper, not values independently derivable from the files shipped here.

Toy Flask CVE emulators referenced by `testbed/inject_flags.py` are not included
here. If obtained from another package, they should be treated as toy API
emulators, not as the validated vulnerable scenarios described in the paper.

## Bundled Few-Shot Examples

| Property | Value |
| --- | --- |
| File | `cage_cloud/fewshot/planner_examples.json` |
| Format | JSON array |
| Records | 18 |
| Main fields | `id`, `skill`, `provider`, `stack`, `input_state`, `output` |
| Intended use | Runtime planner conditioning and software testing |
| Intended outcome | Structured candidate tasks, not verified security findings |
| Personal data | None intentionally included |
| Production credentials | None intentionally included |

The repository does not ship machine-readable generation provenance that would
support treating these 18 examples as a sample of the paper's 328-record
specialisation corpus. They should therefore be cited and analysed as a small,
repository-authored example bank only.

## Collection and Processing

The bundled records are structured illustrative examples, not observations
collected from production cloud tenants. They include hypothetical endpoints,
credentials, services, failures, and security actions to exercise routing and
planning behavior. No claim is made that their distribution represents real
cloud deployments or the paper's evaluation scenarios.

## Appropriate Uses

- Inspecting the expected planner input/output schema.
- Testing skill routing and prompt construction.
- Developing unit and smoke tests in isolated, authorised environments.
- Studying how structured state is presented to a planning component.

## Inappropriate Uses

- Reconstructing or validating the paper's reported FRR or telemetry.
- Treating an example task as evidence that a vulnerability is present.
- Training or benchmarking a model while claiming the paper's 296/32 split.
- Scanning or attacking systems without explicit authorisation.
- Using illustrative credentials, endpoints, or security conditions as
  production configuration.

## Limitations

- The example bank is small and hand-selected.
- It is not statistically representative of providers, CVEs, severity levels,
  products, or attack primitives.
- The outputs express proposed actions; they do not establish execution,
  exploitability, impact, provenance, or external success.
- Security knowledge and provider interfaces change over time, so all proposed
  actions require current, environment-specific validation.

## Licensing and Attribution

Repository-authored content is distributed under the repository's Apache-2.0
license. CVE identifiers, product names, cloud-provider names, and third-party
trademarks remain subject to their respective attribution and trademark terms.
Any future release of the 328-record corpus, the 86 scenarios, or run evidence
must include its own source provenance, data license, redaction record, and
artifact checksums.

## Safety and Maintenance

The examples contain dual-use offensive-security concepts. Use them only in
isolated systems that you own or are explicitly authorised to assess. Report
suspected secrets or unsafe content through the private process in
[SECURITY.md](SECURITY.md), not in a public issue.
