# CAGE-Cloud

**Evidence-Grounded Autonomous Cloud Penetration Testing with Authoritative Structured State**

CAGE-Cloud is an autonomous cloud-oriented penetration-testing framework in
which a persistent normalized runner state is the operational authority. A
Typed Agentic Evidence Graph is materialized from committed state to provide
bounded relational context; it is not an independent source of truth. LLM
components propose tasks and commands, while controlled execution,
provider-aware artifact processing, and 17 deterministic objective handlers
decide whether evidence is `verified`, `partial`, or `unverified`.

This repository contains the framework, adapted PentestAgent-style and
VulnBot-style comparison pipelines, the external flag protocol, and evaluation
code accompanying the paper. It is intended only for authorized, isolated
laboratories.

## Architecture

At round `t`, the runner performs the paper's execution-to-state transition:

```text
state -> materialized graph -> bounded summary -> skill routing -> planning
      -> command generation -> controlled execution -> typed evidence
      -> artifact extraction -> objective verification -> committed state
```

The implementation includes:

- 11 graph node types and 13 directed relation types;
- eight deterministic skill families and an 18-example context bank;
- at most two contextual examples per planning round, ranked by
  `10*skill_match + 4*provider_match + 2*stack_match`;
- 17 objective-specific evidence handlers;
- a Planner-facing graph bound of 120 nodes and 220 edges; and
- early stopping after three completed rounds with an unchanged canonical
  committed-progress signature.

Only verified findings are confirmed planning preconditions. Partial and
unverified observations may remain in the trace with provenance, but do not
establish objective completion.

## Repository Layout

```text
cage_cloud/
  schema.py                typed action, evidence, graph, and verifier records
  graph.py                 state-derived graph and canonical progress signature
  skill_router.py          eight-family router and contextual-example retrieval
  verifier.py              17 deterministic objective handlers
  scope_guard.py           target, command, and budget checks
  orchestrator.py          Planner-to-commit execution loop
  rag/                     optional CVE-context retrieval
  fewshot/                 18 contextual Planner examples
baselines/
  pentestagent.py          adapted PentestAgent-style pipeline
  vulnbot.py               adapted VulnBot-style pipeline
testbed/
  flag_issuer.py           run-specific HMAC flag issuance (paper Eq. 26)
  provision.py             control-plane manifest and target environment setup
  target_event.py          target-side Eq. 27 provenance event writer
  flag_oracle.py           common external outcome evaluator (paper Eq. 27)
evaluation/
  compute_metrics.py       FRR, consistency, telemetry, and efficiency metrics
```

## Installation

```bash
git clone https://github.com/TuanHung1149/CAGE-Cloud-Public.git
cd CAGE-Cloud-Public
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Planner and Generator calls use an OpenAI-compatible chat-completions endpoint.
API keys are supplied at runtime and must not be committed.

```bash
export API_URL="http://localhost:8000/v1"
export API_KEY="..."

python -m cage_cloud.orchestrator \
  --api-url "$API_URL" \
  --api-key "$API_KEY" \
  --target-url "http://localhost:8080" \
  --target "authorized cloud security laboratory" \
  --max-rounds 15
```

## External Outcome Protocol

Each architecture-backbone-scenario run receives a fresh protected flag:

```text
phi(i,r) = FLAG{ Hex[ HMAC(k_i, run_id || nonce) ] }
```

`k_i`, the expected flag, and validation metadata remain in the evaluation
control plane. The assessed pipeline receives none of them. When the protected
condition is satisfied, the target writes a `target_events.jsonl` event with the
run ID, scenario ID, security-condition ID, timestamp, flag digest, and
`condition_satisfied: true`.

The oracle reports a positive outcome only when all conditions in paper Eq. 27
hold:

1. the exact run-specific flag occurs in retained execution observations;
2. a matching target-side issuance event exists; and
3. the scenario-defined security condition is confirmed.

```bash
python -m testbed.provision \
  --cve-list cves.txt \
  --results-dir results/cage-qwen-base \
  --architecture CAGE-Cloud \
  --backbone Qwen2.5-32B-base

python -m testbed.flag_oracle results/cage-qwen-base
python evaluation/compute_metrics.py results/cage-qwen-base
```

The manifest and target events are evaluation-control artifacts and are ignored
by Git.

## Metrics

The primary outcome is **Flag Recovery Rate (FRR)**. ECAR and VIDR are
operational telemetry, not exploitation-success measures. `Tok@T` is reported
as median `[Q1, Q3]`; `Tok@Req`, `Req@F`, `Tok@F`, FPMT, and FPkR are pooled
ratios.

The paper evaluates 86 validated Docker scenarios under three architectures and
six LLM configurations, for 1,548 runs. CAGE-Cloud recovers 53 flags in its 516
runs (FRR 10.3%; CVE-cluster bootstrap 95% interval 4.7-16.9%). The adapted
PentestAgent-style and VulnBot-style pipelines each recover 0/516 flags. These
numbers apply only to the paper's controlled protocol and do not imply a general
CVE exploitation rate.

## Reproducibility Scope

The public repository intentionally excludes control-plane secrets, expected
flags, raw execution traces, model weights, and other sensitive/generated
artifacts. The 328-record Planner-specialization corpus and the full validated
scenario archive are versioned separately in the research release. Their absence
from this repository must not be interpreted as a claim that the complete 1,548
run experiment can be reproduced from this checkout alone.

## Responsible Use

Use CAGE-Cloud only against systems for which you have explicit authorization.
The paper's experiments use freshly provisioned, researcher-controlled Docker
laboratories, scenario-scoped credentials, timeouts, bounded output capture, and
non-destructive policies. The controls reduce risk but are not a formally
verified sandbox for arbitrary untrusted code.

## Citation

```bibtex
@article{nguyen2026cagecloud,
  title  = {CAGE-Cloud: Evidence-Grounded Autonomous Cloud Penetration
            Testing with Authoritative Structured State},
  author = {Nguyen Huu, Quyen and Nguyen Tuan, Hung and Huynh Phan Thi, Nhu
            and Le Pham Khanh, Linh and Nguyen Thi My, Duyen and Pham, Van-Hau},
  year   = {2026}
}
```

## License

Released under the [Apache License 2.0](LICENSE).
