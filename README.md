# CAGE-Cloud

**A Cloud-native Agentic Graph and Evidence-guided Framework for Autonomous Penetration Testing**

CAGE-Cloud is an autonomous cloud penetration-testing framework that separates
*language-model reasoning* from *deterministic execution-state handling*. Instead
of driving a single LLM over flat conversation history, CAGE-Cloud maintains a
normalised runner state and a **typed evidence graph**, uses **deterministic
parsers and an objective-level verifier** to ground findings in real execution
evidence, and applies **skill routing with stagnation-aware stopping** to bound
unproductive exploration.

This repository contains the framework code, the two re-implemented baseline
architectures used for comparison, the flag oracle for the cloud-CVE testbed,
and the metrics tooling — i.e. the code accompanying the paper.

---

## Core ideas

1. **Structured state via a typed evidence graph.** Discovered services,
   endpoints, credentials, CVE candidates, vulnerabilities and evidence are
   represented as typed nodes/edges. Each round the graph is distilled into a
   bounded summary (`≤ 120` nodes, `≤ 220` edges) that becomes the Planner's
   primary state input, replacing the opaque chat transcript with an auditable
   state object.
2. **Fully autonomous operation.** Planning, execution, output interpretation and
   stopping are handled end-to-end with no human in the loop: an LLM plans and
   synthesises commands, deterministic rule-based parsers interpret every output,
   a rule-based verifier assigns a per-objective status, and a deterministic
   stopping rule (no-progress counter, flag capture, or round budget) ends the run.
3. **Cost-efficient local planning via fine-tuning.** A Planner-only few-shot
   QLoRA pipeline adapts open-weight 27–32B backbones (Gemma2-27B, Qwen2.5-32B)
   to parity with commercial APIs at a fraction of the per-target token cost.
4. **A reproducible evaluation testbed.** A Docker-based set of 86 cloud-CVE labs,
   each instrumented with a synthetic `FLAG{<cve-id>_pwned}` oracle, enabling
   strict, reproducible measurement of end-to-end exploitation.

---

## Architecture

CAGE-Cloud is organised as a runner-state-driven loop over six components:

```
 target
   │
   ▼
Skill Router ──► Planner ──► Generator ──► Executor ──► Cloud-native Extractor
 (deterministic) (LLM)       (LLM)         (subprocess)  (provider-aware parse)
   ▲                                                          │
   │                                                          ▼
Graph Manager ◄──────────────── Evidence Verifier ◄───────────┘
 (typed evidence graph Gt)      (rule-based, 17 objective types)
```

At each round `t` the runner reconstructs a bounded, typed **graph summary** from
the current state, the **Skill Router** selects a skill family plus few-shot
exemplars, and the **Planner** (the only strategic LLM) emits a typed task list.
The **Generator** turns each task into one concrete command; the **Executor**
runs it in a subprocess under timeout limits; the **Cloud-native Extractor** and
the deterministic **parser** turn raw output into typed artefacts; and the
**Evidence Verifier** assigns each objective a status in
`{verified, partial, unverified}`. The **Graph Manager** folds artefacts and
verification records back into the next state. The LLM never interprets raw
`stdout`/`stderr` — this is the design choice that removes hallucinated
verification.

---

## Repository layout

```
cage_cloud/                 # the framework
├── schema.py               # typed schema: ObjectiveType, ActionProposal,
│                           #   GraphNode/GraphEdge, VerificationStatus, BudgetSnapshot
├── graph.py                # Agentic Evidence Graph (GraphState, build_graph_lite_state)
├── skill_router.py         # deterministic Skill Router + few-shot exemplar retriever
├── verifier.py             # rule-based Evidence Verifier (17 objective types)
├── scope_guard.py          # ScopeGuard policy module (net / command / budget policies)
├── orchestrator.py         # the Planner→Generator→Executor→Extractor→Verifier loop
│                           #   (RealExecutor, OutputParser, VULN_PATTERNS, AIClient)
├── rag/
│   ├── integration.py      # retrieval-augmented CVE-knowledge recall for the Planner
│   └── search.py           # embedding/keyword search backend over CVE documents
└── fewshot/
    └── planner_examples.json   # in-context exemplar bank used by the Skill Router

baselines/                  # faithful re-implementations used for comparison
├── vulnbot.py              # VulnBot-style sequential multi-agent baseline (B1)
└── pentestagent.py         # PentestAgent-style hierarchical RAG baseline (B2)

testbed/
├── cve_flags.json          # per-CVE flag oracle tokens (FLAG{<cve-id>_pwned})
├── inject_flags.py         # injects flags into the Docker CVE labs
└── flag_oracle.py          # strict flag-capture evaluator (grep token in raw output)

evaluation/
└── compute_metrics.py      # aggregates ECR, FCR, Req@T/S, Tok@T/S, SPM
```

---

## Installation

```bash
git clone https://github.com/huuquyen2606/CAGE-Cloud-Public.git
cd CAGE-Cloud-Public
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Only `requests` is required for the core pipeline and baselines. The
retrieval-augmented recall module (`cage_cloud.rag`) additionally needs
`numpy`, `torch`, `transformers` and `faiss-cpu` (commented in
`requirements.txt`); the pipeline degrades gracefully to keyword recall when
these are absent.

The Planner and Generator are served by any **OpenAI-compatible chat-completions
endpoint** (a hosted API, or a local server such as Ollama/vLLM). Configure it
through environment variables or CLI flags — no keys are hard-coded.

```bash
export API_URL="http://localhost:8000/v1"   # your OpenAI-compatible endpoint
export API_KEY="..."                        # if your endpoint requires one
```

---

## Usage

### 1. Run CAGE-Cloud against a target

```bash
python -m cage_cloud.orchestrator \
    --api-url "$API_URL" --api-key "$API_KEY" \
    --target-url "http://localhost:8080" \
    --target "cloud service pentest" \
    --max-rounds 5
```

Cloud credentials for authenticated enumeration can be supplied through the
`--aws-*`, `--azure-*` and `--gcp-*` flags (synthetic lab credentials only —
see *Responsible use*). Each run writes `<name>_state.json`, `<name>_exec.json`
and `<name>_report.md`.

### 2. Run a baseline (same Executor, different memory/verification)

```bash
python -m baselines.vulnbot      --target-url "http://localhost:8080"
python -m baselines.pentestagent --target-url "http://localhost:8080"
```

### 3. Score exploitation with the strict flag oracle

```bash
python -m testbed.flag_oracle path/to/results_dir [more_dirs ...]
# e.g. -> results_dir: 9/86 flags (10.5%)
```

### 4. Aggregate metrics

```bash
python evaluation/compute_metrics.py    # ECR, FCR, Req@T/S, Tok@T/S, SPM
```

---

## Testbed and flag oracle

The evaluation uses **86 held-out Docker CVE labs** that reproduce cloud-facing
attack surfaces (exposed metadata, leaked credentials, misconfigured storage,
vulnerable services, …). Each lab embeds a unique secret token
`FLAG{<cve-id>_pwned}` reachable only upon successful end-to-end exploitation of
that CVE. `testbed/flag_oracle.py` verifies a capture by an exact string match of
the token in the raw command output — a deterministic, CVE-specific,
non-fakeable proof of exploitation that does not rely on the agent's self-report.

---

## Evaluation metrics

For each of the `N = 86` CVE scenarios the harness logs the terminal verdict,
round count, LLM call count, token consumption and flag-capture events.

| Metric | Meaning |
| ------ | ------- |
| **ECR** (End-to-end Completion Rate) | fraction of scenarios reaching `VULN_FOUND` (at least one vulnerability **detected**) |
| **FCR** (Flag-Capture Rate) | of the `VULN_FOUND` runs, the proportion that additionally **capture the flag** (actually complete the exploit) |
| **Req@T / Req@S** | mean LLM calls per scenario / per success |
| **Tok@T / Tok@S** | mean tokens per scenario / per success |
| **SPM** | successes per million tokens (scale-invariant efficiency) |

**ECR measures *detection*; FCR measures *actual exploitation*.** They are
reported separately because a vulnerability can be flagged without the objective
being completed. On the 86-CVE testbed across six backbones, CAGE-Cloud attains a
mean ECR of ~60% (vs ~25% and ~11% for the PentestAgent- and VulnBot-style
baselines) and is the only architecture with a non-zero FCR (~17%); both
baselines record a 0% flag-capture rate under matched conditions.

---

## Implementation notes (scope & honesty)

To keep the code and the paper aligned, the current runner behaves as follows:

- **Skill Router.** The pipeline uses the six-family runner-side router in
  `cage_cloud/skill_router.py` (`replan_after_fail`, `ssrf_to_metadata`,
  `cloud_enum_after_creds`, `cve_validation`, `web_recon_bootstrap`,
  `general_recon`), scored `10·skill + 4·provider + 1·any`.
- **Evidence graph.** `cage_cloud/graph.py` defines a schema of 11 node types and
  13 edge types; the running pipeline reconstructs a *Planner-facing snapshot*
  from the runner state each round and populates the subset of types that appear
  during a run. The graph is a bounded state summary, not a persistent store.
- **Evidence Verifier.** Confidence is assigned by objective-specific heuristic
  handlers as discrete constants (verified `0.88–0.95`, partial `0.5–0.6`,
  unverified `0.0`); there is no continuous threshold gate or sigmoid.
- **ScopeGuard.** `cage_cloud/scope_guard.py` provides network/command/budget
  policy checks. In the current runner, staying within scope depends on the
  Planner/Generator following their prompt constraints; a deterministic
  pre-execution enforcement gate is left as future work.

---

## Responsible use

CAGE-Cloud is designed and evaluated **exclusively within authorised, isolated,
reproducible cloud-security laboratory environments** under a white-hat threat
model. The operational scope is restricted to reconnaissance, evidence
extraction and non-destructive lateral movement against Docker-based CVE labs
using **synthetic lab credentials only**. Do not point it at systems you are not
explicitly authorised to test. Destructive actions (DoS, data deletion,
persistence) are outside the intended scope.

---

## Citation

```bibtex
@article{cagecloud,
  title   = {CAGE-Cloud: A Cloud-native Agentic Graph and Evidence-guided
             Framework for Autonomous Penetration Testing},
  author  = {CAGE-Cloud authors},
  year    = {2026}
}
```

## License

Released under the [Apache License 2.0](LICENSE).
