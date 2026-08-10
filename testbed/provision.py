#!/usr/bin/env python3
"""Provision run-specific protected flags into targets before a benchmark run.

Glue between the control-plane issuer (:mod:`testbed.flag_issuer`) and the Docker
targets. For every scenario in a run it:

  1. issues a fresh run-specific flag (paper Eq. 26),
  2. returns the ``CAGE_PROTECTED_FLAG`` environment mapping to pass to the
     target container (``docker run -e CAGE_PROTECTED_FLAG=...``), and
  3. writes a ``flags_expected.json`` manifest into the run's results directory
     for the post-hoc oracle (:mod:`testbed.flag_oracle`).

The expected flag is never written into the target image, prompts, scenario
metadata, or any agent-visible input — it exists only in the container
environment (revealed solely behind the vulnerable endpoint) and in the
control-plane manifest used for scoring.
"""

from __future__ import annotations

import argparse
import json
import secrets
from pathlib import Path
from typing import Dict, List

from testbed.flag_issuer import issue_flag
from testbed.target_event import TARGET_EVENTS_ENV

ENV_VAR = "CAGE_PROTECTED_FLAG"


def provision_run(
    scenario_ids: List[str],
    results_dir: str,
    architecture: str = "",
    backbone: str = "",
) -> Dict[str, Dict[str, str]]:
    """Issue flags for each scenario and write the expected-flag manifest.

    Returns ``{cve_id: {"CAGE_PROTECTED_FLAG": flag, "CAGE_RUN_ID": run_id}}`` —
    the per-target environment to inject when the container is started.
    """
    out_dir = Path(results_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    env_by_scenario: Dict[str, Dict[str, str]] = {}
    expected_runs: List[Dict[str, object]] = []
    for cve in scenario_ids:
        prefix = "-".join(part for part in (cve, architecture, backbone) if part)
        run_id = f"{prefix}-{secrets.token_hex(8)}" if prefix else None
        rec = issue_flag(cve, run_id=run_id)
        env_by_scenario[cve] = {
            ENV_VAR: rec["flag"],
            "CAGE_RUN_ID": rec["run_id"],
            "CAGE_SCENARIO_ID": cve,
            "CAGE_SECURITY_CONDITION_ID": rec["security_condition_id"],
            TARGET_EVENTS_ENV: str(out_dir / "target_events.jsonl"),
        }
        expected_runs.append({
            "run_id": rec["run_id"],
            "scenario_id": cve,
            "architecture": architecture,
            "backbone": backbone,
            "security_condition_id": rec["security_condition_id"],
            "expected_flag": rec["flag"],
            "flag_digest": rec["flag_digest"],
            "issued_at": rec["issued_at"],
            "state_file": f"{cve}_state.json",
            "exec_file": f"{cve}_exec.json",
        })

    (out_dir / "flags_expected.json").write_text(
        json.dumps({"schema_version": 1, "runs": expected_runs}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return env_by_scenario


def _read_scenarios(cve_list_path: str) -> List[str]:
    text = Path(cve_list_path).read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip().startswith("CVE-")]


def main() -> int:
    ap = argparse.ArgumentParser(description="Provision run-specific protected flags.")
    ap.add_argument("--cve-list", required=True, help="file with one CVE id per line")
    ap.add_argument("--results-dir", required=True, help="run output directory")
    ap.add_argument("--architecture", default="", help="architecture label for this run batch")
    ap.add_argument("--backbone", default="", help="LLM backbone label for this run batch")
    args = ap.parse_args()

    scenarios = _read_scenarios(args.cve_list)
    env_map = provision_run(scenarios, args.results_dir, args.architecture, args.backbone)
    print(f"Provisioned {len(env_map)} scenarios; manifest -> {args.results_dir}/flags_expected.json")
    print("Pass each scenario's CAGE_PROTECTED_FLAG to its container, e.g.:")
    sample = next(iter(env_map.items()), None)
    if sample:
        cve, env = sample
        print(f"  docker run -e {ENV_VAR}={env[ENV_VAR]} ...   # {cve}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
