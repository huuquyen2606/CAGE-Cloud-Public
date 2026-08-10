#!/usr/bin/env python3
"""Compute the outcome and telemetry metrics defined in paper Section 5.5.

The external outcome is delegated to :mod:`testbed.flag_oracle`; internal
verifier records, return codes, and exploit-labelled commands never establish
Flag Recovery Rate (FRR).
"""

from __future__ import annotations

import csv
import json
import math
import random
import statistics
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

from testbed.flag_oracle import evaluate_results_dir, load_manifest


EXPECTED_BACKBONES = 6


@dataclass
class RunMetrics:
    run_id: str
    cve: str
    architecture: str
    backbone: str
    severity: str = ""
    cloud_type: str = ""
    flag_recovered: int = 0
    protocol_valid: int = 1
    vulnerability_indicators: int = 0
    exploit_activity: int = 0
    services: int = 0
    credentials: int = 0
    llm_requests: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0


def _count(value: Any) -> int:
    return len(value) if isinstance(value, (dict, list, tuple, set)) else 0


def _read_state(results_dir: Path, record: Dict[str, Any]) -> Dict[str, Any]:
    candidates = [
        record.get("state_file", ""),
        f"{record['run_id']}_state.json",
        f"{record['scenario_id']}_state.json",
    ]
    path = next((results_dir / name for name in candidates if name and (results_dir / name).is_file()), None)
    if path is None:
        raise FileNotFoundError(f"missing state record for run {record['run_id']}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"state record is not an object: {path}")
    return payload


def _llm_metrics(state: Dict[str, Any]) -> tuple[int, int, int, int]:
    metrics = state.get("llm_metrics", {}) or {}
    requests = int(
        metrics.get("total_requests")
        or int(metrics.get("planner_requests", 0)) + int(metrics.get("generator_requests", 0))
    )
    input_tokens = int(metrics.get("total_input_tokens", metrics.get("input_tokens", 0)) or 0)
    output_tokens = int(metrics.get("total_output_tokens", metrics.get("output_tokens", 0)) or 0)
    recorded_total = int(metrics.get("total_tokens", 0) or 0)
    total_tokens = recorded_total or input_tokens + output_tokens
    return requests, input_tokens, output_tokens, total_tokens


def load_runs(results_dir: str | Path) -> List[RunMetrics]:
    root = Path(results_dir)
    records = load_manifest(root)
    outcomes = {item.run_id: item for item in evaluate_results_dir(root)}
    runs: List[RunMetrics] = []
    seen_cells: set[tuple[str, str, str]] = set()
    for record in records:
        state = _read_state(root, record)
        outcome = outcomes[str(record["run_id"])]
        architecture = str(record.get("architecture") or state.get("architecture") or state.get("pipeline") or "")
        backbone = str(record.get("backbone") or state.get("backbone") or state.get("model") or "")
        cell = (str(record["scenario_id"]), architecture, backbone)
        if all(cell) and cell in seen_cells:
            raise ValueError(f"duplicate scenario-architecture-backbone cell: {cell}")
        seen_cells.add(cell)
        requests, input_tokens, output_tokens, total_tokens = _llm_metrics(state)
        runs.append(
            RunMetrics(
                run_id=str(record["run_id"]),
                cve=str(record["scenario_id"]),
                architecture=architecture,
                backbone=backbone,
                severity=str(record.get("severity") or state.get("severity") or ""),
                cloud_type=str(record.get("cloud_type") or state.get("cloud_type") or ""),
                flag_recovered=int(outcome.external_success),
                protocol_valid=int(not outcome.protocol_errors),
                vulnerability_indicators=_count(state.get("vulnerabilities_found", [])),
                exploit_activity=(
                    _count(state.get("exploits_successful", []))
                    + _count(state.get("exploits_failed", []))
                ),
                services=_count(state.get("services_detected", [])),
                credentials=_count(state.get("credentials_found", {})),
                llm_requests=requests,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                total_tokens=total_tokens,
            )
        )
    return runs


def _quantile(values: Sequence[int], probability: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def _quantile_float(values: Sequence[float], probability: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def cluster_bootstrap_interval(
    runs: Sequence[RunMetrics],
    *,
    iterations: int = 10_000,
    seed: int = 0,
) -> tuple[float, float]:
    if not runs:
        return (0.0, 0.0)
    by_cve: Dict[str, List[RunMetrics]] = {}
    for run in runs:
        by_cve.setdefault(run.cve, []).append(run)
    clusters = list(by_cve.values())
    if not clusters:
        return (0.0, 0.0)
    rng = random.Random(seed)
    estimates: List[float] = []
    for _ in range(iterations):
        sample: List[RunMetrics] = []
        for _cluster_index in range(len(clusters)):
            sample.extend(rng.choice(clusters))
        flags = sum(run.flag_recovered for run in sample)
        estimates.append(flags / len(sample) if sample else 0.0)
    return (
        _quantile_float(estimates, 0.025),
        _quantile_float(estimates, 0.975),
    )


def summarize(runs: Sequence[RunMetrics]) -> Dict[str, Any]:
    total = len(runs)
    flags = sum(run.flag_recovered for run in runs)
    requests = sum(run.llm_requests for run in runs)
    tokens = sum(run.total_tokens for run in runs)
    token_values = [run.total_tokens for run in runs]

    def rate(attribute: str) -> float:
        return sum(getattr(run, attribute) > 0 for run in runs) / total if total else 0.0

    def yield_per_target(attribute: str) -> float:
        return sum(getattr(run, attribute) for run in runs) / total if total else 0.0

    low, high = cluster_bootstrap_interval(runs)
    return {
        "N": total,
        "flags": flags,
        "FRR": flags / total if total else 0.0,
        "FRR_CI_low": low,
        "FRR_CI_high": high,
        "FRR_CI_method": "scenario_cluster_bootstrap_95",
        "VIDR": rate("vulnerability_indicators"),
        "VIY@T": yield_per_target("vulnerability_indicators"),
        "ECAR": rate("exploit_activity"),
        "ECY@T": yield_per_target("exploit_activity"),
        "SDR": rate("services"),
        "SY@T": yield_per_target("services"),
        "CAR": rate("credentials"),
        "CY@T": yield_per_target("credentials"),
        "Req@T": requests / total if total else 0.0,
        "Tok@T_median": statistics.median(token_values) if token_values else 0.0,
        "Tok@T_Q1": _quantile(token_values, 0.25),
        "Tok@T_Q3": _quantile(token_values, 0.75),
        "Tok@Req": tokens / requests if requests else None,
        "Req@F": requests / flags if flags else None,
        "Tok@F": tokens / flags if flags else None,
        "FPMT": 1_000_000 * flags / tokens if tokens else 0.0,
        "FPkR": 1_000 * flags / requests if requests else 0.0,
        "recorded_requests": requests,
        "recorded_tokens": tokens,
    }


def group_summaries(runs: Sequence[RunMetrics], fields: Sequence[str]) -> Dict[str, Dict[str, Any]]:
    groups: Dict[str, List[RunMetrics]] = {}
    for run in runs:
        label = " / ".join(str(getattr(run, field)) for field in fields)
        groups.setdefault(label, []).append(run)
    return {label: summarize(group) for label, group in sorted(groups.items())}


def group_summaries_nonempty(
    runs: Sequence[RunMetrics],
    fields: Sequence[str],
) -> Dict[str, Dict[str, Any]]:
    filtered = [
        run for run in runs
        if all(str(getattr(run, field)).strip() for field in fields)
    ]
    return group_summaries(filtered, fields)


def coverage_by_architecture(runs: Sequence[RunMetrics]) -> Dict[str, Dict[str, float]]:
    by_architecture: Dict[str, List[RunMetrics]] = {}
    for run in runs:
        by_architecture.setdefault(run.architecture, []).append(run)
    result: Dict[str, Dict[str, float]] = {}
    for architecture, architecture_runs in sorted(by_architecture.items()):
        by_cve: Dict[str, List[RunMetrics]] = {}
        for run in architecture_runs:
            by_cve.setdefault(run.cve, []).append(run)
        any_count = sum(any(run.flag_recovered for run in group) for group in by_cve.values())
        all_count = sum(
            len({run.backbone for run in group}) == EXPECTED_BACKBONES
            and all(run.flag_recovered for run in group)
            for group in by_cve.values()
        )
        denominator = len(by_cve)
        result[architecture] = {
            "ABFC": any_count / denominator if denominator else 0.0,
            "ALBFC": all_count / denominator if denominator else 0.0,
            "covered_any": any_count,
            "covered_all": all_count,
            "scenarios": denominator,
        }
    return result


def exact_mcnemar(left: Sequence[int], right: Sequence[int]) -> float:
    if len(left) != len(right):
        raise ValueError("paired outcomes must have the same length")
    b = sum(a == 1 and c == 0 for a, c in zip(left, right))
    c = sum(a == 0 and c == 1 for a, c in zip(left, right))
    discordant = b + c
    if discordant == 0:
        return 1.0
    tail = sum(math.comb(discordant, k) for k in range(min(b, c) + 1)) / (2**discordant)
    return min(1.0, 2.0 * tail)


def matched_comparisons(runs: Sequence[RunMetrics]) -> List[Dict[str, Any]]:
    architectures = sorted({run.architecture for run in runs})
    cage_names = [name for name in architectures if name.lower() in {"cage-cloud", "cloudpentest", "cage_cloud"}]
    if not cage_names:
        return []
    cage = cage_names[0]
    comparisons: List[Dict[str, Any]] = []
    for baseline in (name for name in architectures if name != cage):
        for backbone in sorted({run.backbone for run in runs}):
            left = {run.cve: run.flag_recovered for run in runs if run.architecture == cage and run.backbone == backbone}
            right = {run.cve: run.flag_recovered for run in runs if run.architecture == baseline and run.backbone == backbone}
            common = sorted(left.keys() & right.keys())
            if common:
                comparisons.append({
                    "baseline": baseline,
                    "backbone": backbone,
                    "pairs": len(common),
                    "p_exact": exact_mcnemar([left[cve] for cve in common], [right[cve] for cve in common]),
                })
    ordered = sorted(range(len(comparisons)), key=lambda index: comparisons[index]["p_exact"])
    running = 0.0
    for rank, index in enumerate(ordered):
        adjusted = min(1.0, comparisons[index]["p_exact"] * (len(ordered) - rank))
        running = max(running, adjusted)
        comparisons[index]["p_holm"] = running
    return comparisons


def _format_ratio(value: Any, decimals: int = 2) -> str:
    return "--" if value is None else f"{value:,.{decimals}f}"


def write_csv(runs: Iterable[RunMetrics], path: Path) -> None:
    rows = [asdict(run) for run in runs]
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def write_report(runs: Sequence[RunMetrics], path: Path) -> None:
    configs = group_summaries(runs, ("backbone", "architecture"))
    architectures = group_summaries(runs, ("architecture",))
    severities = group_summaries_nonempty(runs, ("severity", "architecture"))
    clouds = group_summaries_nonempty(runs, ("cloud_type", "architecture"))
    coverage = coverage_by_architecture(runs)
    protocol_errors = sum(not run.protocol_valid for run in runs)
    lines = [
        "# Paper-Aligned Evaluation Report",
        "",
        f"Runs retained: {len(runs)}",
        f"Protocol-integrity audit: {'PASS' if protocol_errors == 0 else 'FAIL'}",
        "",
        "## End-to-End Effectiveness",
        "",
        "FRR intervals below use 95% scenario-cluster bootstrap, matching the paper.",
        "",
        "| Backbone / Architecture | Flags | FRR [95% cluster bootstrap CI] |",
        "|---|---:|---:|",
    ]
    for label, metric in configs.items():
        lines.append(
            f"| {label} | {metric['flags']}/{metric['N']} | "
            f"{100*metric['FRR']:.1f}% [{100*metric['FRR_CI_low']:.1f}, {100*metric['FRR_CI_high']:.1f}] |"
        )
    lines.extend([
        "",
        "## Architecture Telemetry",
        "",
        "ECAR and ECY@T measure exploit-stage activity, not end-to-end exploit success.",
        "",
        "| Architecture | VIDR | VIY@T | ECAR | ECY@T | SDR | SY@T | CAR | CY@T | ABFC | ALBFC |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for architecture, metric in architectures.items():
        cov = coverage.get(architecture, {})
        lines.append(
            f"| {architecture} | {100*metric['VIDR']:.1f}% | {metric['VIY@T']:.2f} | "
            f"{100*metric['ECAR']:.1f}% | {metric['ECY@T']:.2f} | {100*metric['SDR']:.1f}% | "
            f"{metric['SY@T']:.2f} | {100*metric['CAR']:.1f}% | {metric['CY@T']:.2f} | "
            f"{100*cov.get('ABFC', 0):.1f}% | {100*cov.get('ALBFC', 0):.1f}% |"
        )
    lines.extend(["", "## Request, Token, and Outcome Efficiency", "", "| Backbone / Architecture | Req@T | Tok@T median [Q1, Q3] | Tok@Req | Req@F | Tok@F | FPMT | FPkR |", "|---|---:|---:|---:|---:|---:|---:|---:|"])
    for label, metric in configs.items():
        lines.append(
            f"| {label} | {metric['Req@T']:.1f} | {metric['Tok@T_median']:,.0f} "
            f"[{metric['Tok@T_Q1']:,.0f}, {metric['Tok@T_Q3']:,.0f}] | "
            f"{_format_ratio(metric['Tok@Req'], 0)} | {_format_ratio(metric['Req@F'], 1)} | "
            f"{_format_ratio(metric['Tok@F'], 0)} | {metric['FPMT']:.2f} | {metric['FPkR']:.2f} |"
        )
    comparisons = matched_comparisons(runs)
    if comparisons:
        lines.extend(["", "## Matched Comparisons", "", "| Baseline | Backbone | Pairs | Exact McNemar p | Holm-adjusted p |", "|---|---|---:|---:|---:|"])
        for item in comparisons:
            lines.append(
                f"| {item['baseline']} | {item['backbone']} | {item['pairs']} | "
                f"{item['p_exact']:.4g} | {item['p_holm']:.4g} |"
            )
    if severities:
        lines.extend(["", "## Severity Breakdown", "", "| Severity / Architecture | Flags | FRR | VIDR | ECAR |", "|---|---:|---:|---:|---:|"])
        for label, metric in severities.items():
            lines.append(
                f"| {label} | {metric['flags']}/{metric['N']} | {100*metric['FRR']:.1f}% | "
                f"{100*metric['VIDR']:.1f}% | {100*metric['ECAR']:.1f}% |"
            )
    if clouds:
        lines.extend(["", "## Cloud Breakdown", "", "| Cloud / Architecture | Flags | FRR | VIDR | ECAR |", "|---|---:|---:|---:|---:|"])
        for label, metric in clouds.items():
            lines.append(
                f"| {label} | {metric['flags']}/{metric['N']} | {100*metric['FRR']:.1f}% | "
                f"{100*metric['VIDR']:.1f}% | {100*metric['ECAR']:.1f}% |"
            )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: Sequence[str]) -> int:
    if len(argv) != 1:
        print("usage: python evaluation/compute_metrics.py RESULTS_DIR", file=sys.stderr)
        return 1
    results_dir = Path(argv[0])
    try:
        runs = load_runs(results_dir)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"evaluation error: {exc}", file=sys.stderr)
        return 2
    write_csv(runs, results_dir / "metrics_full.csv")
    write_report(runs, results_dir / "evaluation_report.md")
    invalid = sum(not run.protocol_valid for run in runs)
    print(f"runs={len(runs)} protocol_audit={'PASS' if invalid == 0 else 'FAIL'}")
    for architecture, metrics in group_summaries(runs, ("architecture",)).items():
        print(f"{architecture}: FRR={metrics['flags']}/{metrics['N']} ({100*metrics['FRR']:.1f}%)")
    return 0 if invalid == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
