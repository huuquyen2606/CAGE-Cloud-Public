#!/usr/bin/env python3
"""Architecture-independent external outcome oracle (paper Eq. 27).

A positive run requires the exact run-specific flag, a matching target-side
issuance event, and confirmation of the scenario-defined security condition.
The control-plane manifest is never exposed to the assessed pipeline.
"""

from __future__ import annotations

import hashlib
import json
import math
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List


MANIFEST_NAME = "flags_expected.json"
TARGET_EVENTS_NAME = "target_events.jsonl"


@dataclass(frozen=True)
class ExternalOutcome:
    run_id: str
    scenario_id: str
    exact_match: bool
    target_issued: bool
    condition_satisfied: bool
    external_success: bool
    protocol_errors: tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["protocol_errors"] = list(self.protocol_errors)
        return data


def load_manifest(results_dir: str | Path) -> List[Dict[str, Any]]:
    path = Path(results_dir) / MANIFEST_NAME
    if not path.exists():
        raise FileNotFoundError(f"missing control-plane manifest: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError(f"unsupported {MANIFEST_NAME} schema")
    runs = payload.get("runs")
    if not isinstance(runs, list):
        raise ValueError(f"{MANIFEST_NAME} must contain a runs list")

    required = {
        "run_id",
        "scenario_id",
        "security_condition_id",
        "expected_flag",
        "flag_digest",
        "issued_at",
    }
    seen: set[str] = set()
    for record in runs:
        if not isinstance(record, dict) or required.difference(record):
            raise ValueError(f"invalid run record in {MANIFEST_NAME}")
        run_id = str(record["run_id"])
        if run_id in seen:
            raise ValueError(f"duplicate run_id in manifest: {run_id}")
        seen.add(run_id)
        digest = hashlib.sha256(str(record["expected_flag"]).encode("utf-8")).hexdigest()
        if digest != record["flag_digest"]:
            raise ValueError(f"flag digest mismatch for {run_id}")
    return runs


def load_target_events(results_dir: str | Path) -> List[Dict[str, Any]]:
    path = Path(results_dir) / TARGET_EVENTS_NAME
    if not path.exists():
        return []
    events: List[Dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid target event at line {line_number}") from exc
        if not isinstance(event, dict):
            raise ValueError(f"target event at line {line_number} is not an object")
        events.append(event)
    return events


def execution_path(results_dir: str | Path, record: Dict[str, Any]) -> Path | None:
    root = Path(results_dir)
    candidates = [
        record.get("exec_file", ""),
        f"{record['run_id']}_exec.json",
        f"{record['scenario_id']}_exec.json",
    ]
    return next((root / name for name in candidates if name and (root / name).is_file()), None)


_OBSERVATION_FIELDS = {
    "stdout",
    "stderr",
    "stdout_snippet",
    "stderr_snippet",
    "response",
    "response_body",
    "response_snippet",
    "protocol_response",
}


def _string_leaves(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _string_leaves(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _string_leaves(item)


def retained_observations(payload: Any) -> Iterable[str]:
    """Yield only executor-retained observation fields, never commands or metadata."""
    if isinstance(payload, list):
        for item in payload:
            yield from retained_observations(item)
        return
    if not isinstance(payload, dict):
        return
    for key, value in payload.items():
        normalized_key = str(key).lower()
        if normalized_key in _OBSERVATION_FIELDS:
            yield from _string_leaves(value)
        elif normalized_key in {"protocol", "protocol_result"} and isinstance(value, dict):
            for protocol_key, protocol_value in value.items():
                if str(protocol_key).lower() in {
                    "body", "response", "response_body", "response_snippet"
                }:
                    yield from _string_leaves(protocol_value)
        elif normalized_key in {
            "execution", "executions", "execution_history", "records", "results"
        }:
            yield from retained_observations(value)


def _event_timestamp(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        converted = float(value)
        return converted if math.isfinite(converted) else None
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return float(value)
    except ValueError:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None


def evaluate_record(
    results_dir: str | Path,
    record: Dict[str, Any],
    events: Iterable[Dict[str, Any]],
) -> ExternalOutcome:
    path = execution_path(results_dir, record)
    execution_error = ""
    execution_payload: Any = None
    if path:
        try:
            execution_payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(execution_payload, (dict, list)):
                execution_error = "retained execution record must be a JSON object or list"
        except json.JSONDecodeError:
            execution_error = "invalid retained execution record JSON"
    expected_flag = str(record["expected_flag"])
    exact_match = any(expected_flag in observation for observation in retained_observations(execution_payload))
    issued_at = _event_timestamp(record.get("issued_at"))
    matching = [
        event
        for event in events
        if event.get("run_id") == record["run_id"]
        and event.get("scenario_id") == record["scenario_id"]
        and event.get("security_condition_id") == record["security_condition_id"]
        and event.get("flag_digest") == record["flag_digest"]
        and (event_timestamp := _event_timestamp(event.get("timestamp"))) is not None
        and (issued_at is None or event_timestamp >= issued_at)
    ]
    target_issued = bool(matching)
    condition_satisfied = any(event.get("condition_satisfied") is True for event in matching)
    errors: List[str] = []
    if path is None:
        errors.append("missing retained execution record")
    elif execution_error:
        errors.append(execution_error)
    if exact_match and not target_issued:
        errors.append("exact flag observed without matching target-side issuance")
    if target_issued and not condition_satisfied:
        errors.append("target issuance does not confirm the security condition")
    success = exact_match and target_issued and condition_satisfied
    return ExternalOutcome(
        run_id=str(record["run_id"]),
        scenario_id=str(record["scenario_id"]),
        exact_match=exact_match,
        target_issued=target_issued,
        condition_satisfied=condition_satisfied,
        external_success=success,
        protocol_errors=tuple(errors),
    )


def evaluate_results_dir(results_dir: str | Path) -> List[ExternalOutcome]:
    records = load_manifest(results_dir)
    events = load_target_events(results_dir)
    return [evaluate_record(results_dir, record, events) for record in records]


def recovered_flags(results_dir: str, _expected: Dict[str, str] | None = None) -> List[str]:
    """Compatibility helper returning successful scenario identifiers."""
    return sorted(
        outcome.scenario_id
        for outcome in evaluate_results_dir(results_dir)
        if outcome.external_success
    )


def main(argv: List[str]) -> int:
    if not argv:
        print(__doc__)
        return 1
    exit_code = 0
    for directory in argv:
        outcomes = evaluate_results_dir(directory)
        successes = [outcome for outcome in outcomes if outcome.external_success]
        errors = [error for outcome in outcomes for error in outcome.protocol_errors]
        frr = 100.0 * len(successes) / len(outcomes) if outcomes else 0.0
        print(f"{directory}: FRR = {len(successes)}/{len(outcomes)} = {frr:.1f}%")
        print(f"  protocol audit: {'PASS' if not errors else 'FAIL'}")
        for error in errors:
            print(f"    - {error}")
        if errors:
            exit_code = 2
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
