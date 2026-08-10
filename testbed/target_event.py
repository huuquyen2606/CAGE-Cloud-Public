#!/usr/bin/env python3
"""Emit target-side protected-condition events for the Eq. 27 oracle.

Targets call this helper only after the protected security condition is truly
satisfied. The helper never knows the expected flag in advance; it receives the
already-issued runtime flag value from the target process and records only its
digest together with run/scenario provenance.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Dict


DEFAULT_EVENTS_FILE = "target_events.jsonl"
TARGET_EVENTS_ENV = "CAGE_TARGET_EVENTS_FILE"
TARGET_FLAG_ENV = "CAGE_PROTECTED_FLAG"


def build_target_event(
    issued_flag: str | None = None,
    *,
    condition_satisfied: bool = True,
    extra: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    run_id = os.environ.get("CAGE_RUN_ID", "").strip()
    scenario_id = os.environ.get("CAGE_SCENARIO_ID", "").strip()
    security_condition_id = os.environ.get("CAGE_SECURITY_CONDITION_ID", "").strip()
    if not (run_id and scenario_id and security_condition_id):
        raise ValueError("missing CAGE_RUN_ID, CAGE_SCENARIO_ID, or CAGE_SECURITY_CONDITION_ID")

    flag_value = issued_flag if issued_flag is not None else os.environ.get(TARGET_FLAG_ENV, "")
    if not flag_value:
        raise ValueError(f"missing issued flag value; set {TARGET_FLAG_ENV} or pass issued_flag")

    event: Dict[str, Any] = {
        "run_id": run_id,
        "scenario_id": scenario_id,
        "security_condition_id": security_condition_id,
        "flag_digest": hashlib.sha256(flag_value.encode("utf-8")).hexdigest(),
        "timestamp": time.time(),
        "condition_satisfied": bool(condition_satisfied),
    }
    if extra:
        event.update(extra)
    return event


def emit_target_event(
    issued_flag: str | None = None,
    *,
    condition_satisfied: bool = True,
    events_file: str | None = None,
    extra: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    path = Path(
        events_file
        or os.environ.get(TARGET_EVENTS_ENV)
        or DEFAULT_EVENTS_FILE
    )
    path.parent.mkdir(parents=True, exist_ok=True)

    event = build_target_event(
        issued_flag,
        condition_satisfied=condition_satisfied,
        extra=extra,
    )

    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
    return event
