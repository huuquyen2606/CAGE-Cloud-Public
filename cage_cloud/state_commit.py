"""Deterministic Extract -> Verify -> Commit transition handling."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Dict, Iterable, Mapping


CONFIRMED_FIELDS = (
    "findings",
    "services_detected",
    "ports_open",
    "cve_candidates",
    "cve_candidates_info",
    "cve_tested",
    "cve_failed",
    "cve_success",
    "vulnerabilities_found",
    "exploits_successful",
    "exploits_failed",
    "web_endpoints",
    "credentials_found",
    "credential_sets",
    "dead_credentials",
    "flags_found",
    "secrets_found",
    "target_info",
    "cloud_artifacts",
    "urls_to_follow",
)


def _canonical_items(value: Any) -> set[str]:
    if isinstance(value, Mapping):
        return {
            json.dumps(
                {
                    "key": str(key),
                    "value_digest": (
                        hashlib.sha256(str(item).encode("utf-8")).hexdigest()[:16]
                        if item not in (None, "")
                        else ""
                    ),
                },
                sort_keys=True,
            )
            for key, item in value.items()
        }
    if isinstance(value, Iterable) and not isinstance(value, (str, bytes)):
        return {json.dumps(item, sort_keys=True, default=str) for item in value}
    return {json.dumps(value, sort_keys=True, default=str)}


def candidate_delta(before: Mapping[str, Any], after: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a secret-free summary of tentative additions."""
    delta: Dict[str, Any] = {}
    for field in CONFIRMED_FIELDS:
        old = _canonical_items(before.get(field, []))
        new = _canonical_items(after.get(field, []))
        additions = sorted(new - old)
        if additions:
            delta[field] = {"added_count": len(additions), "canonical_items": additions[:20]}
    return delta


def finalize_transition(
    state: Dict[str, Any],
    before: Mapping[str, Any],
    verification: Mapping[str, Any],
    task: Mapping[str, Any],
) -> Dict[str, Any]:
    """Commit confirmed indexes only for a verified objective."""
    delta = candidate_delta(before, state)
    evidence_ids = sorted(str(item) for item in verification.get("supporting_evidence_ids", []) or [])
    identity = json.dumps(
        {
            "task": task.get("id") or task.get("name"),
            "objective": verification.get("objective_type"),
            "evidence": evidence_ids,
            "delta": delta,
        },
        sort_keys=True,
        default=str,
    )
    observation = {
        "observation_id": "obs-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16],
        "task_id": task.get("id") or task.get("name", "unknown"),
        "objective_type": verification.get("objective_type", "unknown"),
        "status": verification.get("status", "unverified"),
        "supporting_evidence_ids": evidence_ids,
        "candidate_delta": delta,
    }

    if verification.get("status") != "verified":
        for field in CONFIRMED_FIELDS:
            if field in before:
                state[field] = copy.deepcopy(before[field])
            else:
                state.pop(field, None)

    state.setdefault("candidate_observations", []).append(observation)
    state.setdefault("objective_verifications", []).append(dict(verification))
    return observation
