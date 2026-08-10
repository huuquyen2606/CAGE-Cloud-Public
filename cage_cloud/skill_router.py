#!/usr/bin/env python3
"""Deterministic skill routing and contextual-example retrieval (paper Section 4.2.2)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple


DEFAULT_FEWSHOT_PATH = Path(__file__).parent / "fewshot" / "planner_examples.json"


def infer_provider(state: Dict[str, Any], target_description: str = "") -> str:
    providers = state.get("cloud_providers", []) if isinstance(state, dict) else []
    if isinstance(providers, list) and providers:
        return str(providers[0]).lower()

    desc = (target_description or "").lower()
    if "azure" in desc:
        return "azure"
    if "gcp" in desc or "google" in desc:
        return "gcp"
    return "aws"


def infer_stack(state: Dict[str, Any]) -> str:
    """Return the first normalized software-stack label available in committed state."""
    for key in ("software_stack", "stack"):
        value = state.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    services = state.get("services_detected", []) or []
    return str(services[0]).strip().lower() if services else "generic"


def _verified_objectives(state: Dict[str, Any]) -> set[str]:
    return {
        str(item.get("objective_type", ""))
        for item in state.get("objective_verifications", []) or []
        if isinstance(item, dict) and item.get("status") == "verified"
    }


def route_planner_skill(state: Dict[str, Any], target_description: str = "") -> Tuple[str, str]:
    """Select the first matching family in the fixed priority order from paper Table 2."""
    endpoints = state.get("web_endpoints", []) or []
    credentials = state.get("credentials_found", {}) or {}
    cves = state.get("cve_candidates", []) or []
    failures = state.get("failure_history", []) or state.get("exploits_failed", []) or []
    verified = _verified_objectives(state)

    has_proxy = any(
        marker in str(endpoint).lower()
        for endpoint in endpoints
        for marker in ("/proxy", "ssrf", "redirect", "fetch")
    )
    has_auth_workflow = "auth_workflow_detected" in verified or any(
        marker in str(endpoint).lower()
        for endpoint in endpoints
        for marker in ("login", "auth", "signin", "oauth")
    )
    has_session = "session_acquired" in verified or bool(state.get("sessions"))
    has_exploit_effect = "exploit_effect_confirmed" in verified
    has_post_resource = "post_exploit_pivot" in verified or bool(
        state.get("cloud_resources") or state.get("protected_resources")
    )
    has_verified_precondition = "precondition_satisfied" in verified

    if len(failures) >= 2:
        return (
            "replan_after_failure",
            "At least two failures are committed and the failed path requires revision",
        )
    if has_exploit_effect or has_post_resource:
        return (
            "post_exploit_pivot",
            "A verified exploitation effect or newly accessible resource is available",
        )
    if has_auth_workflow and not has_session:
        return (
            "auth_bypass_or_session",
            "An authentication workflow is present without a verified session",
        )
    if has_proxy and not credentials:
        return (
            "ssrf_to_metadata",
            "An SSRF/proxy surface is present without a usable cloud credential",
        )
    if credentials:
        return (
            "cloud_enum_after_creds",
            "A credential-like artifact is available for provider validation or enumeration",
        )
    if cves and has_verified_precondition:
        return (
            "safe_exploit_validation",
            "A CVE candidate has verified preconditions for controlled validation",
        )
    if cves:
        return (
            "version_and_cve_validation",
            "A CVE candidate exists but applicability evidence remains incomplete",
        )
    return (
        "web_recon_bootstrap",
        "No committed service or endpoint context is available for the initial target",
    )


def load_planner_examples(path: Path = DEFAULT_FEWSHOT_PATH) -> List[Dict[str, Any]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []


def retrieve_planner_examples(
    skill: str,
    provider: str,
    stack: str = "generic",
    max_examples: int = 2,
    examples: List[Dict[str, Any]] | None = None,
) -> List[Dict[str, Any]]:
    """Rank examples with s(e)=10 I_skill + 4 I_provider + 2 I_stack."""
    examples = examples if examples is not None else load_planner_examples()
    provider = (provider or "").lower()
    stack = (stack or "").lower()

    def score(example: Dict[str, Any]) -> int:
        return (
            10 * (str(example.get("skill", "")).lower() == skill.lower())
            + 4 * (str(example.get("provider", "")).lower() == provider)
            + 2 * (str(example.get("stack", "")).lower() == stack)
        )

    ranked = sorted(examples, key=lambda item: (-score(item), str(item.get("id", ""))))
    return ranked[: max(0, max_examples)]


def format_planner_fewshot_block(
    skill: str,
    reason: str,
    examples: List[Dict[str, Any]],
) -> str:
    if not examples:
        return ""

    lines = [
        "SKILL ROUTER CONTEXT:",
        f"- Selected skill: {skill}",
        f"- Reason: {reason}",
        "",
        "CONTEXTUAL EXAMPLES (follow the schema; do not copy values):",
    ]
    for index, example in enumerate(examples, 1):
        lines.extend(
            [
                f"\nExample #{index} [{example.get('id', 'n/a')}]",
                "Input State Summary:",
                json.dumps(example.get("input_state", {}), ensure_ascii=False),
                "Expected Planner Output JSON:",
                json.dumps(example.get("output", {}), ensure_ascii=False),
            ]
        )
    return "\n".join(lines)
