#!/usr/bin/env python3
"""
Rule-based Skill Router + planner few-shot retriever (MVP).
"""

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


def route_planner_skill(state: Dict[str, Any], target_description: str = "") -> Tuple[str, str]:
    phase = str(state.get("current_phase", "recon")).lower()
    endpoints = state.get("web_endpoints", []) or []
    creds = state.get("credentials_found", {}) or {}
    cves = state.get("cve_candidates", []) or []
    failed_exploits = len(state.get("exploits_failed", []) or [])
    success_exploits = len(state.get("exploits_successful", []) or [])

    has_proxy = any("/proxy" in str(ep).lower() for ep in endpoints)
    has_target_url = bool(state.get("target_url"))

    if failed_exploits >= 2 and failed_exploits >= success_exploits:
        return "replan_after_fail", "Multiple exploit failures detected; replan required"
    if has_proxy and not creds:
        return "ssrf_to_metadata", "Proxy/SSRF surface exists but credentials not extracted yet"
    if creds:
        return "cloud_enum_after_creds", "Credentials available; prioritize cloud resource enumeration"
    if cves and phase in {"enum", "exploit"}:
        return "cve_validation", "CVE candidates exist and phase requires validation/exploitation planning"
    if has_target_url and not endpoints:
        return "web_recon_bootstrap", "Target URL present but endpoints not discovered"
    return "general_recon", "Default reconnaissance planning"


def load_planner_examples(path: Path = DEFAULT_FEWSHOT_PATH) -> List[Dict[str, Any]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, list):
            return [x for x in raw if isinstance(x, dict)]
    except Exception:
        pass
    return []


def retrieve_planner_examples(
    skill: str,
    provider: str,
    max_examples: int = 2,
    examples: List[Dict[str, Any]] | None = None,
) -> List[Dict[str, Any]]:
    examples = examples if examples is not None else load_planner_examples()
    provider = (provider or "aws").lower()

    def score(ex: Dict[str, Any]) -> int:
        ex_skill = str(ex.get("skill", "")).lower()
        ex_provider = str(ex.get("provider", "any")).lower()
        s = 0
        if ex_skill == skill:
            s += 10
        if ex_provider == provider:
            s += 4
        elif ex_provider == "any":
            s += 1
        return s

    ranked = sorted(examples, key=score, reverse=True)
    out = [ex for ex in ranked if score(ex) > 0][:max_examples]
    return out


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
        "FEW-SHOT EXAMPLES (Planner should follow schema/style, do not copy values blindly):",
    ]

    for i, ex in enumerate(examples, 1):
        lines.append(f"\nExample #{i} [{ex.get('id', 'n/a')}]")
        lines.append("Input State Summary:")
        lines.append(json.dumps(ex.get("input_state", {}), ensure_ascii=False))
        lines.append("Expected Planner Output JSON:")
        lines.append(json.dumps(ex.get("output", {}), ensure_ascii=False))

    return "\n".join(lines)

