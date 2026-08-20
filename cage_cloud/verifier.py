#!/usr/bin/env python3
"""
Rule-based evidence verifier v2 — Full 17-objective implementation.

Verifies cloud pentest actions using artifact-based rules, expected_evidence
contracts, confidence scoring, and failure taxonomy.

Input:
  - task: current task definition
  - action_proposal: ActionProposal with expected_evidence tags
  - evidence_artifacts: list of EvidenceItem dicts from executor
  - state_before / state_after: pentest state snapshots
  - graph_before / graph_after: optional graph state

Output:
  - VerificationResult with status (verified|partial|unverified), confidence,
    matched_rule_ids, supporting_evidence_ids, missing_evidence, reason
"""

from __future__ import annotations

from datetime import datetime
import re
from typing import Any, Dict, List, Optional, Set
from cage_cloud.schema import ObjectiveType, VerificationStatus


def _as_set(values: Any) -> Set[str]:
    """Convert various types to a set of strings."""
    if not values:
        return set()
    if isinstance(values, dict):
        return set(str(k) for k in values.keys())
    if isinstance(values, list):
        out = set()
        for v in values:
            if isinstance(v, dict):
                out.add(str(v.get("id") or v.get("description") or v))
            else:
                out.add(str(v))
        return out
    return {str(values)}


def _infer_objective_type(task: Dict[str, Any], action_proposal: Optional[Dict[str, Any]]) -> str:
    """
    Infer objective type from task phase, name, instruction, and action_proposal.
    Falls back to one of 17 ObjectiveType enum values.
    """
    # If action_proposal provides objective_type, prefer it
    if action_proposal and action_proposal.get("objective_type"):
        return action_proposal["objective_type"]

    phase = str(task.get("phase", "")).lower()
    name = str(task.get("name", "")).lower()
    instruction = str(task.get("instruction", "")).lower()
    action_type = action_proposal.get("action_type", "").lower() if action_proposal else ""

    text = f"{name} {instruction} {action_type}"

    # Map text patterns to 17 objective types
    if any(word in text for word in ["credential", "token", "secret", "api_key", "imds", "extract"]):
        return ObjectiveType.CREDENTIAL_EXTRACTED.value

    if any(word in text for word in ["session", "cookie", "bearer", "jwt", "authenticate"]):
        return ObjectiveType.SESSION_ACQUIRED.value

    if any(word in text for word in ["version", "fingerprint", "banner", "stack"]):
        if "cve" in text or "applicability" in text:
            return ObjectiveType.CVE_APPLICABILITY_VALIDATED.value
        return ObjectiveType.STACK_FINGERPRINT.value

    if any(word in text for word in ["endpoint", "discover", "enumerate", "port", "service"]):
        return ObjectiveType.ENDPOINT_DISCOVERY.value

    if any(word in text for word in ["proxy", "cdn", "waf", "reverse"]):
        return ObjectiveType.REVERSE_PROXY_DETECTED.value

    if any(word in text for word in ["auth", "login", "oauth", "workflow", "flow"]):
        return ObjectiveType.AUTH_WORKFLOW_DETECTED.value

    if any(word in text for word in ["storage", "bucket", "blob", "s3", "azure"]):
        return ObjectiveType.STORAGE_ENDPOINT_DETECTED.value

    if any(word in text for word in ["cloud", "enum", "aws", "gcp", "azure"]):
        return ObjectiveType.CLOUD_ENUM_SUCCESS.value

    if any(word in text for word in ["cve", "exploit", "vulnerability", "precondition"]):
        if "precondition" in text:
            return ObjectiveType.PRECONDITION_SATISFIED.value
        return ObjectiveType.EXPLOIT_EFFECT_CONFIRMED.value

    if any(word in text for word in ["read", "protected", "access", "retrieve"]):
        return ObjectiveType.PROTECTED_RESOURCE_READ.value

    if any(word in text for word in ["pivot", "post-exploit", "post_exploit", "lateral"]):
        return ObjectiveType.POST_EXPLOIT_PIVOT.value

    if any(word in text for word in ["reachable", "reach", "connect", "ping"]):
        return ObjectiveType.TARGET_REACHABLE.value

    if any(word in text for word in ["failure", "error", "fail", "denied", "unreachable"]):
        return ObjectiveType.REPORTABLE_FAILURE.value

    return ObjectiveType.GENERIC.value


# ============================================================================
# RULE HANDLERS - One function per major objective family
# ============================================================================


def _verify_target_reachable(
    artifacts: List[Dict[str, Any]], expected_tags: List[str]
) -> tuple[str, List[str], float]:
    """
    Rules:
    - HTTP_STATUS_REACHABLE: HTTP 200/301/302/401/403 → verified
    - TCP_CONNECT_REACHABLE: TCP handshake success → verified
    - DNS_RESOLVED: DNS only → partial
    Timeout/refused → unverified
    """
    matched_rules = []
    status = "unverified"
    confidence = 0.0

    for art in artifacts:
        http_status = art.get("http_status")
        response_headers = art.get("response_headers", {})
        stdout = art.get("stdout_snippet", "").lower()

        # HTTP reachability
        if http_status in [200, 301, 302, 401, 403]:
            matched_rules.append("HTTP_STATUS_REACHABLE")
            status = "verified"
            confidence = 0.95
            break

        # TCP reachability indicators
        if any(word in stdout for word in ["connected", "syn-ack", "established", "syn_ack"]):
            matched_rules.append("TCP_CONNECT_REACHABLE")
            status = "verified"
            confidence = 0.90
            break

        # DNS resolution only
        if "resolved" in stdout or response_headers.get("via"):
            if status != "verified":
                status = "partial"
                confidence = 0.6
                if "DNS_RESOLVED" not in matched_rules:
                    matched_rules.append("DNS_RESOLVED")

    if "timeout" in str(artifacts) or "refused" in str(artifacts):
        status = "unverified"
        confidence = 0.0
        matched_rules = []

    return status, matched_rules, confidence


def _verify_endpoint_discovery(
    artifacts: List[Dict[str, Any]], state_before: Dict[str, Any], state_after: Dict[str, Any]
) -> tuple[str, List[str], float]:
    """
    Rules:
    - ENDPOINT_ADDED_WITH_RESPONSE: New endpoint + valid response → verified
    - ENDPOINT_HINT_ONLY: Hint in log → partial
    - NO_NEW_ENDPOINT: No new endpoint → unverified
    """
    matched_rules = []
    status = "unverified"
    confidence = 0.0

    before_endpoints = _as_set(state_before.get("web_endpoints"))
    after_endpoints = _as_set(state_after.get("web_endpoints"))
    new_endpoints = after_endpoints - before_endpoints

    for art in artifacts:
        observed = set(art.get("observed_entities", []))
        response = art.get("response_snippet", "")
        http_status = art.get("http_status")

        if new_endpoints and observed:
            overlap = new_endpoints & {str(e) for e in observed}
            if overlap and http_status and http_status < 500:
                matched_rules.append("ENDPOINT_ADDED_WITH_RESPONSE")
                status = "verified"
                confidence = 0.90
                break

        if response and ("endpoint" in response.lower() or "path" in response.lower()):
            if status != "verified":
                status = "partial"
                confidence = 0.5
                matched_rules.append("ENDPOINT_HINT_ONLY")

    return status, matched_rules, confidence


def _verify_stack_fingerprint(artifacts: List[Dict[str, Any]]) -> tuple[str, List[str], float]:
    """
    Rules:
    - STACK_BANNER_MATCH: Banner/header/body match (Spring Boot, GitLab, nginx...) → verified
    - STACK_INDIRECT_HINT: Indirect hint → partial
    - NO_STACK_ARTIFACT: No artifact → unverified
    """
    matched_rules = []
    status = "unverified"
    confidence = 0.0

    stack_keywords = {
        "spring": "Spring Boot",
        "gitlab": "GitLab",
        "nginx": "nginx",
        "apache": "Apache",
        "microsoft-iis": "IIS",
        "tomcat": "Tomcat",
        "gunicorn": "Gunicorn",
        "uwsgi": "uWSGI",
        "django": "Django",
        "rails": "Rails",
    }

    for art in artifacts:
        headers = art.get("response_headers", {})
        body = art.get("response_snippet", "").lower()
        entities = [str(e).lower() for e in art.get("observed_entities", [])]

        # Check headers and body for strong matches
        for keyword, name in stack_keywords.items():
            if keyword in str(headers).lower():
                matched_rules.append("STACK_BANNER_MATCH")
                status = "verified"
                confidence = 0.95
                break
            if keyword in body:
                matched_rules.append("STACK_BANNER_MATCH")
                status = "verified"
                confidence = 0.90
                break

        if status == "verified":
            break

        # Indirect hints
        if body or entities:
            if status != "verified":
                status = "partial"
                confidence = 0.5
                matched_rules.append("STACK_INDIRECT_HINT")

    return status, matched_rules, confidence


def _verify_version_candidate(artifacts: List[Dict[str, Any]]) -> tuple[str, List[str], float]:
    """
    Rules:
    - VERSION_STRING_EXTRACTED: Clear version string → verified
    - VERSION_MAJOR_ONLY: Only major/family → partial
    - NO_VERSION_PROOF: No version proof → unverified
    """
    matched_rules = []
    status = "unverified"
    confidence = 0.0

    for art in artifacts:
        observed = art.get("observed_entities", [])
        json_paths = art.get("json_paths", {})
        snippet = art.get("response_snippet", "")

        # Look for version patterns like "1.2.3", "v1.2.3"
        version_pattern_found = False
        for entity in observed:
            entity_str = str(entity).lower()
            if any(c.isdigit() for c in entity_str) and "version" in entity_str:
                version_pattern_found = True
                break

        if version_pattern_found or any("version" in str(k).lower() for k in json_paths.keys()):
            matched_rules.append("VERSION_STRING_EXTRACTED")
            status = "verified"
            confidence = 0.88
            break

        # Weak signals: major version only
        if snippet and any(word in snippet.lower() for word in ["v1.", "v2.", "v3.", "version"]):
            if status != "verified":
                status = "partial"
                confidence = 0.55
                matched_rules.append("VERSION_MAJOR_ONLY")

    return status, matched_rules, confidence


def _verify_reverse_proxy_detected(artifacts: List[Dict[str, Any]]) -> tuple[str, List[str], float]:
    """
    Rules:
    - PROXY_VENDOR_HEADER: Strong headers (Via, cf-ray, x-cache, x-amz-cf-id) → verified
    - PROXY_WEAK_INDICATOR: Weak header (Server: nginx) → partial
    - NO_PROXY_ARTIFACT: Nothing → unverified
    """
    matched_rules = []
    status = "unverified"
    confidence = 0.0

    strong_proxy_headers = {"via", "cf-ray", "x-cache", "x-amz-cf-id", "x-forwarded-by"}
    weak_proxy_headers = {"server", "x-powered-by"}

    for art in artifacts:
        headers = {k.lower(): v for k, v in art.get("response_headers", {}).items()}

        # Strong proxy indicators
        for header in strong_proxy_headers:
            if header in headers:
                matched_rules.append("PROXY_VENDOR_HEADER")
                status = "verified"
                confidence = 0.92
                break

        if status == "verified":
            break

        # Weak indicators
        for header in weak_proxy_headers:
            if header in headers:
                if status != "verified":
                    status = "partial"
                    confidence = 0.6
                    matched_rules.append("PROXY_WEAK_INDICATOR")

    return status, matched_rules, confidence


def _verify_auth_workflow_detected(artifacts: List[Dict[str, Any]]) -> tuple[str, List[str], float]:
    """
    Rules:
    - AUTH_FLOW_CONFIRMED: Login form, 401→302, Set-Cookie, OAuth, JWT → verified
    - AUTH_PATH_HINT: Only /login path → partial
    - NO_AUTH_SIGNAL: No signal → unverified
    """
    matched_rules = []
    status = "unverified"
    confidence = 0.0

    for art in artifacts:
        headers = art.get("response_headers", {})
        body = art.get("response_snippet", "").lower()
        http_status = art.get("http_status")
        attributes = art.get("attributes", {})

        # Strong signals
        if "set-cookie" in str(headers).lower():
            matched_rules.append("AUTH_FLOW_CONFIRMED")
            status = "verified"
            confidence = 0.88
            break

        if any(word in body for word in ["login", "oauth", "jwt", "bearer", "authenticate"]):
            matched_rules.append("AUTH_FLOW_CONFIRMED")
            status = "verified"
            confidence = 0.85
            break

        if http_status == 401 or "401" in str(http_status):
            if status != "verified":
                status = "partial"
                confidence = 0.70
                matched_rules.append("AUTH_CHALLENGE_OBSERVED")

        # Weak signal: /login path only
        if "/login" in body or "login" in attributes.get("redirect_chain", ""):
            if status != "verified":
                status = "partial"
                confidence = 0.5
                matched_rules.append("AUTH_PATH_HINT")

    return status, matched_rules, confidence


def _verify_storage_endpoint_detected(artifacts: List[Dict[str, Any]]) -> tuple[str, List[str], float]:
    """
    Rules:
    - STORAGE_URL_OBSERVED: s3://, bucket host, blob URL, signed URL → verified
    - STORAGE_KEYWORD_ONLY: Keyword only → partial
    - NO_STORAGE_ARTIFACT: Nothing → unverified
    """
    matched_rules = []
    status = "unverified"
    confidence = 0.0

    storage_patterns = ["s3://", "blob.core", "storage.googleapis", "signed_url", "bucket", "object"]

    for art in artifacts:
        entities = art.get("observed_entities", [])
        body = art.get("response_snippet", "").lower()
        json_paths = art.get("json_paths", {})

        # Strong signals
        full_text = body + str(entities) + str(json_paths)
        for pattern in storage_patterns:
            if pattern in full_text:
                matched_rules.append("STORAGE_URL_OBSERVED")
                status = "verified"
                confidence = 0.90
                break

        if status == "verified":
            break

        # Weak signal: keyword only
        if any(word in body for word in ["storage", "bucket", "blob", "object"]):
            if status != "verified":
                status = "partial"
                confidence = 0.5
                matched_rules.append("STORAGE_KEYWORD_ONLY")

    return status, matched_rules, confidence


def _verify_credential_extracted(
    artifacts: List[Dict[str, Any]], state_before: Dict[str, Any], state_after: Dict[str, Any]
) -> tuple[str, List[str], float]:
    """
    Rules:
    - CREDENTIAL_KEYS_ADDED: New key + stored durably → verified
    - SESSION_SECRET_PARSED: Parser success but no key → partial
    - NO_NEW_CREDENTIAL: No new credential → unverified
    """
    matched_rules = []
    status = "unverified"
    confidence = 0.0

    before_creds = _as_set(state_before.get("credentials_found", {}))
    after_creds = _as_set(state_after.get("credentials_found", {}))
    new_creds = after_creds - before_creds

    for art in artifacts:
        observed = set(art.get("observed_entities", []))
        json_paths = art.get("json_paths", {})
        return_code = art.get("return_code")

        if new_creds or observed:
            overlap = new_creds & {str(e) for e in observed}
            if overlap:
                matched_rules.append("CREDENTIAL_KEYS_ADDED")
                status = "verified"
                confidence = 0.92
                break

        # Check json_paths for credential indicators
        for key in json_paths.keys():
            key_lower = str(key).lower()
            if any(word in key_lower for word in ["password", "token", "secret", "key", "api_key"]):
                matched_rules.append("CREDENTIAL_KEYS_ADDED")
                status = "verified"
                confidence = 0.88
                break

        if status == "verified":
            break

        # Partial: command success but no keys parsed
        if return_code == 0 and status != "verified":
            status = "partial"
            confidence = 0.5
            matched_rules.append("SESSION_SECRET_PARSED")

    return status, matched_rules, confidence


def _verify_session_acquired(
    artifacts: List[Dict[str, Any]], state_before: Dict[str, Any], state_after: Dict[str, Any]
) -> tuple[str, List[str], float]:
    """
    Rules:
    - SESSION_COOKIE_CAPTURED: New cookie/session ID → verified
    - BEARER_TOKEN_CAPTURED: Bearer token → verified
    - AUTH_REDIRECT_HINT: Redirect hint → partial
    - NO_SESSION_ARTIFACT: No artifact → unverified
    """
    matched_rules = []
    status = "unverified"
    confidence = 0.0

    before_creds = _as_set(state_before.get("credentials_found", {}))
    after_creds = _as_set(state_after.get("credentials_found", {}))
    new_creds = after_creds - before_creds

    for art in artifacts:
        headers = {k.lower(): v for k, v in art.get("response_headers", {}).items()}
        body = art.get("response_snippet", "").lower()
        attributes = art.get("attributes", {})

        # Strong signals
        if "set-cookie" in headers or "cookie" in str(attributes).lower():
            matched_rules.append("SESSION_COOKIE_CAPTURED")
            status = "verified"
            confidence = 0.90
            break

        if "authorization" in headers or "bearer" in body:
            matched_rules.append("BEARER_TOKEN_CAPTURED")
            status = "verified"
            confidence = 0.88
            break

        # State delta approach
        if new_creds and len(new_creds) > 0:
            matched_rules.append("SESSION_COOKIE_CAPTURED")
            status = "verified"
            confidence = 0.85
            break

        # Weak signal
        if art.get("http_status") in [301, 302, 303, 307]:
            if status != "verified":
                status = "partial"
                confidence = 0.55
                matched_rules.append("AUTH_REDIRECT_HINT")

    return status, matched_rules, confidence


def _verify_cloud_enum_success(
    artifacts: List[Dict[str, Any]], state_before: Dict[str, Any], state_after: Dict[str, Any]
) -> tuple[str, List[str], float]:
    """
    Rules:
    - RESOURCE_ENUM_PARSED: New bucket/role/VM/secret parsed → verified
    - ENUM_SUCCESS_EMPTY: Command success but output empty → partial
    - ALL_ENUM_FAILED: All fail → unverified
    """
    matched_rules = []
    status = "unverified"
    confidence = 0.0

    before_services = _as_set(state_before.get("services_detected", {}))
    after_services = _as_set(state_after.get("services_detected", {}))
    new_services = after_services - before_services

    for art in artifacts:
        observed = set(art.get("observed_entities", []))
        json_paths = art.get("json_paths", {})
        return_code = art.get("return_code")

        # Strong signal: new resources parsed
        if new_services or observed:
            resource_indicators = any(
                word in str(observed) for word in ["bucket", "role", "vm", "secret", "project"]
            )
            if resource_indicators or json_paths:
                matched_rules.append("RESOURCE_ENUM_PARSED")
                status = "verified"
                confidence = 0.88
                break

        # Partial: command success but empty
        if return_code == 0 and not observed and status != "verified":
            status = "partial"
            confidence = 0.45
            matched_rules.append("ENUM_SUCCESS_EMPTY")

    return status, matched_rules, confidence


def _verify_protected_resource_read(artifacts: List[Dict[str, Any]]) -> tuple[str, List[str], float]:
    """
    Rules:
    - PROTECTED_CONTENT_RETURNED: Actual content of protected object → verified
    - PROTECTED_METADATA_ONLY: Metadata only → partial
    - PROTECTED_DENIED: 403/401/404 → unverified
    """
    matched_rules = []
    status = "unverified"
    confidence = 0.0

    for art in artifacts:
        http_status = art.get("http_status")
        response = art.get("response_snippet", "")
        content_hash = art.get("attributes", {}).get("content_hash")

        # Denied states
        if http_status in [401, 403, 404, 405]:
            status = "unverified"
            confidence = 0.0
            matched_rules = ["PROTECTED_DENIED"]
            break

        # Success with content
        if http_status == 200 and response and len(response) > 50:
            matched_rules.append("PROTECTED_CONTENT_RETURNED")
            status = "verified"
            confidence = 0.92
            break

        # Metadata only
        if response and len(response) < 100:
            if status != "verified":
                status = "partial"
                confidence = 0.55
                matched_rules.append("PROTECTED_METADATA_ONLY")

    return status, matched_rules, confidence


def _verify_cve_applicability_validated(
    artifacts: List[Dict[str, Any]], expected_tags: List[str]
) -> tuple[str, List[str], float]:
    """
    Rules:
    - CVE_VERSION_MATCH: version_match in evidence → verified
    - CVE_PRECONDITION_MATCH: preconditions match → verified
    - VALIDATOR_EXPECTED_RESPONSE: validator output matches → verified
    - CVE_PARTIAL_MATCH: Only one condition → partial
    - CVE_NO_PROOF: LLM guess only → unverified
    """
    matched_rules = []
    status = "unverified"
    confidence = 0.0

    version_match_found = False
    precond_match_found = False
    validator_match_found = False

    for art in artifacts:
        attributes = art.get("attributes", {})

        if attributes.get("version_match"):
            matched_rules.append("CVE_VERSION_MATCH")
            version_match_found = True

        if attributes.get("precondition_match"):
            matched_rules.append("CVE_PRECONDITION_MATCH")
            precond_match_found = True

        if art.get("response_snippet") and "expected" in art.get("response_snippet", "").lower():
            matched_rules.append("VALIDATOR_EXPECTED_RESPONSE")
            validator_match_found = True

    # Determine status
    match_count = sum([version_match_found, precond_match_found, validator_match_found])

    if match_count >= 2:
        status = "verified"
        confidence = 0.88 + (0.05 * match_count)
    elif match_count == 1:
        status = "partial"
        confidence = 0.65
    else:
        status = "unverified"
        confidence = 0.0

    return status, matched_rules, confidence


def _verify_precondition_satisfied(
    artifacts: List[Dict[str, Any]], action_proposal: Optional[Dict[str, Any]]
) -> tuple[str, List[str], float]:
    """
    Rules:
    - PRECOND_ALL_PRESENT: All required preconditions evidence-backed → verified
    - PRECOND_PARTIAL: Some preconditions → partial
    - PRECOND_MISSING: Missing required → unverified
    """
    matched_rules = []
    status = "unverified"
    confidence = 0.0

    if not action_proposal:
        return "unverified", [], 0.0

    required_preconds = action_proposal.get("preconditions", [])
    if not required_preconds:
        return "verified", ["PRECOND_NONE_REQUIRED"], 1.0

    precond_satisfied = 0
    for precond in required_preconds:
        for art in artifacts:
            observed = art.get("observed_entities", [])
            if precond in str(observed) or precond in art.get("response_snippet", ""):
                precond_satisfied += 1
                break

    ratio = precond_satisfied / len(required_preconds) if required_preconds else 0

    if ratio == 1.0:
        matched_rules.append("PRECOND_ALL_PRESENT")
        status = "verified"
        confidence = 0.90
    elif ratio >= 0.5:
        status = "partial"
        confidence = 0.6
        matched_rules.append("PRECOND_PARTIAL")
    else:
        status = "unverified"
        confidence = 0.0
        matched_rules.append("PRECOND_MISSING")

    return status, matched_rules, confidence


def _verify_exploit_effect_confirmed(
    artifacts: List[Dict[str, Any]], state_before: Dict[str, Any], state_after: Dict[str, Any]
) -> tuple[str, List[str], float]:
    """
    Rules:
    - EXPLOIT_EFFECT_STATE_CHANGE: State change matching expected → verified
    - VALIDATOR_EFFECT_CONFIRMED: Validator confirms effect → verified
    - EXPLOIT_SUCCESS_WEAK: Command success but unclear → partial
    - NO_EXPLOIT_PROOF: No proof → unverified
    """
    matched_rules = []
    status = "unverified"
    confidence = 0.0

    for art in artifacts:
        expected_effect = art.get("expected_effect", "")
        response = art.get("response_snippet", "")
        attributes = art.get("attributes", {})
        state_delta = art.get("state_delta", {})

        # Only an executor- or target-observed effect can establish exploitation.
        # Parser changes to internal findings/credential collections are candidate
        # artifacts, not independent evidence of a target-side effect.
        observable_delta = any(
            state_delta.get(key)
            for key in (
                "observable_effects",
                "target_state_effects",
                "protected_resources",
                "exploitation_effects",
            )
        ) if isinstance(state_delta, dict) else False
        if observable_delta:
            matched_rules.append("EXPLOIT_EFFECT_STATE_CHANGE")
            status = "verified"
            confidence = 0.88
            break

        if expected_effect and expected_effect in response:
            matched_rules.append("VALIDATOR_EFFECT_CONFIRMED")
            status = "verified"
            confidence = 0.85
            break

        if any(
            attributes.get(key) is True
            for key in (
                "effect_confirmed",
                "target_state_effect",
                "protected_resource_access",
                "security_condition_satisfied",
            )
        ):
            matched_rules.append("VALIDATOR_EFFECT_CONFIRMED")
            status = "verified"
            confidence = 0.87
            break

        # Weak signal
        if art.get("return_code") == 0 and status != "verified":
            status = "partial"
            confidence = 0.5
            matched_rules.append("EXPLOIT_SUCCESS_WEAK")

    return status, matched_rules, confidence


def _verify_post_exploit_pivot(
    artifacts: List[Dict[str, Any]], state_before: Dict[str, Any], state_after: Dict[str, Any]
) -> tuple[str, List[str], float]:
    """
    Rules:
    - NEW_RELATION_DISCOVERED: New node/edge/asset → verified
    - NEW_RESOURCE_AFTER_EXPLOIT: New resource evidence → verified
    - PIVOT_FINDING_TEXT: Only finding text → partial
    - NO_PIVOT_STATE_CHANGE: No new artifacts → unverified
    """
    matched_rules = []
    status = "unverified"
    confidence = 0.0

    before_findings = _as_set(state_before.get("findings", {}))
    after_findings = _as_set(state_after.get("findings", {}))
    new_findings = after_findings - before_findings

    before_services = _as_set(state_before.get("services_detected", {}))
    after_services = _as_set(state_after.get("services_detected", {}))
    new_services = after_services - before_services

    for art in artifacts:
        observed = set(art.get("observed_entities", []))
        json_paths = art.get("json_paths", {})

        # Strong signals
        if new_services or new_findings:
            matched_rules.append("NEW_RESOURCE_AFTER_EXPLOIT")
            status = "verified"
            confidence = 0.88
            break

        if observed and len(observed) > 2:
            matched_rules.append("NEW_RELATION_DISCOVERED")
            status = "verified"
            confidence = 0.85
            break

        # Weak signal
        if new_findings and len(new_findings) == 1:
            if status != "verified":
                status = "partial"
                confidence = 0.55
                matched_rules.append("PIVOT_FINDING_TEXT")

    return status, matched_rules, confidence


def _verify_reportable_failure(artifacts: List[Dict[str, Any]]) -> tuple[str, List[str], float]:
    """
    Rules:
    - SCOPE_BLOCKED: Scope block error → verified (as reportable failure)
    - AUTH_DENIED: Auth denied → verified
    - NETWORK_UNREACHABLE: Network error → verified
    - TOOLING_FAILURE: Tool/format error → verified
    - FAILURE_UNCLASSIFIED: Fail but unclear → partial
    - NO_FAILURE_ARTIFACT: No failure → unverified
    """
    matched_rules = []
    status = "unverified"
    confidence = 0.0

    for art in artifacts:
        stderr = art.get("stderr_snippet", "").lower()
        stdout = art.get("stdout_snippet", "").lower()
        http_status = art.get("http_status")
        return_code = art.get("return_code")

        full_text = stderr + stdout

        # Strong failure classifications
        if any(word in full_text for word in ["out of scope", "scope_block"]):
            matched_rules.append("SCOPE_BLOCKED")
            status = "verified"
            confidence = 0.90
            break

        if http_status == 403 or any(word in full_text for word in ["unauthorized", "forbidden", "denied"]):
            matched_rules.append("AUTH_DENIED")
            status = "verified"
            confidence = 0.88
            break

        if "timeout" in full_text or "timed out" in full_text:
            matched_rules.append("TIMEOUT")
            status = "verified"
            confidence = 0.85
            break

        if any(word in full_text for word in ["connection refused", "network unreachable", "no route"]):
            matched_rules.append("NETWORK_UNREACHABLE")
            status = "verified"
            confidence = 0.85
            break

        if any(word in full_text for word in [
            "syntax", "parse", "format", "json error", "xml error",
            "command not found", "no such file or directory",
        ]):
            matched_rules.append("TOOLING_FAILURE")
            status = "verified"
            confidence = 0.80
            break

        # Partial: failure but unclear
        if (return_code != 0 or http_status and http_status >= 400) and status != "verified":
            status = "partial"
            confidence = 0.5
            matched_rules.append("FAILURE_UNCLASSIFIED")

    return status, matched_rules, confidence


def _verify_generic(
    artifacts: List[Dict[str, Any]], state_before: Dict[str, Any], state_after: Dict[str, Any]
) -> tuple[str, List[str], float]:
    """
    Rules:
    - GENERIC_STATE_CHANGE: State change or durable evidence → verified
    - GENERIC_SUCCESS_WEAK: Success but weak → partial
    - GENERIC_NO_EVIDENCE: No measurable change → unverified
    """
    matched_rules = []
    status = "unverified"
    confidence = 0.0

    before_keys = set(state_before.keys())
    after_keys = set(state_after.keys())

    state_changed = False
    for key in before_keys & after_keys:
        if state_before.get(key) != state_after.get(key):
            state_changed = True
            break

    for art in artifacts:
        observed = art.get("observed_entities", [])
        state_delta = art.get("state_delta", {})
        return_code = art.get("return_code")

        if state_changed or state_delta or observed:
            matched_rules.append("GENERIC_STATE_CHANGE")
            status = "verified"
            confidence = 0.80
            break

        if return_code == 0 and status != "verified":
            status = "partial"
            confidence = 0.45
            matched_rules.append("GENERIC_SUCCESS_WEAK")

    return status, matched_rules, confidence


# ============================================================================
# MAIN VERIFICATION FUNCTION
# ============================================================================


def verify_evidence(
    task: Dict[str, Any],
    action_proposal: Optional[Dict[str, Any]],
    evidence_artifacts: List[Dict[str, Any]],
    state_before: Dict[str, Any],
    state_after: Dict[str, Any],
    graph_before: Optional[Dict[str, Any]] = None,
    graph_after: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Verify evidence against 17 objective types with rule-based matching.

    Args:
        task: Task definition
        action_proposal: ActionProposal with expected_evidence tags
        evidence_artifacts: List of EvidenceItem dicts from executor
        state_before: Pentest state before action
        state_after: Pentest state after action
        graph_before: Optional graph state before
        graph_after: Optional graph state after

    Returns:
        VerificationResult dict with status, confidence, matched rules, etc.
    """
    verification_id = f"ver-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}"
    task_id = task.get("id", task.get("task_id", "unknown"))
    action_id = action_proposal.get("action_id", "unknown") if action_proposal else "unknown"

    # Infer objective type
    objective_type = _infer_objective_type(task, action_proposal)

    # Get expected evidence tags
    expected_tags = action_proposal.get("expected_evidence", []) if action_proposal else []

    # Dispatch to rule handlers based on objective type
    matched_rules = []
    status = "unverified"
    confidence = 0.0

    if objective_type == ObjectiveType.TARGET_REACHABLE.value:
        status, matched_rules, confidence = _verify_target_reachable(evidence_artifacts, expected_tags)

    elif objective_type == ObjectiveType.ENDPOINT_DISCOVERY.value:
        status, matched_rules, confidence = _verify_endpoint_discovery(
            evidence_artifacts, state_before, state_after
        )

    elif objective_type == ObjectiveType.STACK_FINGERPRINT.value:
        status, matched_rules, confidence = _verify_stack_fingerprint(evidence_artifacts)

    elif objective_type == ObjectiveType.VERSION_CANDIDATE.value:
        status, matched_rules, confidence = _verify_version_candidate(evidence_artifacts)

    elif objective_type == ObjectiveType.REVERSE_PROXY_DETECTED.value:
        status, matched_rules, confidence = _verify_reverse_proxy_detected(evidence_artifacts)

    elif objective_type == ObjectiveType.AUTH_WORKFLOW_DETECTED.value:
        status, matched_rules, confidence = _verify_auth_workflow_detected(evidence_artifacts)

    elif objective_type == ObjectiveType.STORAGE_ENDPOINT_DETECTED.value:
        status, matched_rules, confidence = _verify_storage_endpoint_detected(evidence_artifacts)

    elif objective_type == ObjectiveType.CREDENTIAL_EXTRACTED.value:
        status, matched_rules, confidence = _verify_credential_extracted(
            evidence_artifacts, state_before, state_after
        )

    elif objective_type == ObjectiveType.SESSION_ACQUIRED.value:
        status, matched_rules, confidence = _verify_session_acquired(
            evidence_artifacts, state_before, state_after
        )

    elif objective_type == ObjectiveType.CLOUD_ENUM_SUCCESS.value:
        status, matched_rules, confidence = _verify_cloud_enum_success(
            evidence_artifacts, state_before, state_after
        )

    elif objective_type == ObjectiveType.PROTECTED_RESOURCE_READ.value:
        status, matched_rules, confidence = _verify_protected_resource_read(evidence_artifacts)

    elif objective_type == ObjectiveType.CVE_APPLICABILITY_VALIDATED.value:
        status, matched_rules, confidence = _verify_cve_applicability_validated(evidence_artifacts, expected_tags)

    elif objective_type == ObjectiveType.PRECONDITION_SATISFIED.value:
        status, matched_rules, confidence = _verify_precondition_satisfied(evidence_artifacts, action_proposal)

    elif objective_type == ObjectiveType.EXPLOIT_EFFECT_CONFIRMED.value:
        status, matched_rules, confidence = _verify_exploit_effect_confirmed(
            evidence_artifacts, state_before, state_after
        )

    elif objective_type == ObjectiveType.POST_EXPLOIT_PIVOT.value:
        status, matched_rules, confidence = _verify_post_exploit_pivot(
            evidence_artifacts, state_before, state_after
        )

    elif objective_type == ObjectiveType.REPORTABLE_FAILURE.value:
        status, matched_rules, confidence = _verify_reportable_failure(evidence_artifacts)

    else:  # GENERIC
        status, matched_rules, confidence = _verify_generic(evidence_artifacts, state_before, state_after)

    # Collect supporting evidence IDs
    supporting_evidence_ids = [art.get("evidence_id", "") for art in evidence_artifacts if art.get("evidence_id")]

    # Identify missing evidence from expected_tags
    missing_evidence = []
    for tag in expected_tags:
        found = False
        for rule in matched_rules:
            if tag.upper() in rule.upper():
                found = True
                break
        if not found:
            missing_evidence.append(tag)

    # Determine failure taxonomy if unverified
    failure_class = None
    if status == "unverified":
        for art in evidence_artifacts:
            stderr = art.get("stderr_snippet", "").lower()
            http_status = art.get("http_status")
            if "scope" in stderr or "out of scope" in stderr:
                failure_class = "scope_block"
                break
            if http_status == 403 or "auth" in stderr:
                failure_class = "auth_denied"
                break
            if "timeout" in stderr or "timed out" in stderr:
                failure_class = "timeout"
                break
            if "connection" in stderr or "network unreachable" in stderr or "no route" in stderr:
                failure_class = "network_unreachable"
                break
            if any(marker in stderr for marker in (
                "format", "parse", "command not found", "no such file or directory"
            )):
                failure_class = "tooling_failure"
                break

    # Build reason string
    if status == "verified":
        reason = f"Objective verified via rules: {', '.join(matched_rules[:3])}"
    elif status == "partial":
        reason = f"Weak evidence; partial match via: {', '.join(matched_rules[:2])}"
    else:
        reason = f"No objective evidence found"
        if failure_class:
            reason += f"; classified as {failure_class}"

    # Build result dict
    result = {
        "verification_id": verification_id,
        "task_id": task_id,
        "action_id": action_id,
        "objective_type": objective_type,
        "status": status,
        "confidence": confidence,
        "matched_rule_ids": matched_rules,
        "supporting_evidence_ids": supporting_evidence_ids,
        "missing_evidence": missing_evidence,
        "reason": reason,
        "reportable": status in ["verified", "partial"],
        "metrics": {
            "artifacts_processed": len(evidence_artifacts),
            "rules_matched": len(matched_rules),
            "expected_evidence_found": len(expected_tags) - len(missing_evidence),
            "expected_evidence_total": len(expected_tags),
        },
        "evidence_summary": {
            "artifacts": [
                {
                    "id": art.get("evidence_id", ""),
                    "tool": art.get("tool_type", ""),
                    "http_status": art.get("http_status"),
                    "return_code": art.get("return_code"),
                }
                for art in evidence_artifacts[:5]
            ]
        },
        "timestamp": datetime.now().isoformat(),
    }

    return result


# ============================================================================
# BACKWARD COMPATIBILITY WRAPPER
# ============================================================================


def verify_task_execution(
    task: Dict[str, Any],
    command_results: List[Dict[str, Any]],
    state_before: Dict[str, Any],
    state_after: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Backward-compatible wrapper for existing code.
    Converts legacy verify_task_execution signature to verify_evidence.
    """
    # Convert command_results to the complete logical EvidenceItem interface.
    # The task is also the legacy ActionProposal, so expected evidence and
    # preconditions remain available to objective-specific handlers.
    artifacts = []
    task_id = str(task.get("id", task.get("task_id", "unknown")))
    action_id = str(task.get("action_id", task_id))
    evidence_batch_id = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    for idx, result in enumerate(command_results or []):
        protocol = result.get("protocol", {}) or {}
        attributes = dict(result.get("attributes", {}) or {})
        for metadata_key in ("provenance", "timeout", "target_metadata"):
            if metadata_key in result:
                attributes.setdefault(metadata_key, result[metadata_key])
        evidence_id = result.get("evidence_id")
        if not evidence_id:
            safe_task_id = re.sub(r"[^A-Za-z0-9_.-]+", "-", task_id).strip("-") or "unknown"
            safe_action_id = re.sub(r"[^A-Za-z0-9_.-]+", "-", action_id).strip("-") or "unknown"
            evidence_id = f"ev-{safe_task_id}-{safe_action_id}-{evidence_batch_id}-{idx}"
        artifact = {
            "evidence_id": evidence_id,
            "task_id": task_id,
            "action_id": action_id,
            "objective_type": task.get("objective_type"),
            "tool_type": result.get("tool_type", "cli"),
            "command_or_request": result.get(
                "command_or_request", result.get("command", result.get("request", ""))
            ),
            "timestamp": result.get("timestamp", datetime.now().isoformat()),
            "return_code": result.get("return_code"),
            "http_status": result.get(
                "http_status", result.get("status_code", protocol.get("status_code"))
            ),
            "response_headers": result.get(
                "response_headers", protocol.get("headers", {})
            ) or {},
            "response_snippet": result.get(
                "response_snippet",
                result.get("response", protocol.get("response", protocol.get("body", ""))),
            ) or "",
            "json_paths": result.get("json_paths", {}) or {},
            "stdout_snippet": result.get("stdout", "") or "",
            "stderr_snippet": result.get("stderr", "") or "",
            "observed_entities": result.get("observed_entities", []) or [],
            "state_delta": result.get("state_delta", {}) or {},
            "expected_effect": result.get("expected_effect", "") or "",
            "attributes": attributes,
        }
        artifacts.append(artifact)

    # Call new verifier
    return verify_evidence(
        task=task,
        action_proposal=task,
        evidence_artifacts=artifacts,
        state_before=state_before,
        state_after=state_after,
    )
