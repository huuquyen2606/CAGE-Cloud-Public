#!/usr/bin/env python3
"""
Core typed schema for the rule-first CloudGraph rebuild.

These models are intentionally dependency-light so they can be shared by
orchestrator, guard, graph, verifier, and executors without pulling in API
server frameworks.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class ObjectiveType(str, Enum):
    TARGET_REACHABLE = "target_reachable"
    ENDPOINT_DISCOVERY = "endpoint_discovery"
    STACK_FINGERPRINT = "stack_fingerprint"
    VERSION_CANDIDATE = "version_candidate"
    REVERSE_PROXY_DETECTED = "reverse_proxy_detected"
    AUTH_WORKFLOW_DETECTED = "auth_workflow_detected"
    STORAGE_ENDPOINT_DETECTED = "storage_endpoint_detected"
    CREDENTIAL_EXTRACTED = "credential_extracted"
    SESSION_ACQUIRED = "session_acquired"
    CLOUD_ENUM_SUCCESS = "cloud_enum_success"
    PROTECTED_RESOURCE_READ = "protected_resource_read"
    CVE_APPLICABILITY_VALIDATED = "cve_applicability_validated"
    PRECONDITION_SATISFIED = "precondition_satisfied"
    EXPLOIT_EFFECT_CONFIRMED = "exploit_effect_confirmed"
    POST_EXPLOIT_PIVOT = "post_exploit_pivot"
    REPORTABLE_FAILURE = "reportable_failure"
    GENERIC = "generic"


class ToolType(str, Enum):
    CLI = "cli"
    HTTP = "http"
    API = "api"
    VALIDATOR = "validator"
    INTERNAL = "internal"


class VerificationStatus(str, Enum):
    VERIFIED = "verified"
    PARTIAL = "partial"
    UNVERIFIED = "unverified"


@dataclass
class Fact:
    fact_type: str
    label: str
    value: str = ""
    source: str = ""
    confidence: float = 1.0
    attributes: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GraphNode:
    node_id: str
    node_type: str
    label: str
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GraphEdge:
    src: str
    rel: str
    dst: str
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceItem:
    evidence_id: str
    task_id: str
    action_id: str
    objective_type: ObjectiveType
    tool_type: ToolType
    command_or_request: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    return_code: Optional[int] = None
    http_status: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_snippet: str = ""
    json_paths: Dict[str, Any] = field(default_factory=dict)
    stdout_snippet: str = ""
    stderr_snippet: str = ""
    observed_entities: List[str] = field(default_factory=list)
    state_delta: Dict[str, Any] = field(default_factory=dict)
    expected_effect: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["objective_type"] = self.objective_type.value
        data["tool_type"] = self.tool_type.value
        return data


@dataclass
class ActionProposal:
    action_id: str
    action_type: str
    instruction: str
    target_service: str = ""
    cve_id: Optional[str] = None
    preconditions: List[str] = field(default_factory=list)
    expected_evidence: List[str] = field(default_factory=list)
    estimated_cost: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationResult:
    verification_id: str
    task_id: str
    action_id: str
    objective_type: ObjectiveType
    status: VerificationStatus
    confidence: float
    matched_rule_ids: List[str] = field(default_factory=list)
    supporting_evidence_ids: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
    reason: str = ""
    reportable: bool = True
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["objective_type"] = self.objective_type.value
        data["status"] = self.status.value
        return data


@dataclass
class BudgetSnapshot:
    llm_requests_used: int = 0
    llm_tokens_used: int = 0
    http_requests_used: int = 0
    tool_calls_used: int = 0
    elapsed_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
