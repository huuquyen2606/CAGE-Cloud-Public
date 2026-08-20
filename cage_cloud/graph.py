#!/usr/bin/env python3
"""
Persistent graph state module for cloud penetration testing.

Replaces MVP graph_lite.py with a full in-memory graph store featuring:
- Typed nodes and edges with attributes
- Failure history tracking
- Precondition tracking
- Verification linkage
- JSON serialization
"""

from __future__ import annotations

import json
import hashlib
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from cage_cloud.schema import GraphEdge, GraphNode, VerificationResult


# Node type constants
NODE_TYPE_TARGET = "target"
NODE_TYPE_SERVICE = "service"
NODE_TYPE_ENDPOINT = "endpoint"
NODE_TYPE_CREDENTIAL_KEY = "credential_key"
NODE_TYPE_CVE_CANDIDATE = "cve_candidate"
NODE_TYPE_VULNERABILITY = "vulnerability"
NODE_TYPE_EVIDENCE = "evidence"
NODE_TYPE_ATTACK_SURFACE = "attack_surface"
NODE_TYPE_RESOURCE = "resource"
NODE_TYPE_VERSION = "version"
NODE_TYPE_SESSION = "session"

NODE_TYPES = {
    NODE_TYPE_TARGET,
    NODE_TYPE_SERVICE,
    NODE_TYPE_ENDPOINT,
    NODE_TYPE_CREDENTIAL_KEY,
    NODE_TYPE_CVE_CANDIDATE,
    NODE_TYPE_VULNERABILITY,
    NODE_TYPE_EVIDENCE,
    NODE_TYPE_ATTACK_SURFACE,
    NODE_TYPE_RESOURCE,
    NODE_TYPE_VERSION,
    NODE_TYPE_SESSION,
}

# Edge type constants
EDGE_TYPE_HAS_SERVICE = "has_service"
EDGE_TYPE_HAS_ENDPOINT = "has_endpoint"
EDGE_TYPE_HAS_CREDENTIAL_KEY = "has_credential_key"
EDGE_TYPE_HAS_VULNERABILITY = "has_vulnerability"
EDGE_TYPE_SUGGESTS = "suggests"
EDGE_TYPE_OBSERVED = "observed"
EDGE_TYPE_REQUIRES = "requires"
EDGE_TYPE_VERIFIED_BY = "verified_by"
EDGE_TYPE_FAILED_WITH = "failed_with"
EDGE_TYPE_CAN_REACH = "can_reach"
EDGE_TYPE_HAS_VERSION = "has_version"
EDGE_TYPE_LEADS_TO = "leads_to"
EDGE_TYPE_EXPLOITED_VIA = "exploited_via"

EDGE_TYPES = {
    EDGE_TYPE_HAS_SERVICE,
    EDGE_TYPE_HAS_ENDPOINT,
    EDGE_TYPE_HAS_CREDENTIAL_KEY,
    EDGE_TYPE_HAS_VULNERABILITY,
    EDGE_TYPE_SUGGESTS,
    EDGE_TYPE_OBSERVED,
    EDGE_TYPE_REQUIRES,
    EDGE_TYPE_VERIFIED_BY,
    EDGE_TYPE_FAILED_WITH,
    EDGE_TYPE_CAN_REACH,
    EDGE_TYPE_HAS_VERSION,
    EDGE_TYPE_LEADS_TO,
    EDGE_TYPE_EXPLOITED_VIA,
}


def _nid(kind: str, value: str) -> str:
    """Create a node ID from type and value."""
    return f"{kind}:{value}"


def _safe_text(value: Any) -> str:
    """Safely convert value to non-empty string."""
    if value is None:
        return ""
    text = str(value).strip()
    return text if text else ""


def _canonical_key(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("id", "vuln_id", "cve_id", "name", "command", "resource_id"):
            if value.get(key):
                return f"{key}:{str(value[key]).strip().lower()}"
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return str(value).strip().lower()


def _credential_signature(key: str, value: Any) -> str:
    text = str(value).strip()
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
    return f"{key.lower()}:{digest}"


def progress_signature(state: Dict[str, Any]) -> Tuple[Tuple[str, ...], ...]:
    """Build the canonical committed-progress signature from paper Eq. 24."""
    verifications = [
        item
        for item in state.get("objective_verifications", []) or []
        if isinstance(item, dict) and item.get("status") == "verified"
    ]
    verified_findings = {
        str(evidence_id)
        for item in verifications
        for evidence_id in item.get("supporting_evidence_ids", []) or []
    }
    usable_credentials = {
        _credential_signature(str(key), value)
        for key, value in (state.get("credentials_found", {}) or {}).items()
        if value not in (None, "")
    }
    dead_credentials = {
        _credential_signature(str(key), value)
        for item in state.get("dead_credentials", []) or []
        if isinstance(item, dict)
        for key, value in item.items()
        if value not in (None, "")
    }
    usable_credentials.difference_update(dead_credentials)

    validated_cves = {_canonical_key(item) for item in state.get("cve_success", []) or []}
    if any(item.get("objective_type") == "cve_applicability_validated" for item in verifications):
        validated_cves.update(
            _canonical_key(item) for item in state.get("cve_candidates", []) or []
        )

    effects: set[str] = set()
    if any(item.get("objective_type") == "exploit_effect_confirmed" for item in verifications):
        effects.update(
            _canonical_key(item) for item in state.get("exploits_successful", []) or []
        )

    resources = {
        f"{kind}:{_canonical_key(item)}"
        for kind, values in (state.get("cloud_artifacts", {}) or {}).items()
        if isinstance(values, list)
        for item in values
    }
    return tuple(
        tuple(sorted(group))
        for group in (
            verified_findings,
            usable_credentials,
            validated_cves,
            effects,
            resources,
        )
    )


@dataclass
class FailureRecord:
    """Record of an action failure with count and reason."""

    action_type: str
    count: int = 1
    last_timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    reason: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class GraphState:
    """Persistent in-memory graph store with node/edge management."""

    def __init__(self) -> None:
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: Dict[str, GraphEdge] = {}
        self._edge_index: Dict[str, Set[str]] = defaultdict(set)
        self._reverse_edge_index: Dict[str, Set[str]] = defaultdict(set)
        self.failure_history: Dict[str, FailureRecord] = {}
        self.verification_links: Dict[str, List[str]] = defaultdict(list)

    def add_node(
        self,
        node_id: str,
        node_type: str,
        label: str,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Add or update a node. Returns node ID."""
        if not node_id or not label:
            return ""

        if node_type not in NODE_TYPES:
            raise ValueError(f"Invalid node type: {node_type}")

        attrs = attributes or {}
        node = GraphNode(node_id=node_id, node_type=node_type, label=label, attributes=attrs)
        self.nodes[node_id] = node
        return node_id

    def add_edge(
        self,
        src: str,
        rel: str,
        dst: str,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Add or update an edge. Returns edge ID (src:rel:dst)."""
        if not src or not dst or not rel:
            return ""

        if rel not in EDGE_TYPES:
            raise ValueError(f"Invalid edge type: {rel}")

        if src not in self.nodes or dst not in self.nodes:
            return ""

        edge_id = f"{src}::{rel}::{dst}"
        attrs = attributes or {}
        edge = GraphEdge(src=src, rel=rel, dst=dst, attributes=attrs)
        self.edges[edge_id] = edge
        self._edge_index[src].add(edge_id)
        self._reverse_edge_index[dst].add(edge_id)
        return edge_id

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Get a node by ID."""
        return self.nodes.get(node_id)

    def get_nodes_by_type(self, node_type: str) -> List[GraphNode]:
        """Get all nodes of a given type."""
        return [n for n in self.nodes.values() if n.node_type == node_type]

    def get_edges_from(self, node_id: str, rel: Optional[str] = None) -> List[GraphEdge]:
        """Get outgoing edges from a node, optionally filtered by relation type."""
        edges = []
        for edge_id in self._edge_index.get(node_id, set()):
            edge = self.edges[edge_id]
            if rel is None or edge.rel == rel:
                edges.append(edge)
        return edges

    def get_edges_to(self, node_id: str, rel: Optional[str] = None) -> List[GraphEdge]:
        """Get incoming edges to a node, optionally filtered by relation type."""
        edges = []
        for edge_id in self._reverse_edge_index.get(node_id, set()):
            edge = self.edges[edge_id]
            if rel is None or edge.rel == rel:
                edges.append(edge)
        return edges

    def get_neighbors(self, node_id: str, rel: Optional[str] = None) -> List[GraphNode]:
        """Get neighboring nodes connected via outgoing edges."""
        neighbors = []
        for edge in self.get_edges_from(node_id, rel):
            neighbor = self.get_node(edge.dst)
            if neighbor:
                neighbors.append(neighbor)
        return neighbors

    def add_failure(
        self,
        action_type: str,
        reason: str = "",
        attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record an action failure."""
        if action_type not in self.failure_history:
            self.failure_history[action_type] = FailureRecord(
                action_type=action_type,
                reason=reason,
                attributes=attributes or {},
            )
        else:
            record = self.failure_history[action_type]
            record.count += 1
            record.last_timestamp = datetime.utcnow().isoformat()
            if reason:
                record.reason = reason
            if attributes:
                record.attributes.update(attributes)

    def get_failure_count(self, action_type: str) -> int:
        """Get failure count for action type."""
        record = self.failure_history.get(action_type)
        return record.count if record else 0

    def check_preconditions(self, action_id: str) -> Dict[str, bool]:
        """Check which preconditions are met for an action."""
        action_node = self.get_node(action_id)
        if not action_node:
            return {}

        preconditions = {}
        requires_edges = self.get_edges_from(action_id, EDGE_TYPE_REQUIRES)

        for edge in requires_edges:
            precond_node_id = edge.dst
            precond_node = self.get_node(precond_node_id)
            if precond_node:
                is_met = self._is_precondition_met(precond_node_id)
                preconditions[precond_node_id] = is_met

        return preconditions

    def _is_precondition_met(self, precond_node_id: str) -> bool:
        """Check if a precondition is met (has incoming verified_by edge)."""
        verification_edges = self.get_edges_to(precond_node_id, EDGE_TYPE_VERIFIED_BY)
        return len(verification_edges) > 0

    def add_verification_link(self, task_id: str, evidence_id: str) -> None:
        """Link a task/objective to its verifying evidence."""
        if task_id not in self.verification_links:
            self.verification_links[task_id] = []
        if evidence_id not in self.verification_links[task_id]:
            self.verification_links[task_id].append(evidence_id)

    def get_verifications_for(self, task_id: str) -> List[str]:
        """Get evidence IDs that verify a task/objective."""
        return self.verification_links.get(task_id, [])

    def update_from_state(self, state: Dict[str, Any], target_description: str = "") -> None:
        """Ingest state dict from pipeline and populate graph."""
        target_label = _safe_text(target_description) or "current_target"
        target_id = self.add_node(
            _nid(NODE_TYPE_TARGET, target_label),
            NODE_TYPE_TARGET,
            target_label,
        )

        # Services
        for svc in state.get("services_detected", []) or []:
            svc_label = _safe_text(svc)
            if svc_label:
                svc_id = self.add_node(_nid(NODE_TYPE_SERVICE, svc_label), NODE_TYPE_SERVICE, svc_label)
                self.add_edge(target_id, EDGE_TYPE_HAS_SERVICE, svc_id)

        # Web endpoints
        for ep in state.get("web_endpoints", []) or []:
            ep_label = _safe_text(ep)
            if ep_label:
                ep_id = self.add_node(
                    _nid(NODE_TYPE_ENDPOINT, ep_label),
                    NODE_TYPE_ENDPOINT,
                    ep_label,
                    {"status": "observed"},
                )
                self.add_edge(target_id, EDGE_TYPE_HAS_ENDPOINT, ep_id)

        # Credential keys (names only, no values)
        for key in (state.get("credentials_found", {}) or {}).keys():
            key_label = _safe_text(key)
            if key_label:
                cred_id = self.add_node(
                    _nid(NODE_TYPE_CREDENTIAL_KEY, key_label),
                    NODE_TYPE_CREDENTIAL_KEY,
                    key_label,
                )
                self.add_edge(target_id, EDGE_TYPE_HAS_CREDENTIAL_KEY, cred_id)

        # CVE candidates
        for cve in state.get("cve_candidates", []) or []:
            cve_label = _safe_text(cve)
            if cve_label:
                cve_id = self.add_node(
                    _nid(NODE_TYPE_CVE_CANDIDATE, cve_label),
                    NODE_TYPE_CVE_CANDIDATE,
                    cve_label,
                    {"status": "candidate"},
                )
                self.add_edge(target_id, EDGE_TYPE_SUGGESTS, cve_id)

        # Vulnerabilities
        for vuln in state.get("vulnerabilities_found", []) or []:
            if isinstance(vuln, dict):
                vid = _safe_text(vuln.get("id")) or _safe_text(vuln.get("description"))
                sev = _safe_text(vuln.get("severity")) or "?"
                vuln_label = f"{vid} [{sev}]"
            else:
                vuln_label = _safe_text(vuln)

            if vuln_label:
                vuln_id = self.add_node(
                    _nid(NODE_TYPE_VULNERABILITY, vuln_label),
                    NODE_TYPE_VULNERABILITY,
                    vuln_label,
                    {"status": "verified"},
                )
                self.add_edge(target_id, EDGE_TYPE_HAS_VULNERABILITY, vuln_id)

        # Evidence items (findings)
        for f in (state.get("findings", []) or [])[-25:]:
            ev_label = _safe_text(f)[:140]
            if ev_label:
                ev_id = self.add_node(_nid(NODE_TYPE_EVIDENCE, ev_label), NODE_TYPE_EVIDENCE, ev_label)
                self.add_edge(target_id, EDGE_TYPE_OBSERVED, ev_id)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize graph to dict."""
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges.values()],
            "failure_history": {k: v.to_dict() for k, v in self.failure_history.items()},
            "verification_links": dict(self.verification_links),
        }

    def save(self, filepath: str | Path) -> None:
        """Save graph to JSON file."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    def load(self, filepath: str | Path) -> None:
        """Load graph from JSON file."""
        path = Path(filepath)
        if not path.exists():
            return

        with open(path, "r") as f:
            data = json.load(f)

        # Load nodes
        for node_data in data.get("nodes", []):
            node = GraphNode(
                node_id=node_data["node_id"],
                node_type=node_data["node_type"],
                label=node_data["label"],
                attributes=node_data.get("attributes", {}),
            )
            self.nodes[node.node_id] = node

        # Load edges
        for edge_data in data.get("edges", []):
            edge = GraphEdge(
                src=edge_data["src"],
                rel=edge_data["rel"],
                dst=edge_data["dst"],
                attributes=edge_data.get("attributes", {}),
            )
            edge_id = f"{edge.src}::{edge.rel}::{edge.dst}"
            self.edges[edge_id] = edge
            self._edge_index[edge.src].add(edge_id)
            self._reverse_edge_index[edge.dst].add(edge_id)

        # Load failure history
        for action_type, record_data in data.get("failure_history", {}).items():
            self.failure_history[action_type] = FailureRecord(
                action_type=action_type,
                count=record_data.get("count", 1),
                last_timestamp=record_data.get("last_timestamp", ""),
                reason=record_data.get("reason", ""),
                attributes=record_data.get("attributes", {}),
            )

        # Load verification links
        self.verification_links = defaultdict(list, data.get("verification_links", {}))

    def generate_summary_text(self, max_nodes: int = 120, max_edges: int = 220) -> str:
        """Generate summary text for Planner prompt (compatible with graph_lite)."""
        node_list = list(self.nodes.values())[:max_nodes]
        node_ids = {n.node_id for n in node_list}
        edge_list = [e for e in self.edges.values() if e.src in node_ids and e.dst in node_ids][
            :max_edges
        ]

        node_type_counts = Counter(n.node_type for n in node_list)
        rel_counts = Counter(e.rel for e in edge_list)

        summary_parts = [
            f"nodes={len(node_list)}",
            f"edges={len(edge_list)}",
        ]
        if node_type_counts:
            summary_parts.append(
                "types=" + ", ".join(f"{k}:{v}" for k, v in sorted(node_type_counts.items()))
            )
        if rel_counts:
            summary_parts.append(
                "rels=" + ", ".join(f"{k}:{v}" for k, v in sorted(rel_counts.items()))
            )

        top_services = ", ".join(n.label for n in node_list if n.node_type == NODE_TYPE_SERVICE) or "None"
        top_endpoints = ", ".join(n.label for n in node_list if n.node_type == NODE_TYPE_ENDPOINT) or "None"
        top_vulns = (
            ", ".join(n.label for n in node_list if n.node_type == NODE_TYPE_VULNERABILITY) or "None"
        )

        summary_text = (
            f"[GraphState] {', '.join(summary_parts)} | "
            f"services={top_services} | endpoints={top_endpoints} | vulns={top_vulns}"
        )
        return summary_text


def build_graph_lite_state(
    state: Dict[str, Any],
    target_description: str = "",
    max_nodes: int = 120,
    max_edges: int = 220,
) -> Dict[str, Any]:
    """
    Backward compatibility wrapper. Creates temporary GraphState,
    populates from state dict, and returns dict format compatible
    with original graph_lite.py usage.
    """
    graph = GraphState()
    graph.update_from_state(state, target_description)

    node_list = list(graph.nodes.values())[:max_nodes]
    node_ids = {n.node_id for n in node_list}
    edge_list = [e for e in graph.edges.values() if e.src in node_ids and e.dst in node_ids][
        :max_edges
    ]

    node_type_counts = Counter(n.node_type for n in node_list)
    rel_counts = Counter(e.rel for e in edge_list)

    return {
        "nodes": [{"id": n.node_id, "type": n.node_type, "label": n.label} for n in node_list],
        "edges": [{"src": e.src, "rel": e.rel, "dst": e.dst} for e in edge_list],
        "summary": {
            "node_count": len(node_list),
            "edge_count": len(edge_list),
            "node_type_counts": dict(node_type_counts),
            "relation_counts": dict(rel_counts),
        },
        "summary_text": graph.generate_summary_text(max_nodes, max_edges),
    }
