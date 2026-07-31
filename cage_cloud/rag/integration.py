#!/usr/bin/env python3
"""
RAG Integration Module for Cloud Auto Pentest Pipeline

This module provides a simple interface to integrate RAG (Retrieval-Augmented Generation)
into the pentest pipeline. It searches for relevant CVEs based on detected services
and provides context for the Planner.

Usage:
    from cage_cloud.rag.integration import RAGIntegration

    rag = RAGIntegration()

    # Search for CVEs based on detected services
    cves = rag.search_cves_for_services(["tomcat", "java", "apache"])

    # Get context for Planner
    context = rag.get_planner_context(services=["tomcat"], findings=["Port 8080 open"])
"""

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

# Dataset path — CVE-CLOUD (435 files: aws/azure/gcp/other)
DATASET_PATH = Path(
    os.environ.get(
        "CVE_DATASET_PATH",
        "/root/NCKH/CVE-CLOUD/COT_Planner_CVE-CLOUD",
    )
)
# rag_search.py lives in same dir as this file (CloudPentest/)
RAG_SEARCH_DIR = Path(__file__).parent
if str(RAG_SEARCH_DIR) not in sys.path:
    sys.path.insert(0, str(RAG_SEARCH_DIR))


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class CVEMatch:
    """Represents a matched CVE."""

    cve_id: str
    title: str
    severity: str
    cvss_score: float
    services: List[str]
    attack_phases: List[str]
    exploit_commands: List[str]
    relevance_score: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "title": self.title,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "services": self.services,
            "attack_phases": self.attack_phases,
            "exploit_commands": self.exploit_commands,
            "relevance_score": self.relevance_score,
        }


# =============================================================================
# RAG Integration Class
# =============================================================================


class RAGIntegration:
    """
    Integrates RAG search into the pentest pipeline.

    This class provides methods to:
    1. Search for CVEs based on detected services
    2. Match services to known vulnerabilities
    3. Get context for Planner decisions
    4. Get exploit commands for specific CVEs
    """

    # Service to CVE keyword mappings
    SERVICE_KEYWORDS = {
        "tomcat": ["tomcat", "apache tomcat", "java", "servlet"],
        "java": ["java", "jvm", "log4j", "spring", "log4shell"],
        "apache": ["apache", "httpd", "mod_"],
        "nginx": ["nginx"],
        "mysql": ["mysql", "mariadb", "sql"],
        "postgres": ["postgresql", "postgres"],
        "ssh": ["ssh", "openssh", "sshd"],
        "docker": ["docker", "container", "kubernetes", "k8s"],
        "aws": ["aws", "s3", "ec2", "iam", "lambda", "rds"],
        "azure": ["azure", "blob", "ad", "entra"],
        "gcp": ["gcp", "gcloud", "bigquery", "gke"],
        "elasticsearch": ["elasticsearch", "elastic", "kibana"],
        "redis": ["redis"],
        "mongodb": ["mongodb", "mongo"],
        "jenkins": ["jenkins", "ci/cd"],
        "spring": ["spring", "spring4shell", "springboot"],
        "log4j": ["log4j", "log4shell", "jndi"],
    }

    def __init__(self, index_path: Optional[str] = None):
        default_index_path = Path(
            os.environ.get("RAG_INDEX_DIR", str(Path(__file__).parent / "rag_index"))
        )
        self.index_path = Path(index_path) if index_path else default_index_path
        self.output_path = DATASET_PATH / "output"
        self.rag_search = None
        self.cve_cache: Dict[str, Dict] = {}
        self._loaded = False

    def _ensure_loaded(self) -> bool:
        """Ensure RAG index is loaded."""
        if self._loaded:
            return True

        try:
            import importlib.util, sys
            rag_search_path = Path(__file__).parent / "search.py"
            spec = importlib.util.spec_from_file_location("cage_cloud_rag_search", rag_search_path)
            rag_mod = importlib.util.module_from_spec(spec)
            sys.modules["rag_search"] = rag_mod
            spec.loader.exec_module(rag_mod)

            self.rag_search = rag_mod.CVERAGSearch()

            if self.index_path.exists():
                self.rag_search.load_index(str(self.index_path))
                self._populate_cache_from_documents()
                self._loaded = True
                return True
            else:
                print(f"  RAG index not found at {self.index_path}")
                return False

        except Exception as e:
            print(f"  Could not load RAG: {e}")
            return False

    def _populate_cache_from_documents(self) -> None:
        """Build cve_cache from rag_search.documents when CVE JSON files aren't on disk."""
        if self.cve_cache or not self.rag_search or not self.rag_search.documents:
            return

        for doc in self.rag_search.documents:
            tasks = []
            for i, phase in enumerate(doc.attack_phases):
                cmd = doc.exploit_commands[i] if i < len(doc.exploit_commands) else ""
                tasks.append({"phase": phase, "action_method": cmd})
            for cmd in doc.exploit_commands[len(doc.attack_phases):]:
                tasks.append({"phase": "", "action_method": cmd})

            self.cve_cache[doc.cve_id] = {
                "metadata": {
                    "cve_id": doc.cve_id,
                    "title": doc.title,
                    "description": doc.description,
                    "severity": doc.severity,
                    "cvss_score": doc.cvss_score,
                    "tags": doc.tags,
                },
                "classification": {"cloud_type": doc.cloud_type},
                "vulnerability": {"type": doc.vuln_type},
                "attack_path": {"tasks": tasks},
                "preconditions": doc.preconditions,
            }

    def _load_cve_files(self) -> None:
        """Load CVE data into cache from JSON files or pickle-loaded documents."""
        if self.cve_cache:
            return

        if self.output_path.exists():
            for json_file in self.output_path.rglob("CVE-*.json"):
                try:
                    with open(json_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        cve_id = data.get("metadata", {}).get("cve_id", json_file.stem)
                        self.cve_cache[cve_id] = data
                except Exception:
                    continue

        if not self.cve_cache:
            self._ensure_loaded()
            self._populate_cache_from_documents()

    def search_cves_for_services(
        self,
        services: List[str],
        provider: str = "aws",
        top_k: int = 5,
        severity_filter: Optional[List[str]] = None,
    ) -> List[CVEMatch]:
        """
        Search for CVEs that match detected services.

        Args:
            services: List of detected services (e.g., ["tomcat", "java"])
            provider: Cloud provider filter
            top_k: Maximum number of results
            severity_filter: Filter by severity (e.g., ["CRITICAL", "HIGH"])

        Returns:
            List of matched CVEs sorted by relevance
        """
        # Build search query from services
        query_parts = []
        for service in services:
            service_lower = service.lower()
            # Add service and related keywords
            query_parts.append(service_lower)
            if service_lower in self.SERVICE_KEYWORDS:
                query_parts.extend(self.SERVICE_KEYWORDS[service_lower][:2])

        query = " ".join(set(query_parts))

        # Try RAG search first
        if self._ensure_loaded() and self.rag_search:
            try:
                results = self.rag_search.search(
                    query=query,
                    top_k=top_k,
                    provider_filter=provider,
                    severity_filter=severity_filter,
                )

                matches = []
                for result in results:
                    doc = result.document
                    exploit_cmds = self._get_exploit_commands(doc.cve_id, provider)
                    matches.append(
                        CVEMatch(
                            cve_id=doc.cve_id,
                            title=doc.title,
                            severity=doc.severity,
                            cvss_score=doc.cvss_score,
                            services=doc.tags[:5],           # CVEDocument.tags
                            attack_phases=doc.attack_phases[:4],
                            exploit_commands=doc.exploit_commands[:5],
                            relevance_score=result.score,
                        )
                    )

                return matches

            except Exception as e:
                print(f"⚠️ RAG search failed: {e}, using fallback")

        # Fallback: keyword matching on cached CVE files
        return self._keyword_search(services, provider, top_k, severity_filter)

    def _keyword_search(
        self,
        services: List[str],
        provider: str,
        top_k: int,
        severity_filter: Optional[List[str]],
    ) -> List[CVEMatch]:
        """Fallback keyword-based search."""
        self._load_cve_files()

        if not self.cve_cache:
            return []

        matches = []
        services_lower = [s.lower() for s in services]

        for cve_id, data in self.cve_cache.items():
            meta = data.get("metadata", {})

            # Check severity filter
            severity = meta.get("severity", "MEDIUM")
            if severity_filter and severity not in severity_filter:
                continue

            # Check provider — schema: classification.cloud_type = "aws"|"azure"|"gcp"|"other"
            cloud_type = data.get("classification", {}).get("cloud_type", "other")
            if provider.lower() not in (cloud_type.lower(), "other"):
                continue

            # Calculate relevance based on keyword matching
            title = meta.get("title", "").lower()
            tags = [t.lower() for t in meta.get("tags", [])]
            # Use tags + title for service matching (no cloud_providers.services key)
            cve_services_lower = tags + title.split()

            score = 0.0
            for service in services_lower:
                if service in title:
                    score += 0.5
                if service in tags:
                    score += 0.3
                if service in cve_services_lower:
                    score += 0.4
                # Check related keywords
                for keyword in self.SERVICE_KEYWORDS.get(service, []):
                    if keyword in title or keyword in tags:
                        score += 0.2

            if score > 0:
                exploit_cmds = self._get_exploit_commands(cve_id, provider)
                attack_phases = self._get_attack_phases(data)

                matches.append(
                    CVEMatch(
                        cve_id=cve_id,
                        title=meta.get("title", "Unknown"),
                        severity=severity,
                        cvss_score=meta.get("cvss_score", 0.0),
                        services=tags[:5],
                        attack_phases=attack_phases,
                        exploit_commands=exploit_cmds,
                        relevance_score=score,
                    )
                )

        # Sort by score and severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        matches.sort(
            key=lambda x: (-x.relevance_score, severity_order.get(x.severity, 2))
        )

        return matches[:top_k]

    def _get_exploit_commands(self, cve_id: str, provider: str) -> List[str]:
        """Get exploit commands from attack_path.tasks[].action_method."""
        self._load_cve_files()

        if cve_id not in self.cve_cache:
            return []

        data = self.cve_cache[cve_id]
        commands = []

        # Schema: attack_path is a dict with "tasks" list
        attack_path = data.get("attack_path", {})
        if isinstance(attack_path, dict):
            tasks = attack_path.get("tasks", [])
        else:
            tasks = attack_path  # fallback: old list schema

        for task in tasks:
            method = task.get("action_method", "")
            if method:
                commands.append(method)
            # Also grab example commands from semantic_context if present
            sc = task.get("semantic_context", {})
            if isinstance(sc, dict):
                for artifact in sc.get("artifact", []):
                    if isinstance(artifact, str) and any(
                        c in artifact for c in ["aws ", "az ", "curl ", "gcloud "]
                    ):
                        commands.append(artifact)

        # Also try agent_guidance.generator_hints (present in some old files)
        guidance = data.get("agent_guidance", {})
        if guidance:
            hints = guidance.get("generator_hints", {})
            if isinstance(hints, dict):
                cmds = hints.get("commands", [])
                commands.extend(cmds[:3])

        return list(dict.fromkeys(commands))[:5]  # deduplicate, keep order

    def _get_attack_phases(self, data: Dict) -> List[str]:
        """Extract attack phases from CVE data (schema: attack_path.tasks[].phase)."""
        phases = []
        attack_path = data.get("attack_path", {})
        if isinstance(attack_path, dict):
            tasks = attack_path.get("tasks", [])
        else:
            tasks = attack_path
        for task in tasks:
            phase = task.get("phase", "")
            if phase and phase not in phases:
                phases.append(phase)
        return phases[:4]

    def get_planner_context(
        self,
        services: List[str],
        findings: List[str],
        provider: str = "aws",
        top_k: int = 3,
    ) -> str:
        """
        Get formatted context for Planner agent.

        Args:
            services: Detected services
            findings: Current findings
            provider: Cloud provider
            top_k: Number of CVEs to include

        Returns:
            Formatted context string
        """
        # Build query from services and findings
        query_parts = services.copy()
        for finding in findings[:5]:
            # Extract key terms from findings
            words = finding.lower().split()
            for word in words:
                if len(word) > 3 and word.isalpha():
                    query_parts.append(word)

        # Search for relevant CVEs
        cves = self.search_cves_for_services(
            services=list(set(query_parts)),
            provider=provider,
            top_k=top_k,
            severity_filter=["CRITICAL", "HIGH"],
        )

        if not cves:
            return "No relevant CVEs found for detected services."

        # Build context
        context_parts = [
            "=== RELEVANT CVE CONTEXT FROM RAG ===",
            f"Based on detected services: {', '.join(services)}",
            f"Found {len(cves)} relevant CVEs:",
            "",
        ]

        for i, cve in enumerate(cves, 1):
            context_parts.extend(
                [
                    f"--- CVE #{i} ---",
                    f"ID: {cve.cve_id}",
                    f"Title: {cve.title}",
                    f"Severity: {cve.severity} (CVSS: {cve.cvss_score})",
                    f"Attack Phases: {' -> '.join(cve.attack_phases)}",
                ]
            )
            if cve.exploit_commands:
                context_parts.append(
                    f"Example Commands: {'; '.join(cve.exploit_commands[:3])}"
                )
            context_parts.append("")

        context_parts.append("=== END CVE CONTEXT ===")

        return "\n".join(context_parts)

    def get_cve_exploit_info(
        self, cve_id: str, provider: str = "aws"
    ) -> Optional[Dict]:
        """
        Get detailed exploit information for a specific CVE.

        Args:
            cve_id: CVE identifier
            provider: Cloud provider

        Returns:
            Dict with exploit details or None
        """
        self._load_cve_files()

        if cve_id not in self.cve_cache:
            return None

        data = self.cve_cache[cve_id]
        meta = data.get("metadata", {})

        return {
            "cve_id": cve_id,
            "title": meta.get("title", ""),
            "severity": meta.get("severity", ""),
            "cvss_score": meta.get("cvss_score", 0),
            "attack_path": data.get("attack_path", []),
            "exploit_commands": self._get_exploit_commands(cve_id, provider),
            "preconditions": data.get("preconditions", {}),
            "success_indicators": self._get_success_indicators(data),
            "remediation": data.get("remediation", {}),
        }

    def _get_success_indicators(self, data: Dict) -> List[str]:
        """Extract success indicators from CVE data (semantic_context.success_criteria)."""
        indicators = []
        attack_path = data.get("attack_path", {})
        if isinstance(attack_path, dict):
            tasks = attack_path.get("tasks", [])
        else:
            tasks = attack_path
        for task in tasks:
            sc = task.get("semantic_context", {})
            if isinstance(sc, dict):
                crit = sc.get("success_criteria", "")
                if crit and crit not in indicators:
                    indicators.append(crit)
        return indicators[:5]

    def match_services_to_cves(self, services: List[str]) -> Dict[str, List[str]]:
        """
        Map detected services to potential CVE categories.

        Args:
            services: List of detected services

        Returns:
            Dict mapping service to list of CVE IDs
        """
        self._load_cve_files()

        service_cves: Dict[str, List[str]] = {}

        for service in services:
            service_lower = service.lower()
            matching_cves = []

            for cve_id, data in self.cve_cache.items():
                meta = data.get("metadata", {})
                title = meta.get("title", "").lower()
                tags = [t.lower() for t in meta.get("tags", [])]

                # Check direct match
                if service_lower in title or service_lower in tags:
                    matching_cves.append(cve_id)
                    continue

                # Check keyword match
                keywords = self.SERVICE_KEYWORDS.get(service_lower, [])
                for keyword in keywords:
                    if keyword in title or keyword in tags:
                        matching_cves.append(cve_id)
                        break

            if matching_cves:
                service_cves[service] = matching_cves[:5]

        return service_cves


# =============================================================================
# Utility Functions
# =============================================================================


def get_rag_context_for_state(state: Dict, provider: str = "aws") -> str:
    """
    Convenience function to get RAG context from pipeline state.

    Args:
        state: Pipeline state dictionary
        provider: Cloud provider

    Returns:
        Formatted context string
    """
    rag = RAGIntegration()

    services = state.get("services_detected", [])
    findings = state.get("findings", [])

    if not services and not findings:
        return ""

    return rag.get_planner_context(
        services=services,
        findings=findings,
        provider=provider,
    )


def search_cves_for_target(
    target_description: str, provider: str = "aws"
) -> List[Dict]:
    """
    Search CVEs based on target description.

    Args:
        target_description: Free-form target description
        provider: Cloud provider

    Returns:
        List of CVE dicts
    """
    rag = RAGIntegration()

    # Extract potential services from description
    services = []
    description_lower = target_description.lower()

    for service, keywords in RAGIntegration.SERVICE_KEYWORDS.items():
        if service in description_lower:
            services.append(service)
        for keyword in keywords:
            if keyword in description_lower:
                services.append(service)
                break

    if not services:
        # Default to common services
        services = ["aws", "s3", "iam"]

    cves = rag.search_cves_for_services(
        services=list(set(services)),
        provider=provider,
        top_k=5,
    )

    return [cve.to_dict() for cve in cves]


# =============================================================================
# Main (for testing)
# =============================================================================


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="RAG Integration Test")
    parser.add_argument(
        "--services",
        nargs="+",
        default=["tomcat", "java"],
        help="Services to search for",
    )
    parser.add_argument("--provider", default="aws", help="Cloud provider")
    parser.add_argument(
        "--target", type=str, default=None, help="Target description for search"
    )

    args = parser.parse_args()

    rag = RAGIntegration()

    if args.target:
        print(f"\n🔍 Searching CVEs for target: {args.target}")
        cves = search_cves_for_target(args.target, args.provider)
        for cve in cves:
            print(f"\n  {cve['cve_id']}: {cve['title']}")
            print(f"    Severity: {cve['severity']} | Score: {cve['cvss_score']}")
    else:
        print(f"\n🔍 Searching CVEs for services: {args.services}")
        cves = rag.search_cves_for_services(args.services, args.provider)

        for cve in cves:
            print(f"\n  {cve.cve_id}: {cve.title}")
            print(f"    Severity: {cve.severity} | Score: {cve.cvss_score}")
            print(f"    Phases: {' -> '.join(cve.attack_phases)}")
            if cve.exploit_commands:
                print(f"    Commands: {cve.exploit_commands[:2]}")

        print("\n📄 Planner Context:")
        print("-" * 60)
        context = rag.get_planner_context(args.services, [], args.provider)
        print(context)
