#!/usr/bin/env python3
"""
Scope and policy guard for the rule-first CloudGraph rebuild.

This module is intentionally deterministic. It is designed to run before any
planner-selected action is executed.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from fnmatch import fnmatch
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from cage_cloud.schema import BudgetSnapshot


@dataclass
class ScopePolicy:
    allowed_domains: List[str] = field(default_factory=list)
    allowed_hosts: List[str] = field(default_factory=list)
    allowed_url_prefixes: List[str] = field(default_factory=list)
    blocked_domains: List[str] = field(default_factory=list)
    blocked_command_patterns: List[str] = field(default_factory=list)
    max_llm_requests: Optional[int] = None
    max_llm_tokens: Optional[int] = None
    max_http_requests: Optional[int] = None
    max_tool_calls: Optional[int] = None
    max_elapsed_seconds: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GuardDecision:
    allowed: bool
    reason: str
    matched_rule: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ScopeGuard:
    def __init__(self, policy: ScopePolicy):
        self.policy = policy

    def is_url_in_scope(self, url: str) -> GuardDecision:
        if not url:
            return GuardDecision(True, "No URL to validate", "NO_URL")

        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        netloc = parsed.netloc.lower()

        if self._matches_any(host, self.policy.blocked_domains):
            return GuardDecision(False, f"Blocked domain: {host}", "BLOCKED_DOMAIN")

        if self.policy.allowed_domains and not self._matches_any(host, self.policy.allowed_domains):
            return GuardDecision(False, f"Host outside allowed domains: {host}", "OUTSIDE_ALLOWED_DOMAIN")

        if self.policy.allowed_hosts and host not in {h.lower() for h in self.policy.allowed_hosts}:
            return GuardDecision(False, f"Host outside allowed hosts: {host}", "OUTSIDE_ALLOWED_HOST")

        if self.policy.allowed_url_prefixes:
            full = f"{parsed.scheme}://{netloc}{parsed.path}"
            if not any(full.startswith(prefix) for prefix in self.policy.allowed_url_prefixes):
                return GuardDecision(False, f"URL outside allowed prefixes: {full}", "OUTSIDE_ALLOWED_PREFIX")

        return GuardDecision(True, f"URL allowed: {host}", "URL_ALLOWED")

    def is_command_allowed(self, command: str) -> GuardDecision:
        cmd = (command or "").strip()
        if not cmd:
            return GuardDecision(True, "Empty command", "EMPTY_COMMAND")

        lower_cmd = cmd.lower()
        for pattern in self.policy.blocked_command_patterns:
            if fnmatch(lower_cmd, pattern.lower()) or pattern.lower() in lower_cmd:
                return GuardDecision(False, f"Blocked command pattern matched: {pattern}", "BLOCKED_COMMAND_PATTERN")

        return GuardDecision(True, "Command allowed by policy", "COMMAND_ALLOWED")

    def check_budget(self, budget: BudgetSnapshot) -> GuardDecision:
        checks = [
            ("max_llm_requests", budget.llm_requests_used, "LLM request budget exceeded"),
            ("max_llm_tokens", budget.llm_tokens_used, "LLM token budget exceeded"),
            ("max_http_requests", budget.http_requests_used, "HTTP request budget exceeded"),
            ("max_tool_calls", budget.tool_calls_used, "Tool call budget exceeded"),
            ("max_elapsed_seconds", budget.elapsed_seconds, "Elapsed time budget exceeded"),
        ]

        for policy_field, used, reason in checks:
            limit = getattr(self.policy, policy_field)
            if limit is not None and used > limit:
                return GuardDecision(False, f"{reason}: {used} > {limit}", policy_field.upper())

        return GuardDecision(True, "Budget within policy", "BUDGET_OK")

    def check_action(
        self,
        command: str = "",
        target_urls: Optional[Iterable[str]] = None,
        budget: Optional[BudgetSnapshot] = None,
    ) -> GuardDecision:
        if budget is not None:
            decision = self.check_budget(budget)
            if not decision.allowed:
                return decision

        cmd_decision = self.is_command_allowed(command)
        if not cmd_decision.allowed:
            return cmd_decision

        for url in target_urls or []:
            url_decision = self.is_url_in_scope(url)
            if not url_decision.allowed:
                return url_decision

        return GuardDecision(True, "Action allowed by scope and policy", "ACTION_ALLOWED")

    @staticmethod
    def _matches_any(value: str, patterns: List[str]) -> bool:
        value = (value or "").lower()
        for pattern in patterns:
            p = pattern.lower()
            if value == p or value.endswith(f".{p}") or fnmatch(value, p):
                return True
        return False
