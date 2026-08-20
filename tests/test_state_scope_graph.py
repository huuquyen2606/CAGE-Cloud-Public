import json

from cage_cloud.graph import GraphState, progress_signature
from cage_cloud.scope_guard import ScopeGuard, ScopePolicy
from cage_cloud.state_commit import finalize_transition
from testbed.target_event import emit_target_event


def test_finalize_transition_rolls_back_unverified_candidate():
    before = {
        "findings": [],
        "credentials_found": {},
        "objective_verifications": [],
        "candidate_observations": [],
    }
    state = {
        "findings": ["candidate finding"],
        "credentials_found": {"AWS_ACCESS_KEY_ID": "AKIA1234567890EXAMPLE"},
        "objective_verifications": [],
        "candidate_observations": [],
    }
    verification = {
        "objective_type": "credential_extracted",
        "status": "unverified",
        "supporting_evidence_ids": ["ev-1"],
    }
    finalize_transition(state, before, verification, {"id": "task-1", "name": "Task 1"})
    assert state["findings"] == []
    assert state["credentials_found"] == {}
    assert state["objective_verifications"][0]["status"] == "unverified"
    assert state["candidate_observations"][0]["status"] == "unverified"


def test_finalize_transition_keeps_verified_state():
    before = {"findings": [], "objective_verifications": [], "candidate_observations": []}
    state = {"findings": ["verified finding"], "objective_verifications": [], "candidate_observations": []}
    verification = {
        "objective_type": "target_reachable",
        "status": "verified",
        "supporting_evidence_ids": ["ev-1"],
    }
    finalize_transition(state, before, verification, {"id": "task-2", "name": "Task 2"})
    assert state["findings"] == ["verified finding"]
    assert state["candidate_observations"][0]["status"] == "verified"


def test_scope_guard_blocks_composition_and_out_of_scope_host():
    guard = ScopeGuard(
        ScopePolicy(
            allowed_hosts=["target.local"],
            allowed_tools=["curl", "jq"],
            blocked_command_patterns=["*rm -rf*"],
        )
    )
    assert not guard.is_command_allowed("curl http://target.local && id").allowed
    assert not guard.check_action(command="curl http://example.com", target_urls=["http://example.com"]).allowed
    assert guard.check_action(
        command="curl -s http://target.local | jq .",
        target_urls=["http://target.local"],
    ).allowed


def test_graph_state_does_not_infer_ssrf_from_proxy_endpoint():
    graph = GraphState()
    graph.update_from_state(
        {
            "web_endpoints": ["/proxy"],
            "cve_candidates": ["CVE-2024-0001"],
            "vulnerabilities_found": [{"id": "ssrf", "severity": "HIGH"}],
            "credentials_found": {},
            "findings": [],
            "services_detected": [],
        },
        "lab target",
    )
    node_ids = set(graph.nodes)
    assert "attack_surface:ssrf_pivot" not in node_ids
    assert graph.nodes["endpoint:/proxy"].attributes["status"] == "observed"
    assert graph.nodes["cve_candidate:CVE-2024-0001"].attributes["status"] == "candidate"


def test_progress_signature_excludes_dead_current_credentials():
    state = {
        "objective_verifications": [],
        "credentials_found": {"AWS_ACCESS_KEY_ID": "AKIA123", "AWS_SECRET_ACCESS_KEY": "secret"},
        "dead_credentials": [{"AWS_ACCESS_KEY_ID": "AKIA123", "AWS_SECRET_ACCESS_KEY": "secret"}],
        "cve_success": [],
        "cve_candidates": [],
        "exploits_successful": [],
        "cloud_artifacts": {},
    }
    signature = progress_signature(state)
    assert signature[1] == ()


def test_emit_target_event_writes_digest(tmp_path, monkeypatch):
    monkeypatch.setenv("CAGE_RUN_ID", "run-1")
    monkeypatch.setenv("CAGE_SCENARIO_ID", "CVE-2024-0001")
    monkeypatch.setenv("CAGE_SECURITY_CONDITION_ID", "condition-1")
    output = tmp_path / "target_events.jsonl"
    event = emit_target_event("FLAG{dynamic}", events_file=str(output))
    row = json.loads(output.read_text(encoding="utf-8").strip())
    assert row["run_id"] == "run-1"
    assert row["flag_digest"] == event["flag_digest"]
    assert row["condition_satisfied"] is True
