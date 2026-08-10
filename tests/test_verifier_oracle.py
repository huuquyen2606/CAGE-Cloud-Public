import hashlib
import json
import os
from pathlib import Path

from cage_cloud.verifier import verify_task_execution
from testbed.flag_oracle import evaluate_results_dir
from testbed.inject_flags import update_lab_file


def test_legacy_verifier_preserves_typed_evidence_and_action_contract():
    task = {
        "id": "task-1",
        "action_id": "action-1",
        "objective_type": "target_reachable",
        "expected_evidence": ["HTTP_STATUS_REACHABLE"],
    }
    verdict = verify_task_execution(
        task,
        [{
            "command": "curl http://target",
            "return_code": 0,
            "http_status": 200,
            "response_headers": {"server": "nginx"},
            "response_snippet": "ok",
            "attributes": {"provenance": "executor"},
        }],
        {},
        {},
    )
    assert verdict["status"] == "verified"
    assert verdict["action_id"] == "action-1"
    assert verdict["missing_evidence"] == []
    assert verdict["evidence_summary"]["artifacts"][0]["http_status"] == 200


def test_exploit_verifier_rejects_internal_parser_delta():
    verdict = verify_task_execution(
        {
            "id": "task-2",
            "action_id": "action-2",
            "objective_type": "exploit_effect_confirmed",
        },
        [{"command": "curl /CVE-2024-0001", "return_code": 1, "stdout": "", "stderr": "failed"}],
        {"vulnerabilities_found": [], "credentials_found": {}},
        {"vulnerabilities_found": [{"id": "command-regex"}], "credentials_found": {}},
    )
    assert verdict["status"] == "unverified"
    assert "EXPLOIT_EFFECT_STATE_CHANGE" not in verdict["matched_rule_ids"]


def _write_oracle_fixture(root: Path, flag_in: str) -> None:
    flag = "FLAG{run-specific}"
    digest = hashlib.sha256(flag.encode()).hexdigest()
    (root / "flags_expected.json").write_text(json.dumps({
        "schema_version": 1,
        "runs": [{
            "run_id": "run-1",
            "scenario_id": "CVE-2024-0001",
            "security_condition_id": "condition-1",
            "expected_flag": flag,
            "flag_digest": digest,
            "issued_at": 1,
            "exec_file": "run_exec.json",
        }],
    }), encoding="utf-8")
    record = {"command": "echo harmless", "stdout": "no flag", "stderr": ""}
    record[flag_in] = flag
    (root / "run_exec.json").write_text(json.dumps([record]), encoding="utf-8")
    (root / "target_events.jsonl").write_text(json.dumps({
        "run_id": "run-1",
        "scenario_id": "CVE-2024-0001",
        "security_condition_id": "condition-1",
        "flag_digest": digest,
        "timestamp": 2,
        "condition_satisfied": True,
    }) + "\n", encoding="utf-8")


def test_oracle_does_not_match_flag_in_command(tmp_path: Path):
    _write_oracle_fixture(tmp_path, "command")
    outcome = evaluate_results_dir(tmp_path)[0]
    assert not outcome.exact_match
    assert not outcome.external_success


def test_oracle_requires_all_eq27_conditions(tmp_path: Path):
    _write_oracle_fixture(tmp_path, "stdout")
    outcome = evaluate_results_dir(tmp_path)[0]
    assert outcome.exact_match
    assert outcome.target_issued
    assert outcome.condition_satisfied
    assert outcome.external_success

    event_path = tmp_path / "target_events.jsonl"
    event = json.loads(event_path.read_text(encoding="utf-8"))
    event["condition_satisfied"] = False
    event_path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    failed = evaluate_results_dir(tmp_path)[0]
    assert failed.exact_match and failed.target_issued
    assert not failed.condition_satisfied
    assert not failed.external_success


def test_oracle_reads_protocol_body_inside_execution_wrapper(tmp_path: Path):
    _write_oracle_fixture(tmp_path, "ignored")
    exec_path = tmp_path / "run_exec.json"
    payload = json.loads(exec_path.read_text(encoding="utf-8"))
    payload[0].pop("ignored")
    payload[0]["protocol"] = {
        "request": "FLAG{must-not-match-request}",
        "body": "FLAG{run-specific}",
    }
    exec_path.write_text(json.dumps({"execution_history": payload}), encoding="utf-8")
    assert evaluate_results_dir(tmp_path)[0].external_success


def test_inject_flags_generates_valid_dynamic_python(tmp_path: Path, monkeypatch):
    cve = "CVE-2024-0001"
    lab = tmp_path / "lab.py"
    lab.write_text(
        '"""Lab module."""\n'
        'def plain():\n'
        f'    return {{"flag": "FLAG{{{cve}_pwned}}"}}\n'
        'def triple():\n'
        f'    return """prefix FLAG{{{cve}_pwned}} suffix"""\n',
        encoding="utf-8",
    )
    ok, message = update_lab_file(lab, cve)
    assert ok, message
    source = lab.read_text(encoding="utf-8")
    assert f"FLAG{{{cve}_pwned}}" not in source
    compile(source, str(lab), "exec")
    monkeypatch.setenv("CAGE_PROTECTED_FLAG", "FLAG{dynamic}")
    namespace = {"os": os}
    exec(source, namespace)
    assert namespace["plain"]()["flag"] == "FLAG{dynamic}"
    assert namespace["triple"]() == "prefix FLAG{dynamic} suffix"
