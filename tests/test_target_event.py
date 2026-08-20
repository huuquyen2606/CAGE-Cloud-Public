import hashlib
import json

from testbed.target_event import emit_target_event


def test_emit_target_event_records_eq27_provenance(tmp_path, monkeypatch):
    events_path = tmp_path / "target_events.jsonl"
    monkeypatch.setenv("CAGE_RUN_ID", "run-123")
    monkeypatch.setenv("CAGE_SCENARIO_ID", "CVE-2026-0001")
    monkeypatch.setenv("CAGE_SECURITY_CONDITION_ID", "condition-1")

    event = emit_target_event("FLAG{dynamic}", events_file=str(events_path))

    saved = json.loads(events_path.read_text(encoding="utf-8").strip())
    assert event["run_id"] == "run-123"
    assert saved["scenario_id"] == "CVE-2026-0001"
    assert saved["security_condition_id"] == "condition-1"
    assert saved["flag_digest"] == hashlib.sha256(b"FLAG{dynamic}").hexdigest()
    assert saved["condition_satisfied"] is True
