from cage_cloud.state_commit import finalize_transition


def test_finalize_transition_rolls_back_unverified_changes():
    before = {
        "credentials_found": {},
        "findings": [],
        "objective_verifications": [],
        "candidate_observations": [],
    }
    state = {
        "credentials_found": {"AWS_ACCESS_KEY_ID": "AKIAEXAMPLE00000000"},
        "findings": ["credential observed"],
        "objective_verifications": [],
        "candidate_observations": [],
    }
    verification = {
        "objective_type": "credential_extracted",
        "status": "unverified",
        "supporting_evidence_ids": ["ev-1"],
    }

    finalize_transition(state, before, verification, {"name": "extract creds"})

    assert state["credentials_found"] == {}
    assert state["findings"] == []
    assert state["objective_verifications"][0]["status"] == "unverified"
    assert state["candidate_observations"][0]["candidate_delta"]["credentials_found"]["added_count"] == 1


def test_finalize_transition_keeps_verified_changes():
    before = {
        "flags_found": [],
        "objective_verifications": [],
        "candidate_observations": [],
    }
    state = {
        "flags_found": ["FLAG{verified}"],
        "objective_verifications": [],
        "candidate_observations": [],
    }
    verification = {
        "objective_type": "protected_resource_read",
        "status": "verified",
        "supporting_evidence_ids": ["ev-2"],
    }

    finalize_transition(state, before, verification, {"name": "read flag"})

    assert state["flags_found"] == ["FLAG{verified}"]
    assert state["objective_verifications"][0]["status"] == "verified"
    assert state["candidate_observations"][0]["status"] == "verified"
