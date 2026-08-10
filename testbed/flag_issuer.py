#!/usr/bin/env python3
"""Run-specific protected-flag issuer for the CAGE-Cloud cloud-CVE testbed.

This is the evaluation *control plane*. For scenario ``i`` and run ``r`` the
controller samples a fresh cryptographically random nonce ``n`` and derives the
protected flag value

    phi = FLAG{ Hex[ HMAC_{k_i}( run_id || nonce ) ] }

where ``k_i`` is a scenario-specific secret held only by the control plane. The
nonce guarantees that repeated executions of the same CVE receive different
expected values, so the flag can never be hard-coded or replayed.

Security posture:
  * ``k_i`` and the expected flag live only under ``control_plane/`` (git-ignored)
    and are never exposed to the assessed pipeline.
  * The flag is provisioned into the running target *only* through the
    ``CAGE_PROTECTED_FLAG`` environment variable; the lab reveals it solely
    behind the intended security condition (the vulnerable endpoint).
  * Each issuance writes a provenance record (run id, scenario id, timestamp,
    and a digest of the issued flag) linking the flag to its run.

Typical use (per run, before the target container is started):

    from testbed.flag_issuer import issue_flag
    rec = issue_flag("CVE-2023-29332")
    # docker run -e CAGE_PROTECTED_FLAG=... :
    subprocess.run([..., "-e", f"CAGE_PROTECTED_FLAG={rec['flag']}", ...])
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Dict, Optional

# Control-plane storage (secrets + expected flags + provenance). Git-ignored.
CONTROL_PLANE = Path(
    os.environ.get("CAGE_CONTROL_PLANE", Path(__file__).with_name("control_plane"))
)
SECRETS_FILE = CONTROL_PLANE / "scenario_secrets.json"
ISSUANCE_FILE = CONTROL_PLANE / "issuance.jsonl"

# Length of the scenario secret k_i and the per-run nonce, in bytes.
_SECRET_BYTES = 32
_NONCE_BYTES = 16


def _load_secrets() -> Dict[str, str]:
    if SECRETS_FILE.exists():
        return json.loads(SECRETS_FILE.read_text(encoding="utf-8"))
    return {}


def _scenario_secret(scenario_id: str, store: Dict[str, str]) -> bytes:
    """Return the scenario-specific secret k_i, minting and persisting one on first use."""
    if scenario_id not in store:
        store[scenario_id] = secrets.token_hex(_SECRET_BYTES)
        CONTROL_PLANE.mkdir(parents=True, exist_ok=True)
        SECRETS_FILE.write_text(
            json.dumps(store, indent=2, sort_keys=True), encoding="utf-8"
        )
    return bytes.fromhex(store[scenario_id])


def derive_flag(secret_k: bytes, run_id: str, nonce: str) -> str:
    """Compute FLAG{ Hex[ HMAC_{k}( run_id || nonce ) ] } (paper Eq. 26)."""
    mac = hmac.new(secret_k, f"{run_id}||{nonce}".encode("utf-8"), hashlib.sha256)
    return f"FLAG{{{mac.hexdigest()}}}"


def issue_flag(
    scenario_id: str,
    run_id: Optional[str] = None,
    security_condition_id: str = "protected_terminal_objective",
) -> Dict[str, str]:
    """Issue a fresh run-specific flag for ``scenario_id`` and record its provenance.

    Returns a control-plane record; only ``record['flag']`` is provisioned into
    the target (never the secret or the nonce derivation).
    """
    store = _load_secrets()
    secret_k = _scenario_secret(scenario_id, store)
    run_id = run_id or f"{scenario_id}-{secrets.token_hex(8)}"
    nonce = secrets.token_hex(_NONCE_BYTES)
    flag = derive_flag(secret_k, run_id, nonce)

    record = {
        "run_id": run_id,
        "scenario_id": scenario_id,
        "security_condition_id": security_condition_id,
        "nonce": nonce,
        "flag": flag,
        "flag_digest": hashlib.sha256(flag.encode("utf-8")).hexdigest(),
        "issued_at": time.time(),
    }

    CONTROL_PLANE.mkdir(parents=True, exist_ok=True)
    (CONTROL_PLANE / f"{run_id}.json").write_text(
        json.dumps(record, indent=2), encoding="utf-8"
    )
    with open(ISSUANCE_FILE, "a", encoding="utf-8") as fh:
        fh.write(
            json.dumps(
                {
                    "run_id": run_id,
                    "scenario_id": scenario_id,
                    "security_condition_id": security_condition_id,
                    "issued_at": record["issued_at"],
                    "flag_digest": record["flag_digest"],
                }
            )
            + "\n"
        )
    return record


def expected_flag(run_id: str) -> str:
    """Return the expected flag for a completed issuance (control-plane lookup)."""
    rec = json.loads((CONTROL_PLANE / f"{run_id}.json").read_text(encoding="utf-8"))
    return rec["flag"]


def _demo() -> int:
    """Self-check: two issuances of the same scenario must differ."""
    a = issue_flag("CVE-0000-0000", run_id="demo-a")
    b = issue_flag("CVE-0000-0000", run_id="demo-b")
    assert a["flag"] != b["flag"], "run-specific flags must differ"
    assert a["flag"].startswith("FLAG{") and a["flag"].endswith("}")
    print("issue_flag OK — two runs, two distinct flags:")
    print("  run demo-a:", a["flag"])
    print("  run demo-b:", b["flag"])
    return 0


if __name__ == "__main__":
    raise SystemExit(_demo())
