from evaluation.compute_metrics import RunMetrics, coverage_by_architecture, summarize


def _run(run_id: str, cve: str, architecture: str, backbone: str, flag: int) -> RunMetrics:
    return RunMetrics(
        run_id=run_id,
        cve=cve,
        architecture=architecture,
        backbone=backbone,
        flag_recovered=flag,
        llm_requests=10,
        total_tokens=1000,
    )


def test_summarize_reports_cluster_bootstrap_bounds():
    runs = []
    for idx in range(6):
        runs.append(_run(f"a-{idx}", "CVE-1", "CAGE-Cloud", f"bb-{idx}", 1))
        runs.append(_run(f"b-{idx}", "CVE-2", "CAGE-Cloud", f"bb-{idx}", 0))

    summary = summarize(runs)

    assert summary["FRR"] == 0.5
    assert 0.0 <= summary["FRR_CI_low"] <= summary["FRR"] <= summary["FRR_CI_high"] <= 1.0
    assert summary["FRR_CI_method"] == "scenario_cluster_bootstrap_95"


def test_coverage_by_architecture_tracks_any_and_all_backbones():
    runs = []
    for idx in range(6):
        runs.append(_run(f"a-{idx}", "CVE-1", "CAGE-Cloud", f"bb-{idx}", 1))
        runs.append(_run(f"b-{idx}", "CVE-2", "CAGE-Cloud", f"bb-{idx}", 1 if idx == 0 else 0))

    coverage = coverage_by_architecture(runs)["CAGE-Cloud"]

    assert coverage["scenarios"] == 2
    assert coverage["covered_any"] == 2
    assert coverage["covered_all"] == 1
    assert coverage["ABFC"] == 1.0
    assert coverage["ALBFC"] == 0.5
