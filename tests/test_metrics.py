from evaluation.compute_metrics import RunMetrics, cluster_bootstrap_interval, summarize


def test_cluster_bootstrap_interval_is_deterministic():
    runs = [
        RunMetrics(run_id="r1", cve="CVE-1", architecture="CAGE-Cloud", backbone="b1", flag_recovered=1),
        RunMetrics(run_id="r2", cve="CVE-2", architecture="CAGE-Cloud", backbone="b1", flag_recovered=0),
        RunMetrics(run_id="r3", cve="CVE-3", architecture="CAGE-Cloud", backbone="b1", flag_recovered=1),
    ]
    first = cluster_bootstrap_interval(runs, iterations=200, seed=7)
    second = cluster_bootstrap_interval(runs, iterations=200, seed=7)
    assert first == second
    assert 0.0 <= first[0] <= first[1] <= 1.0


def test_summarize_uses_exploit_activity_for_ecar():
    runs = [
        RunMetrics(
            run_id="r1",
            cve="CVE-1",
            architecture="CAGE-Cloud",
            backbone="b1",
            exploit_activity=2,
            total_tokens=100,
            llm_requests=2,
        ),
        RunMetrics(
            run_id="r2",
            cve="CVE-2",
            architecture="CAGE-Cloud",
            backbone="b1",
            exploit_activity=0,
            total_tokens=100,
            llm_requests=2,
        ),
    ]
    metric = summarize(runs)
    assert metric["ECAR"] == 0.5
    assert metric["ECY@T"] == 1.0
    assert metric["FRR_CI_method"] == "scenario_cluster_bootstrap_95"

