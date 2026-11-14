"""Tests for IncidentLens.

    py -m pytest test_incidentlens.py -q

Most of these exist because something was wrong and this is what wrong
looked like. Four of them pin bugs that produced confident, completely
false output during the build:

  * a number glued to a unit ("56ms") was never masked, so every distinct
    millisecond value became its own log template: 3,795 templates and
    10,476 spurious "never seen before" anomalies;
  * per-minute log counts were judged against a round-the-clock median, so
    every working day looked like an incident;
  * the MAD floor was a fraction of the median, and per-minute counts have a
    median of zero, so a single extra log line scored z = 1.3e9;
  * a 3-minute run-gap split one memory leak into 24 anomalies.

The last two tests are the measurements the README quotes, so the README
cannot drift away from the code without a test failing.
"""
import os
import subprocess
import sys

import numpy as np
import pandas as pd
import pytest

from incidentlens.anomaly import (detect_metric_anomalies,
                                  detect_template_anomalies, robust_stats,
                                  robust_z, seasonal_profile, _runs)
from incidentlens.causes import rank_causes
from incidentlens.config import (DEPENDENCIES, PLANTED, dependency_distance,
                                 is_upstream_of, real_planted)
from incidentlens.incidents import group_incidents
from incidentlens.similar import fingerprint, jaccard, find_similar
from incidentlens.templates import build_templates, mask, per_minute_counts

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
HAVE_DATA = os.path.exists(os.path.join(DATA, "metrics.csv"))
needs_data = pytest.mark.skipif(not HAVE_DATA,
                                reason="run scripts/make_sample_data.py first")


# ---------------------------------------------------------------------------
# Templating
# ---------------------------------------------------------------------------
def test_mask_collapses_variable_parts():
    a = mask("handled request id=4f1a9c33 path=/v1/orders status=200 in 42ms")
    b = mask("handled request id=90bb2e01 path=/v1/orders status=200 in 17ms")
    assert a == b


def test_mask_handles_a_number_glued_to_its_unit():
    """The bug that produced 3,795 templates instead of 20.

    \\b needs a non-word character after the digits and there is none between
    the 6 and the m of "56ms", so the plain-number rule cannot match it.
    """
    assert mask("db query took 56ms rows=12") == \
        mask("db query took 981ms rows=7")
    assert "<NUM>ms" in mask("db query took 56ms rows=12")


def test_mask_keeps_the_unit():
    """"took <NUM>ms" and "took <NUM>rows" must not collapse together."""
    assert mask("waited 40ms") != mask("waited 40s")


def test_mask_order_uuid_before_number():
    out = mask("session 4f1a9c33-1111-2222-3333-444455556666 from 10.1.2.3")
    assert "<UUID>" in out and "<IP>" in out
    assert "<NUM>." not in out        # the IP was not eaten digit by digit


def test_build_templates_assigns_stable_ids():
    logs = pd.DataFrame({
        "service": ["a"] * 4,
        "message": ["x took 1ms", "x took 2ms", "y failed code=5", "x took 9ms"],
        "level": ["INFO"] * 4,
        "minute": [0, 1, 2, 3],
    })
    out, table = build_templates(logs)
    assert len(table) == 2
    assert out[out["message"] == "x took 1ms"]["template_id"].iloc[0] == \
        out[out["message"] == "x took 9ms"]["template_id"].iloc[0]


# ---------------------------------------------------------------------------
# Robust statistics
# ---------------------------------------------------------------------------
def test_median_resists_an_outlier_that_a_mean_does_not():
    clean = [10.0] * 50
    spiked = clean + [10_000.0]
    med, mad = robust_stats(clean)
    assert abs(robust_z(10_000.0, med, mad)) > 100
    # the mean-based equivalent is dragged towards the outlier
    mean, sd = float(np.mean(spiked)), float(np.std(spiked))
    assert abs((10_000.0 - mean) / sd) < 10


def test_mad_floor_is_absolute_for_counts():
    """The z = 1.3e9 bug: a median of zero and a fractional floor.

    Per-minute log counts are mostly zero, so a floor of 2% of the median is
    no floor at all.
    """
    counts = [0.0] * 60
    _, mad_fractional = robust_stats(counts, floor_fraction=0.25)
    _, mad_absolute = robust_stats(counts, floor_fraction=0.25, floor_abs=1.0)
    assert mad_absolute >= 1.0
    assert robust_z(2.0, 0.0, mad_absolute) < 6.0      # two lines is not news
    assert robust_z(2.0, 0.0, mad_fractional) > 1e6    # what it used to do


def test_runs_tolerates_gaps_and_splits_on_long_ones():
    assert _runs([1, 2, 4, 20, 21], max_gap=3) == [(1, 4), (20, 21)]
    assert _runs([1, 8, 15], max_gap=10) == [(1, 15)]
    assert _runs([1, 8, 15], max_gap=3) == [(1, 1), (8, 8), (15, 15)]


def test_seasonal_profile_finds_the_daily_shape():
    minutes = np.arange(1440)
    values = np.array([100.0 if 8 <= (m // 60) % 24 < 18 else 50.0
                       for m in minutes])
    profile = seasonal_profile(minutes, values, ref_cutoff=1440)
    assert profile[12] > profile[3]
    assert profile[12] / profile[3] == pytest.approx(2.0, rel=0.05)


# ---------------------------------------------------------------------------
# Dependency graph
# ---------------------------------------------------------------------------
def test_upstream_direction_is_not_symmetric():
    # orders calls payments, so payments is upstream of orders, not vice versa
    assert is_upstream_of("payments", "orders")
    assert not is_upstream_of("orders", "payments")


def test_upstream_is_transitive():
    # gateway -> orders -> payments -> db-proxy
    assert is_upstream_of("db-proxy", "gateway")


def test_dependency_distance_is_symmetric_and_bounded():
    assert dependency_distance("payments", "payments") == 0
    assert dependency_distance("gateway", "orders") == 1
    assert dependency_distance("orders", "gateway") == 1
    assert dependency_distance("notify", "db-proxy", limit=1) is None


def test_every_dependency_names_a_real_service():
    for svc, calls in DEPENDENCIES.items():
        for c in calls:
            assert c in DEPENDENCIES, f"{svc} calls unknown service {c}"


# ---------------------------------------------------------------------------
# Grouping rules
# ---------------------------------------------------------------------------
def _metric(service, signal, start, end, z=30.0, severity="high"):
    return {"kind": "metric", "service": service, "signal": signal,
            "start_min": start, "end_min": end, "peak_min": start,
            "peak_z": z, "severity": severity, "strategy": "reference"}


def test_an_alert_alone_is_never_an_incident():
    """The noisy-alert case. A system that pages on every alert is the
    system this project exists to replace."""
    alerts = [{"service": "notify", "rule": "probe_flapped", "minute": 100,
               "severity": "warning"}]
    incidents, rejected = group_incidents([], [], alerts)
    assert incidents == []
    assert len(rejected) == 1
    assert "no corroborating" in rejected[0]["reason"]


def test_a_single_brief_signal_is_rejected():
    incidents, rejected = group_incidents(
        [_metric("db-proxy", "error_rate", 500, 500, z=6.7, severity="low")],
        [], [])
    assert incidents == []
    assert "single brief signal" in rejected[0]["reason"]


def test_a_severe_signal_stands_on_its_own():
    incidents, _ = group_incidents(
        [_metric("db-proxy", "latency_ms", 500, 500, z=95.0,
                 severity="high")], [], [])
    assert len(incidents) == 1


def test_connected_services_in_the_same_window_become_one_incident():
    anoms = [
        _metric("db-proxy", "latency_ms", 100, 150),
        _metric("search", "latency_ms", 102, 150),
        _metric("auth", "latency_ms", 102, 150),
    ]
    incidents, _ = group_incidents(anoms, [], [])
    assert len(incidents) == 1
    assert incidents[0]["first_service"] == "db-proxy"
    assert set(incidents[0]["services"]) == {"db-proxy", "search", "auth"}


def test_the_same_services_far_apart_in_time_stay_separate():
    anoms = [
        _metric("payments", "error_rate", 100, 140),
        _metric("orders", "error_rate", 101, 140),
        _metric("payments", "error_rate", 6000, 6040),
        _metric("orders", "error_rate", 6001, 6040),
    ]
    incidents, _ = group_incidents(anoms, [], [])
    assert len(incidents) == 2


def test_distant_services_in_the_same_minute_stay_separate():
    """Time alone must not merge: notify and db-proxy are three hops apart."""
    assert dependency_distance("notify", "db-proxy", limit=2) is None
    anoms = [
        _metric("notify", "latency_ms", 100, 140),
        _metric("db-proxy", "latency_ms", 100, 140),
    ]
    incidents, _ = group_incidents(anoms, [], [])
    assert len(incidents) == 2


# ---------------------------------------------------------------------------
# Cause ranking
# ---------------------------------------------------------------------------
def _incident(services, first, start=100, end=140, signals=None):
    sigs = signals or [_metric(s, "error_rate", start + i, end)
                       for i, s in enumerate(services)]
    return {"incident_id": "INC-001", "start_min": start, "end_min": end,
            "services": sorted(services), "first_service": first,
            "first_signal": "error_rate", "first_anomaly_min": start,
            "signals": [{**s, "signal_type": "metric"} for s in sigs],
            "alerts": [], "severity": "high"}


def _deploy(service, minute, version="v9.9.9"):
    from datetime import timedelta
    from incidentlens.config import START
    return {"service": service, "minute": minute, "version": version,
            "author": "t.test", "commit_message": "a change",
            "timestamp": START + timedelta(minutes=minute)}


def test_a_deploy_just_before_onset_on_the_failing_service_wins():
    inc = _incident(["payments", "orders", "gateway"], "payments")
    causes = rank_causes(inc, [_deploy("payments", 97)])
    assert causes[0]["type"] == "deploy"
    assert causes[0]["service"] == "payments"


def test_an_old_deploy_is_not_an_explanation():
    inc = _incident(["payments", "orders", "gateway"], "payments")
    causes = rank_causes(inc, [_deploy("payments", 100 - 600)])
    assert causes[0]["type"] == "service"


def test_an_unrelated_deploy_is_not_a_candidate():
    """auth is neither in this incident nor a dependency of anything in it.

    The first version of this test used notify, which orders calls -- so a
    release there IS a legitimate candidate, and the code was right to offer
    it. The dependency map decides this, not intuition about names.
    """
    inc = _incident(["payments", "orders"], "payments")
    assert not any(is_upstream_of("auth", s) for s in ("payments", "orders"))
    causes = rank_causes(inc, [_deploy("auth", 97)])
    assert all(c["type"] == "service" for c in causes)


def test_a_deploy_on_a_dependency_is_a_weak_candidate():
    """notify is called by orders, so a release there is worth considering,
    but it must not outrank the service the incident started on."""
    inc = _incident(["payments", "orders"], "payments")
    causes = rank_causes(inc, [_deploy("notify", 97)])
    deploys = [c for c in causes if c["type"] == "deploy"]
    assert len(deploys) == 1
    assert causes[0]["type"] == "service"
    assert causes[0]["score"] > deploys[0]["score"]


def test_an_upstream_service_outranks_a_deploy_on_collateral():
    """A service that started first AND sits upstream of everything else
    beats a release on a service that was merely caught in it."""
    inc = _incident(["db-proxy", "search", "auth", "inventory", "payments"],
                    "db-proxy")
    causes = rank_causes(inc, [_deploy("search", 97)])
    assert causes[0]["type"] == "service"
    assert causes[0]["service"] == "db-proxy"


def test_every_candidate_shows_its_arithmetic():
    inc = _incident(["payments", "orders"], "payments")
    causes = rank_causes(inc, [_deploy("payments", 97)])
    for c in causes:
        assert c["components"]
        assert sum(c["components"].values()) == c["score"]
        assert c["evidence"]


def test_a_close_race_is_reported_as_low_confidence():
    inc = _incident(["payments", "inventory"], "payments")
    causes = rank_causes(inc, [])
    if len(causes) > 1 and causes[0]["score"] - causes[1]["score"] < 10:
        assert causes[0]["confidence"].startswith("low")


# ---------------------------------------------------------------------------
# Similarity
# ---------------------------------------------------------------------------
def test_identical_symptom_sets_match_and_different_ones_do_not():
    a = _incident(["payments", "orders", "gateway"], "payments", 100, 140)
    b = _incident(["payments", "orders", "gateway"], "payments", 6000, 6040)
    c = _incident(["db-proxy", "search"], "db-proxy", 9000, 9040)
    b["incident_id"], c["incident_id"] = "INC-002", "INC-003"
    assert jaccard(fingerprint(a), fingerprint(b)) == 1.0
    assert jaccard(fingerprint(a), fingerprint(c)) == 0.0


def test_similarity_only_looks_backwards():
    a = _incident(["payments", "orders"], "payments", 100, 140)
    b = _incident(["payments", "orders"], "payments", 6000, 6040)
    b["incident_id"] = "INC-002"
    matches = find_similar([a, b])
    assert matches["INC-001"] == []                 # nothing before it
    assert matches["INC-002"][0]["incident_id"] == "INC-001"


def test_alerts_do_not_contribute_to_a_fingerprint():
    inc = _incident(["payments"], "payments")
    inc["signals"].append({"signal_type": "alert", "service": "payments",
                           "signal": "error_rate_above_5pct", "start_min": 105,
                           "end_min": 105, "peak_z": None,
                           "severity": "critical", "kind": "alert"})
    assert all(sig != "error_rate_above_5pct" for _, sig in fingerprint(inc))


def test_template_ids_are_generalised_before_matching():
    a = _incident(["payments"], "payments",
                  signals=[_metric("payments", "new_template:17", 100, 140)])
    b = _incident(["payments"], "payments",
                  signals=[_metric("payments", "new_template:91", 100, 140)])
    assert jaccard(fingerprint(a), fingerprint(b)) == 1.0


# ---------------------------------------------------------------------------
# End to end, on the generated data
# ---------------------------------------------------------------------------
@needs_data
def test_templating_collapses_the_week_to_about_twenty_templates():
    from incidentlens.ingest import load_logs
    logs, _ = load_logs(DATA)
    _, table = build_templates(logs)
    assert 10 <= len(table) <= 40, \
        f"{len(table)} templates: masking has regressed"


@needs_data
def test_only_the_planted_fault_templates_are_new():
    from incidentlens.ingest import load_logs
    from incidentlens.config import REFERENCE_HOURS
    logs, _ = load_logs(DATA)
    logs, table = build_templates(logs)
    early = set(logs[logs["minute"] < REFERENCE_HOURS * 60]["template_id"])
    new = set(table["template_id"]) - early
    assert len(new) == 3, f"expected the 3 fault templates, got {len(new)}"


@needs_data
def test_log_anomalies_are_only_the_fault_templates():
    """The seasonality and MAD-floor bugs together produced 5,430 log
    anomalies on this data, all of them ordinary daytime traffic."""
    from incidentlens.ingest import load_logs
    logs, _ = load_logs(DATA)
    logs, _ = build_templates(logs)
    anomalies = detect_template_anomalies(per_minute_counts(logs))
    assert len(anomalies) < 20, f"{len(anomalies)} log anomalies"
    assert all(a["signal"].startswith("new_template:") for a in anomalies)


@needs_data
def test_the_pipeline_finds_every_real_fault_and_rejects_the_noise():
    from incidentlens.ingest import load_all
    data = load_all(DATA)
    logs, _ = build_templates(data["logs"])
    metric_anoms = detect_metric_anomalies(data["metrics"])
    log_anoms = detect_template_anomalies(per_minute_counts(logs))
    incidents, _ = group_incidents(metric_anoms, log_anoms, data["alerts"])

    for p in PLANTED:
        start, end = p["start_min"], p["start_min"] + p["duration_min"]
        hit = [i for i in incidents
               if p["service"] in i["services"]
               and i["start_min"] - 20 <= end and start - 20 <= i["end_min"]]
        if p["real"]:
            assert hit, f"{p['id']} was not detected"
        else:
            assert not hit, f"{p['id']} is noise and became an incident"


@needs_data
def test_every_planted_cause_is_ranked_first():
    from incidentlens.ingest import load_all
    data = load_all(DATA)
    logs, _ = build_templates(data["logs"])
    incidents, _ = group_incidents(
        detect_metric_anomalies(data["metrics"]),
        detect_template_anomalies(per_minute_counts(logs)),
        data["alerts"])

    for p in real_planted():
        start, end = p["start_min"], p["start_min"] + p["duration_min"]
        inc = next(i for i in incidents
                   if p["service"] in i["services"]
                   and i["start_min"] - 20 <= end and start - 20 <= i["end_min"])
        top = rank_causes(inc, data["deploys"])[0]
        assert (top["type"], top["service"]) == \
            (p["cause"]["type"], p["cause"]["service"]), \
            f"{p['id']}: ranked {top['type']}/{top['service']}"


@needs_data
def test_the_repeat_links_back_to_the_first_occurrence():
    from incidentlens.ingest import load_all
    data = load_all(DATA)
    logs, _ = build_templates(data["logs"])
    incidents, _ = group_incidents(
        detect_metric_anomalies(data["metrics"]),
        detect_template_anomalies(per_minute_counts(logs)),
        data["alerts"])
    repeat = next(p for p in PLANTED if p.get("repeat_of"))

    def find(p):
        start, end = p["start_min"], p["start_min"] + p["duration_min"]
        return next(i for i in incidents
                    if p["service"] in i["services"]
                    and i["start_min"] - 20 <= end
                    and start - 20 <= i["end_min"])

    later, first = find(repeat), find(next(p for p in PLANTED
                                           if p["id"] == repeat["repeat_of"]))
    matches = find_similar(incidents)[later["incident_id"]]
    assert any(m["incident_id"] == first["incident_id"] for m in matches)


@needs_data
def test_the_coverage_numbers_the_readme_quotes():
    """The README's claim is that both baselines are identical on the fast
    faults and diverge on the slow one. If that stops being true, this
    fails rather than the README quietly going stale."""
    from incidentlens.ingest import load_metrics
    metrics = load_metrics(DATA)
    coverage = {}
    for strategy in ("reference", "trailing"):
        anomalies = detect_metric_anomalies(metrics, strategy=strategy)
        for p in real_planted():
            start, end = p["start_min"], p["start_min"] + p["duration_min"]
            covered = {m for a in anomalies if a["service"] == p["service"]
                       for m in range(a["start_min"], a["end_min"] + 1)
                       if start <= m < end}
            coverage[(strategy, p["id"])] = len(covered) / p["duration_min"]

    for fast in ("bad-deploy-1", "db-slowdown", "bad-deploy-2"):
        assert coverage[("reference", fast)] == 1.0
        assert coverage[("trailing", fast)] == 1.0

    ref = coverage[("reference", "memory-leak")]
    trail = coverage[("trailing", "memory-leak")]
    assert ref > trail + 0.15, \
        f"reference {ref:.2f} vs trailing {trail:.2f}: no longer a difference"
    assert 0.7 < ref < 0.9 and 0.4 < trail < 0.6


@needs_data
def test_the_demo_runs_and_its_self_check_passes():
    here = os.path.dirname(os.path.abspath(__file__))
    proc = subprocess.run([sys.executable, "run_demo.py"], cwd=here,
                          capture_output=True, text=True, timeout=2400)
    assert proc.returncode == 0, proc.stdout[-3000:] + proc.stderr[-2000:]
    assert "all checks passed" in proc.stdout
