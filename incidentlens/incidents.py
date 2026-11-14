"""Group anomalies and alerts that belong to the same failure.

A database slowdown that spreads to its three callers produces anomalies on
four services. Reporting four incidents would be worse than useless: the
on-call engineer would page four teams for one problem. Two signals belong
together when they are close in time **and** connected in the dependency
map. Time alone is not enough -- two unrelated services can degrade in the
same minute by coincidence -- and connection alone is not enough either,
since every service here is connected to something.

Two rules decide what becomes an incident at all, and both exist because of
specific noise in the sample data:

  An alert on its own is not an incident. The planted noisy alert fires with
  no metric movement and no log spike behind it, and a system that paged on
  every alert would not need this project. A cluster must contain at least
  one metric or log anomaly.

  A single one-minute blip is not an incident. db-proxy's error rate sits at
  0.001, so one noisy sample is a large multiple of the baseline and clears
  any z threshold. A cluster needs either corroboration from a second signal
  or one signal that is sustained or severe.
"""
from .config import dependency_distance

JOIN_WINDOW_MIN = 15        # how far apart in time two signals can still join
JOIN_MAX_HOPS = 2           # how far apart in the dependency graph
MIN_SUSTAINED_MIN = 5       # a lone signal must last this long to count


class _Union:
    def __init__(self, n):
        self.parent = list(range(n))

    def find(self, i):
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def join(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _as_signals(metric_anomalies, log_anomalies, alerts):
    signals = []
    for a in metric_anomalies + log_anomalies:
        signals.append({**a, "signal_type": a["kind"]})
    for al in alerts:
        signals.append({
            "kind": "alert", "signal_type": "alert",
            "service": al["service"], "signal": al["rule"],
            "start_min": al["minute"], "end_min": al["minute"],
            "peak_min": al["minute"], "peak_z": None,
            "severity": al["severity"], "strategy": "alert_rule",
        })
    return sorted(signals, key=lambda s: (s["start_min"], s["service"]))


def _can_join(a, b):
    gap = max(a["start_min"], b["start_min"]) - min(a["end_min"], b["end_min"])
    if gap > JOIN_WINDOW_MIN:
        return False
    hops = dependency_distance(a["service"], b["service"], limit=JOIN_MAX_HOPS)
    return hops is not None and hops <= JOIN_MAX_HOPS


def group_incidents(metric_anomalies, log_anomalies, alerts):
    """Clusters of signals, with the ones that do not qualify kept and
    labelled rather than dropped, so the demo can show what it rejected and
    why."""
    signals = _as_signals(metric_anomalies, log_anomalies, alerts)
    if not signals:
        return [], []

    union = _Union(len(signals))
    for i in range(len(signals)):
        for j in range(i + 1, len(signals)):
            if signals[j]["start_min"] - signals[i]["end_min"] > JOIN_WINDOW_MIN:
                continue      # sorted by time, but ranges vary, so only skip
            if _can_join(signals[i], signals[j]):
                union.join(i, j)

    clusters = {}
    for i, s in enumerate(signals):
        clusters.setdefault(union.find(i), []).append(s)

    incidents, rejected = [], []
    for n, members in enumerate(sorted(clusters.values(),
                                       key=lambda ms: min(m["start_min"]
                                                          for m in ms))):
        evidence = [m for m in members if m["signal_type"] in ("metric", "log")]
        member_alerts = [m for m in members if m["signal_type"] == "alert"]

        if not evidence:
            rejected.append({
                "reason": "alert with no corroborating metric or log anomaly",
                "services": sorted({m["service"] for m in members}),
                "start_min": min(m["start_min"] for m in members),
                "signals": members,
            })
            continue

        longest = max(m["end_min"] - m["start_min"] + 1 for m in evidence)
        severe = any(m["severity"] in ("high", "critical") for m in evidence)
        if len(evidence) < 2 and longest < MIN_SUSTAINED_MIN and not severe:
            rejected.append({
                "reason": f"single brief signal ({longest} min) with no "
                          f"corroboration",
                "services": sorted({m["service"] for m in members}),
                "start_min": min(m["start_min"] for m in members),
                "signals": members,
            })
            continue

        start = min(m["start_min"] for m in members)
        end = max(m["end_min"] for m in members)
        first = min(evidence, key=lambda m: m["start_min"])
        incidents.append({
            "incident_id": f"INC-{n + 1:03d}",
            "start_min": start,
            "end_min": end,
            "services": sorted({m["service"] for m in members}),
            "first_service": first["service"],
            "first_signal": first["signal"],
            "first_anomaly_min": first["start_min"],
            "signals": sorted(members, key=lambda m: m["start_min"]),
            "alerts": member_alerts,
            "severity": "high" if severe else "medium",
        })

    # renumber after filtering so ids are contiguous
    for n, inc in enumerate(incidents, 1):
        inc["incident_id"] = f"INC-{n:03d}"
    return incidents, rejected


def timeline(incident):
    """The incident as an ordered list of events, each carrying the signal
    that evidences it. Nothing in a timeline should be unattributable."""
    rows = []
    for s in incident["signals"]:
        if s["signal_type"] == "alert":
            what = f"alert fired: {s['signal']} ({s['severity']})"
        elif s["signal_type"] == "log":
            what = (f"log {s['signal']} on {s['service']}, peak "
                    f"{s.get('peak_count', '?')} lines/min")
        else:
            what = (f"{s['signal']} on {s['service']} departed baseline "
                    f"(z={s['peak_z']})")
        rows.append({
            "minute": s["start_min"],
            "service": s["service"],
            "event": what,
            "evidence": s,
        })
    return sorted(rows, key=lambda r: r["minute"])
