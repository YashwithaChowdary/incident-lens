"""Build the IncidentLens web portal as one self-contained HTML page.

    py scripts/make_sample_data.py     # once
    py build_site.py                   # writes docs/index.html
    start docs\\index.html             # open it (Windows)

The page is static: this script runs the pipeline, writes every result into
the page as JSON, and the page draws itself from that. Nothing on the page is
typed in by hand, so it cannot disagree with run_demo.py. Because it is a
single file with no server behind it, it can be hosted as-is on GitHub Pages
from the docs/ folder.
"""
import argparse
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from incidentlens.anomaly import (detect_metric_anomalies,        # noqa: E402
                                  detect_template_anomalies)
from incidentlens.causes import rank_causes                       # noqa: E402
from incidentlens.config import (DEPENDENCIES, MINUTES, PLANTED,  # noqa: E402
                                 REFERENCE_HOURS, START, real_planted)
from incidentlens.incidents import group_incidents, timeline      # noqa: E402
from incidentlens.ingest import load_all                          # noqa: E402
from incidentlens.similar import find_similar                     # noqa: E402
from incidentlens.templates import build_templates, per_minute_counts  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CHART_LEAD_MIN = 90      # how much calm to show before an incident
CHART_TAIL_MIN = 60
MAX_CHARTS = 4


def overlaps(a_start, a_end, b_start, b_end, slack=20):
    return a_start - slack <= b_end and b_start - slack <= a_end


def coverage(anomalies, planted):
    start = planted["start_min"]
    end = start + planted["duration_min"]
    covered = {m for a in anomalies if a["service"] == planted["service"]
               for m in range(a["start_min"], a["end_min"] + 1)
               if start <= m < end}
    return {"covered": len(covered),
            "onset": (min(covered) - start) if covered else None}


def build(data_dir):
    data = load_all(data_dir)
    metrics = data["metrics"]
    logs, template_table = build_templates(data["logs"])
    per_minute = per_minute_counts(logs)

    by_strategy = {s: detect_metric_anomalies(metrics, strategy=s,
                                              reference_hours=REFERENCE_HOURS)
                   for s in ("reference", "trailing")}
    metric_anoms = by_strategy["reference"]
    log_anoms = detect_template_anomalies(per_minute,
                                          reference_hours=REFERENCE_HOURS)
    incidents, rejected = group_incidents(metric_anoms, log_anoms,
                                          data["alerts"])
    similar = find_similar(incidents)

    series = {}
    for (svc, metric), g in metrics.groupby(["service", "metric"]):
        g = g.sort_values("minute")
        series[(svc, metric)] = g["value"].to_numpy(dtype=float)

    # which planted event each incident corresponds to, if any
    planted_for = {}
    for p in PLANTED:
        start, end = p["start_min"], p["start_min"] + p["duration_min"]
        hit = next((i for i in incidents if p["service"] in i["services"]
                    and overlaps(i["start_min"], i["end_min"], start, end)),
                   None)
        planted_for[p["id"]] = hit

    templates = {int(r["template_id"]): r["template"]
                 for _, r in template_table.iterrows()}

    out_incidents = []
    for inc in incidents:
        causes = rank_causes(inc, data["deploys"])
        planted = next((p for p in PLANTED
                        if planted_for[p["id"]] is inc), None)

        lo = max(0, inc["start_min"] - CHART_LEAD_MIN)
        if planted:
            lo = max(0, min(lo, planted["start_min"] - 30))
        hi = min(MINUTES - 1, inc["end_min"] + CHART_TAIL_MIN)

        charts, seen = [], set()
        for s in inc["signals"]:
            key = (s["service"], s["signal"])
            if s["signal_type"] != "metric" or key in seen:
                continue
            seen.add(key)
            runs = [[x["start_min"], x["end_min"]] for x in inc["signals"]
                    if x["signal_type"] == "metric"
                    and (x["service"], x["signal"]) == key]
            peak = max((abs(x["peak_z"]) for x in inc["signals"]
                        if x["signal_type"] == "metric"
                        and (x["service"], x["signal"]) == key))
            charts.append({
                "service": s["service"], "metric": s["signal"],
                "from": lo, "peak_z": round(peak, 1), "runs": runs,
                "values": [float(f"{v:.4g}") for v in series[key][lo:hi + 1]],
            })
        charts = charts[:MAX_CHARTS]

        deploy_marks = [{"minute": d["minute"],
                         "label": f"{d['version']} to {d['service']}"}
                        for d in data["deploys"] if lo <= d["minute"] <= hi
                        and d["service"] in inc["services"]]

        new_lines = []
        for s in inc["signals"]:
            if str(s.get("signal", "")).startswith("new_template:"):
                new_lines.append({"service": s["service"],
                                  "text": templates.get(s["template_id"], ""),
                                  "first": s["start_min"],
                                  "peak": s.get("peak_count")})

        out_incidents.append({
            "id": inc["incident_id"],
            "start": inc["start_min"], "end": inc["end_min"],
            "services": inc["services"],
            "first_service": inc["first_service"],
            "first_signal": inc["first_signal"],
            "severity": inc["severity"],
            "planted": planted["id"] if planted else None,
            "planted_start": planted["start_min"] if planted else None,
            "alerts": [{"minute": a["start_min"], "rule": a["signal"],
                        "severity": a["severity"]} for a in inc["alerts"]],
            "timeline": [{"minute": r["minute"], "service": r["service"],
                          "event": r["event"],
                          "kind": r["evidence"]["signal_type"]}
                         for r in timeline(inc)],
            "causes": [{"label": c["label"], "type": c["type"],
                        "service": c["service"], "score": c["score"],
                        "confidence": c["confidence"],
                        "components": [[k, v] for k, v in sorted(
                            c["components"].items(), key=lambda kv: -kv[1])],
                        "evidence": c["evidence"]} for c in causes],
            "similar": similar[inc["incident_id"]],
            "charts": charts, "deploys": deploy_marks,
            "new_lines": new_lines,
        })

    checks = []
    for p in PLANTED:
        inc = planted_for[p["id"]]
        row = {"id": p["id"], "service": p["service"], "real": p["real"],
               "start": p["start_min"], "duration": p["duration_min"],
               "notes": p["notes"], "incident": inc["incident_id"] if inc else None}
        own_alerts = [a["minute"] - p["start_min"] for a in data["alerts"]
                      if a["service"] == p["service"]
                      and 0 <= a["minute"] - p["start_min"]
                      <= p["duration_min"] + 30
                      and not a["rule"].startswith("disk_usage")]
        row["alert_delay"] = min(own_alerts) if own_alerts else None
        if p["real"] and inc:
            top = rank_causes(inc, data["deploys"])[0]
            row["detect_delay"] = inc["first_anomaly_min"] - p["start_min"]
            row["ranked"] = f"{top['type']}/{top['service']}"
            row["wanted"] = f"{p['cause']['type']}/{p['cause']['service']}"
            row["cause_correct"] = row["ranked"] == row["wanted"]
        checks.append(row)

    repeat = next((p for p in PLANTED if p.get("repeat_of")), None)
    repeat_link = None
    if repeat and planted_for[repeat["id"]] and planted_for[repeat["repeat_of"]]:
        later = planted_for[repeat["id"]]
        first = planted_for[repeat["repeat_of"]]
        hit = next((m for m in similar[later["incident_id"]]
                    if m["incident_id"] == first["incident_id"]), None)
        if hit:
            repeat_link = {"later": later["incident_id"],
                           "first": first["incident_id"],
                           "similarity": hit["similarity"]}

    baselines = []
    for p in real_planted():
        baselines.append({"id": p["id"], "duration": p["duration_min"],
                          "reference": coverage(by_strategy["reference"], p),
                          "trailing": coverage(by_strategy["trailing"], p)})

    why = Counter()
    for r in rejected:
        for s in r["signals"]:
            why[f"{s['service']} / {s['signal']}"] += 1

    early = set(logs[logs["minute"] < REFERENCE_HOURS * 60]["template_id"])
    template_rows = [{"id": int(r["template_id"]), "text": r["template"],
                      "count": int(r["count"]),
                      "new": int(r["template_id"]) not in early}
                     for _, r in template_table.iterrows()]

    real_found = sum(1 for c in checks if c["real"] and c["incident"])
    return {
        "start": START.isoformat(),
        "minutes": MINUTES,
        "reference_hours": REFERENCE_HOURS,
        "inputs": {"metric_points": int(len(metrics)),
                   "log_lines": int(len(logs)),
                   "deploys": len(data["deploys"]),
                   "alerts": len(data["alerts"]),
                   "services": len(DEPENDENCIES),
                   "templates": len(template_table)},
        "counts": {"metric_anomalies": len(metric_anoms),
                   "log_anomalies": len(log_anoms),
                   "incidents": len(incidents),
                   "rejected": len(rejected),
                   "real_planted": len(real_planted()),
                   "real_found": real_found,
                   "false_incidents": len(incidents) - real_found},
        "dependencies": DEPENDENCIES,
        "incidents": out_incidents,
        "checks": checks,
        "repeat_link": repeat_link,
        "baselines": baselines,
        "rejected_sources": why.most_common(),
        "rejected_marks": [{"minute": r["start_min"],
                            "alert_only": r["reason"].startswith("alert")}
                           for r in rejected],
        "alerts": [{"minute": a["minute"], "service": a["service"],
                    "rule": a["rule"]} for a in data["alerts"]],
        "deploys": [{"minute": d["minute"], "service": d["service"],
                     "version": d["version"]} for d in data["deploys"]],
        "templates": template_rows,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", default="data")
    ap.add_argument("--out", default="docs")
    args = ap.parse_args()

    if not os.path.exists(os.path.join(args.data, "metrics.csv")):
        sys.exit(f"No data in {args.data}/. Run: py scripts/make_sample_data.py")

    print("Running the pipeline...")
    payload = build(args.data)
    with open(os.path.join(HERE, "web", "page.html"), encoding="utf-8") as fh:
        page = fh.read()
    blob = json.dumps(payload, separators=(",", ":")).replace("</", "<\\/")
    page = page.replace("/*__DATA__*/null", blob)

    os.makedirs(args.out, exist_ok=True)
    full = ("<!doctype html>\n<html lang=\"en\">\n<head>\n"
            "<meta charset=\"utf-8\">\n<meta name=\"viewport\" "
            "content=\"width=device-width, initial-scale=1\">\n"
            "<style>body{margin:0}[hidden]{display:none!important}</style>\n"
            "</head>\n<body>\n" + page + "\n</body>\n</html>\n")
    target = os.path.join(args.out, "index.html")
    with open(target, "w", encoding="utf-8") as fh:
        fh.write(full)
    print(f"  {payload['counts']['incidents']} incidents, "
          f"{payload['counts']['rejected']} rejected clusters")
    print(f"  wrote {target}  ({os.path.getsize(target) / 1024:.0f} KB)")


if __name__ == "__main__":
    main()
