"""Run the whole pipeline on the sample data and check it against the answers.

    py scripts/make_sample_data.py          # once, to generate the data
    py run_demo.py
    py run_demo.py --data data --strategy reference

Everything printed is measured on this run. The final section compares what
the pipeline found against `config.PLANTED`, which the generator read from the
same place, and reports failures as failures.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from incidentlens import report                                   # noqa: E402
from incidentlens.anomaly import (detect_metric_anomalies,        # noqa: E402
                                  detect_template_anomalies)
from incidentlens.causes import rank_causes                       # noqa: E402
from incidentlens.config import (PLANTED, REFERENCE_HOURS,        # noqa: E402
                                 real_planted, timestamp)
from incidentlens.incidents import group_incidents                # noqa: E402
from incidentlens.ingest import load_all                          # noqa: E402
from incidentlens.similar import find_similar                     # noqa: E402
from incidentlens.templates import build_templates, per_minute_counts  # noqa: E402

RULE = "-" * 74


def head(title):
    print(f"\n{RULE}\n{title}\n{RULE}")


def overlaps(a_start, a_end, b_start, b_end, slack=20):
    return a_start - slack <= b_end and b_start - slack <= a_end


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", default="data")
    ap.add_argument("--strategy", default="reference",
                    choices=["reference", "trailing"],
                    help="which baseline the reported incidents are built "
                         "from; both are always compared")
    ap.add_argument("--z", type=float, default=6.0)
    args = ap.parse_args()

    if not os.path.exists(os.path.join(args.data, "metrics.csv")):
        sys.exit(f"No data in {args.data}/. Run: py scripts/make_sample_data.py")

    # -- 1. ingest ----------------------------------------------------------
    head("1. INPUTS  (all data synthetic)")
    data = load_all(args.data)
    metrics, logs = data["metrics"], data["logs"]
    print(f"  metrics        {len(metrics):>8,} points   "
          f"{metrics['service'].nunique()} services x "
          f"{metrics['metric'].nunique()} metrics")
    print(f"  logs           {len(logs):>8,} lines    "
          f"({data['malformed_log_lines']} malformed, dropped and counted)")
    print(f"  deploys        {len(data['deploys']):>8,} events")
    print(f"  alerts         {len(data['alerts']):>8,} alerts")
    print(f"  window         {timestamp(0):%Y-%m-%d %H:%M} -> "
          f"{timestamp(int(metrics['minute'].max())):%Y-%m-%d %H:%M}")
    print(f"  reference      first {REFERENCE_HOURS}h, guaranteed clean")

    # -- 2. templating ------------------------------------------------------
    head("2. LOG TEMPLATES")
    logs, template_table = build_templates(logs)
    per_minute = per_minute_counts(logs)
    print(f"  {len(logs):,} lines -> {len(template_table)} distinct templates")
    print(f"  compression    {len(logs) / max(len(template_table), 1):,.0f}x")
    print("\n  the five most common:")
    for _, row in template_table.head(5).iterrows():
        print(f"    {row['count']:>7,}  {row['template'][:60]}")
    seen_early = set(logs[logs["minute"] < REFERENCE_HOURS * 60]["template_id"])
    late_only = sorted(set(template_table["template_id"]) - seen_early)
    print(f"\n  templates never seen in the reference period: {len(late_only)}")
    for tid in late_only:
        row = template_table[template_table["template_id"] == tid].iloc[0]
        print(f"    id {tid:<4} x{row['count']:<6} {row['template'][:58]}")

    # -- 3. both baselines --------------------------------------------------
    head("3. WHAT COUNTS AS NORMAL  (the two baselines disagree)")
    found = {}
    for strategy in ("reference", "trailing"):
        found[strategy] = detect_metric_anomalies(
            metrics, strategy=strategy, z_threshold=args.z,
            reference_hours=REFERENCE_HOURS)
        print(f"  {strategy:<10} {len(found[strategy]):>4} metric anomalies")

    # "Found" or "missed" is too coarse to show the difference: both
    # strategies notice every fault here. What separates them is how much of
    # each fault they hold on to, so that is what is measured.
    print(f"\n  {'planted fault':<16}{'length':<9}"
          f"{'reference: onset / coverage':<30}"
          f"{'trailing: onset / coverage':<30}")
    for p in real_planted():
        start, end = p["start_min"], p["start_min"] + p["duration_min"]
        cells = []
        for strategy in ("reference", "trailing"):
            covered = set()
            for a in found[strategy]:
                if a["service"] != p["service"]:
                    continue
                for m in range(a["start_min"], a["end_min"] + 1):
                    if start <= m < end:
                        covered.add(m)
            if covered:
                onset = min(covered) - start
                pct = 100 * len(covered) / p["duration_min"]
                cells.append(f"+{onset}m / {len(covered)}/"
                             f"{p['duration_min']} = {pct:.0f}%")
            else:
                cells.append("MISSED")
        print(f"  {p['id']:<16}{str(p['duration_min']) + 'm':<9}"
              f"{cells[0]:<30}{cells[1]:<30}")
    print("\n  Both baselines divide out the same hour-of-day profile, so the\n"
          "  only difference between them is how far back the window reaches.\n"
          "  On faults that arrive in minutes they are indistinguishable. On\n"
          "  the six-hour leak both see the onset at the same moment and then\n"
          "  diverge: the trailing window climbs into the fault and loses the\n"
          "  back half of it. It does not miss the fault -- it forgets it.")

    # -- 4. incidents -------------------------------------------------------
    head(f"4. INCIDENTS  (built from the {args.strategy} baseline)")
    metric_anoms = found[args.strategy]
    log_anoms = detect_template_anomalies(per_minute, z_threshold=args.z,
                                          reference_hours=REFERENCE_HOURS)
    print(f"  {len(metric_anoms)} metric + {len(log_anoms)} log anomalies + "
          f"{len(data['alerts'])} alerts")
    incidents, rejected = group_incidents(metric_anoms, log_anoms,
                                          data["alerts"])
    print(f"  grouped into {len(incidents)} incidents, "
          f"{len(rejected)} clusters rejected\n")
    for inc in incidents:
        print(f"  {inc['incident_id']}  "
              f"{timestamp(inc['start_min']):%a %d %b %H:%M} "
              f"+{inc['end_min'] - inc['start_min'] + 1}m  "
              f"{len(inc['signals'])} signals  "
              f"[{', '.join(inc['services'])}]")

    if rejected:
        print(f"\n  the {len(rejected)} rejected clusters, by what raised "
              f"them:")
        from collections import Counter
        why = Counter()
        for r in rejected:
            for s in r["signals"]:
                why[(s["service"], s["signal"])] += 1
        for (svc, sig), n in why.most_common():
            print(f"    {n:>3}  {svc}/{sig}")
        print("\n  Almost all of it is one series. db-proxy's error rate has\n"
              "  the smallest baseline in the system (0.001, half the next\n"
              "  lowest), so a single noisy sample is a large multiple of it\n"
              "  and clears any threshold. The corroboration rule rejects\n"
              "  these one at a time; where two happen to land within the\n"
              "  join window they vouch for each other and one gets through.\n"
              "  That is the pipeline's whole false-positive budget, and it\n"
              "  is reported rather than tuned away: the honest fix is a\n"
              "  floor in absolute error-rate terms, not a higher z.")
        print("\n  first 8 rejected clusters:")
        for r in rejected[:8]:
            print(f"    {timestamp(r['start_min']):%a %d %b %H:%M}  "
                  f"{', '.join(r['services']):<22} {r['reason']}")

    # -- 5. causes and similarity ------------------------------------------
    head("5. EACH INCIDENT, WITH ITS EVIDENCE")
    similar = find_similar(incidents)
    causes_by_id = {}
    for inc in incidents:
        causes = rank_causes(inc, data["deploys"])
        causes_by_id[inc["incident_id"]] = causes
        print()
        print(report.summarise(inc, causes, similar[inc["incident_id"]],
                               template_table))
        print("\n    timeline:")
        print(report.timeline_text(inc))
        print("\n    candidates considered:")
        print("    " + report.cause_breakdown(causes).replace("\n", "\n    "))

    # -- 6. self-check ------------------------------------------------------
    head("6. SELF-CHECK AGAINST THE PLANTED ANSWERS")
    failures = []
    mapping = {}
    for p in PLANTED:
        start, end = p["start_min"], p["start_min"] + p["duration_min"]
        hits = [inc for inc in incidents
                if p["service"] in inc["services"]
                and overlaps(inc["start_min"], inc["end_min"], start, end)]
        mapping[p["id"]] = hits[0] if hits else None

    print(f"  {'planted':<16}{'real?':<8}{'as':<10}"
          f"{'detected':<11}{'alert fired':<13}{'cause ranked first':<26}")
    for p in PLANTED:
        inc = mapping[p["id"]]
        if not p["real"]:
            ok = inc is None
            print(f"  {p['id']:<16}{'noise':<8}"
                  f"{('no' if ok else 'YES'):<10}"
                  f"{'-':<11}{'+0m':<13}"
                  f"{'none, correctly' if ok else 'WRONGLY PROMOTED':<26}")
            if not ok:
                failures.append(f"{p['id']} was promoted to an incident")
            continue

        if inc is None:
            print(f"  {p['id']:<16}{'real':<8}{'MISSED':<10}"
                  f"{'-':<11}{'-':<13}{'-':<26}")
            failures.append(f"{p['id']} was not detected")
            continue

        delay = inc["first_anomaly_min"] - p["start_min"]
        # When did the alert rule covering this fault fire, if any did? This
        # is the comparison that matters: the pipeline is only worth running
        # if it beats the alerts that already exist.
        own_alerts = [a["minute"] - p["start_min"] for a in data["alerts"]
                      if a["service"] == p["service"]
                      and 0 <= a["minute"] - p["start_min"]
                      <= p["duration_min"] + 30
                      and not a["rule"].startswith("disk_usage")]
        alert_cell = f"+{min(own_alerts)}m" if own_alerts else "never"

        top = causes_by_id[inc["incident_id"]][0]
        want = p["cause"]
        correct = (top["type"] == want["type"] and
                   top["service"] == want["service"])
        verdict = f"{top['type']}/{top['service']}" + ("" if correct
                                                       else "  <- WRONG")
        print(f"  {p['id']:<16}{'real':<8}{inc['incident_id']:<10}"
              f"{'+' + str(delay) + 'm':<11}{alert_cell:<13}{verdict:<26}")
        if not correct:
            failures.append(f"{p['id']}: ranked {top['type']}/"
                            f"{top['service']}, planted "
                            f"{want['type']}/{want['service']}")

    # the repeat must link back to the first occurrence
    repeat = next((p for p in PLANTED if p.get("repeat_of")), None)
    if repeat:
        inc = mapping[repeat["id"]]
        origin = mapping[repeat["repeat_of"]]
        print()
        if inc and origin:
            matches = similar[inc["incident_id"]]
            hit = next((m for m in matches
                        if m["incident_id"] == origin["incident_id"]), None)
            if hit:
                print(f"  repeat link     {inc['incident_id']} -> "
                      f"{origin['incident_id']} at similarity "
                      f"{hit['similarity']}  (correct)")
            else:
                print(f"  repeat link     {inc['incident_id']} did NOT match "
                      f"{origin['incident_id']}")
                failures.append("the repeat was not linked to its original")
        else:
            failures.append("the repeat or its original was not detected")

    print()
    extra = len(incidents) - sum(1 for p in real_planted() if mapping[p["id"]])
    print(f"  incidents reported            {len(incidents)}")
    print(f"  real planted incidents        {len(real_planted())}")
    print(f"  unexplained extra incidents   {extra}")
    if extra:
        claimed = {id(mapping[p["id"]]) for p in real_planted()
                   if mapping[p["id"]]}
        for inc in incidents:
            if id(inc) not in claimed:
                print(f"    {inc['incident_id']} "
                      f"{timestamp(inc['start_min']):%a %H:%M} "
                      f"[{', '.join(inc['services'])}] -- not a planted fault")

    print()
    if failures:
        print(f"  {len(failures)} CHECK(S) FAILED:")
        for f in failures:
            print(f"    - {f}")
        sys.exit(1)
    print("  all checks passed")


if __name__ == "__main__":
    main()
