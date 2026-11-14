"""Generate a synthetic week of production signals with known incidents.

ALL DATA PRODUCED HERE IS SYNTHETIC. The point is not realism for its own
sake: it is that every incident has a planted cause recorded in
`config.PLANTED`, so the pipeline's answers can be checked against something
rather than eyeballed.

Written as a separate step from the pipeline on purpose. A detector evaluated
on data whose faults it helped define proves nothing.

    py scripts/make_sample_data.py
    py scripts/make_sample_data.py --out data --seed 7
"""
import argparse
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from incidentlens.config import (  # noqa: E402
    BASELINES, DEPENDENCIES, METRICS, MINUTES, PLANTED, SERVICES, callers_of,
    timestamp,
)

# Routine log messages per service, with the variable parts that templating
# has to strip back out.
ROUTINE = [
    'handled request id={req} path=/v1/{path} status=200 in {ms}ms',
    'cache hit key=user:{uid} ttl={ttl}s',
    'db query took {ms}ms rows={rows}',
    'outbound call to {peer} ok in {ms}ms',
    'session refreshed for user {uid} from {ip}',
]
PATHS = ["orders", "items", "search", "profile", "checkout", "status"]

FAULT_TEMPLATES = {
    "bad_deploy": 'payment gateway timeout after {ms}ms req={req} retry={n}',
    "memory_leak": 'allocation slow: heap {pct}% used, gc pause {ms}ms',
    "db_slowdown": 'connection pool exhausted, waited {ms}ms for a slot',
}


def seasonal(minute_index):
    """Daytime traffic is heavier than night traffic.

    This matters more than it looks. A detector whose baseline ignores the
    daily cycle will flag every lunchtime peak, so the reference baseline in
    anomaly.py is computed per hour of day rather than as one number.
    """
    hour = (minute_index // 60) % 24
    if 8 <= hour < 18:
        return 1.25
    if 6 <= hour < 8 or 18 <= hour < 22:
        return 1.0
    return 0.65


def build_incident_effects():
    """A lookup of {(service, metric, minute): multiplier} for planted faults,
    plus the extra log lines each fault produces and the alerts it raises."""
    effects = {}
    extra_logs = []     # (minute, service, level, message_template, kind)
    alerts = []         # (minute, rule, service, severity)
    deploys = []        # (minute, service, version, author, message)

    def scale(service, metric, minute_index, factor):
        key = (service, metric, minute_index)
        effects[key] = effects.get(key, 1.0) * factor

    for p in PLANTED:
        start, dur, svc = p["start_min"], p["duration_min"], p["service"]

        if p["kind"] == "bad_deploy":
            # the deploy lands three minutes before anything goes wrong
            deploys.append((start - 3, svc, f"v{2 + PLANTED.index(p)}.4.0",
                            "r.lindqvist",
                            "retry payment confirmations more aggressively"))
            for m in range(start, start + dur):
                ramp = min(1.0, (m - start + 1) / 5.0)
                scale(svc, "error_rate", m, 1 + 11 * ramp)
                scale(svc, "latency_ms", m, 1 + 0.5 * ramp)
                # downstream: orders calls payments, gateway calls orders
                scale("orders", "error_rate", m, 1 + 1.4 * ramp)
                scale("gateway", "error_rate", m, 1 + 0.9 * ramp)
                if m % 2 == 0:
                    extra_logs.append((m, svc, "ERROR",
                                       FAULT_TEMPLATES["bad_deploy"],
                                       "bad_deploy"))
            alerts.append((start + 6, "error_rate_above_5pct", svc, "critical"))

        elif p["kind"] == "memory_leak":
            for m in range(start, start + dur):
                frac = (m - start) / dur
                # memory climbs from baseline towards 95%
                base = BASELINES[svc][3]
                target = base + (95.0 - base) * frac
                scale(svc, "memory_pct", m, target / base)
                # latency only follows in the last third, which is why a
                # latency-only detector would notice this four hours late
                if frac > 0.66:
                    scale(svc, "latency_ms", m, 1 + 1.8 * (frac - 0.66) / 0.34)
                if frac > 0.5 and m % 7 == 0:
                    extra_logs.append((m, svc, "WARN",
                                       FAULT_TEMPLATES["memory_leak"],
                                       "memory_leak"))
            alerts.append((start + int(dur * 0.8), "memory_above_90pct", svc,
                           "warning"))

        elif p["kind"] == "db_slowdown":
            for m in range(start, start + dur):
                ramp = min(1.0, (m - start + 1) / 4.0)
                scale(svc, "latency_ms", m, 1 + 5.0 * ramp)
                scale(svc, "cpu_pct", m, 1 + 0.4 * ramp)
                if m % 3 == 0:
                    extra_logs.append((m, svc, "ERROR",
                                       FAULT_TEMPLATES["db_slowdown"],
                                       "db_slowdown"))
                # the callers slow down a couple of minutes behind it
                for caller in callers_of(svc):
                    if m >= start + 2:
                        cramp = min(1.0, (m - start - 1) / 4.0)
                        scale(caller, "latency_ms", m, 1 + 1.6 * cramp)
            alerts.append((start + 4, "latency_p99_above_slo", svc, "critical"))

        elif p["kind"] == "noisy_alert":
            # an alert and nothing else: no metric moves, no logs change
            alerts.append((start, "synthetic_probe_flapped", svc, "warning"))

    # Benign deploys scattered through the week, so that "a deploy happened
    # recently" cannot by itself be the whole answer.
    rng = random.Random(99)
    for day in range(1, 7):
        for _ in range(2):
            svc = rng.choice(SERVICES)
            m = (day * 24 + rng.choice([9, 11, 13, 15])) * 60 + rng.randrange(60)
            if any(abs(m - p["start_min"]) < 120 and p["service"] == svc
                   for p in PLANTED):
                continue   # keep benign deploys clear of the planted windows
            deploys.append((m, svc, f"v1.{day}.{rng.randrange(9)}",
                            rng.choice(["a.berg", "m.sandell", "k.ohlsson"]),
                            rng.choice(["bump dependencies",
                                        "add index to lookup table",
                                        "tidy logging", "raise cache ttl"])))

    # Routine alerts that correspond to nothing, to keep the alert stream
    # from being a perfect oracle.
    for day in range(0, 7):
        alerts.append(((day * 24 + 4) * 60 + 20, "disk_usage_above_70pct",
                       rng.choice(SERVICES), "info"))

    return effects, extra_logs, alerts, deploys


def write_metrics(path, effects, rng):
    """One row per service, metric and minute."""
    rows = 0
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("timestamp,service,metric,value\n")
        for svc in SERVICES:
            base = dict(zip(METRICS, BASELINES[svc]))
            for m in range(MINUTES):
                season = seasonal(m)
                for metric in METRICS:
                    b = base[metric]
                    if metric in ("latency_ms", "error_rate"):
                        value = b * season
                    elif metric == "cpu_pct":
                        value = b * (0.85 + 0.3 * (season - 0.65))
                    else:                        # memory drifts very slowly
                        value = b * (1 + 0.0004 * (m / 1440.0))
                    value *= 1 + rng.gauss(0, 0.06)
                    value *= effects.get((svc, metric, m), 1.0)
                    if metric in ("cpu_pct", "memory_pct"):
                        value = min(value, 99.5)
                    value = max(value, 0.0)
                    fh.write(f"{timestamp(m).isoformat()},{svc},{metric},"
                             f"{value:.4f}\n")
                    rows += 1
    return rows


def write_logs(path, extra_logs, rng):
    """Routine traffic plus the extra lines the planted faults produce."""
    planted_by_minute = {}
    for m, svc, level, template, kind in extra_logs:
        planted_by_minute.setdefault(m, []).append((svc, level, template, kind))

    lines = 0
    with open(path, "w", encoding="utf-8") as fh:
        for m in range(MINUTES):
            season = seasonal(m)
            per_service = max(1, int(round(2 * season)))
            for svc in SERVICES:
                for _ in range(per_service):
                    msg = rng.choice(ROUTINE).format(
                        req=f"{rng.randrange(16**8):08x}",
                        path=rng.choice(PATHS),
                        ms=rng.randrange(3, 180),
                        uid=rng.randrange(1000, 99999),
                        ttl=rng.choice([30, 60, 300]),
                        rows=rng.randrange(1, 500),
                        peer=rng.choice(SERVICES),
                        ip=f"10.{rng.randrange(256)}.{rng.randrange(256)}."
                           f"{rng.randrange(256)}",
                        n=rng.randrange(1, 4),
                        pct=rng.randrange(30, 60),
                    )
                    level = "INFO" if rng.random() > 0.03 else "WARN"
                    fh.write(json.dumps({
                        "timestamp": timestamp(m).isoformat(),
                        "service": svc,
                        "level": level,
                        "message": msg,
                        "trace_id": f"{rng.randrange(16**16):016x}",
                    }) + "\n")
                    lines += 1
            for svc, level, template, _kind in planted_by_minute.get(m, []):
                # several lines per affected minute, so the template spikes
                for _ in range(rng.randrange(8, 20)):
                    fh.write(json.dumps({
                        "timestamp": timestamp(m).isoformat(),
                        "service": svc,
                        "level": level,
                        "message": template.format(
                            ms=rng.randrange(900, 9000),
                            req=f"{rng.randrange(16**8):08x}",
                            n=rng.randrange(1, 5),
                            pct=rng.randrange(88, 99),
                        ),
                        "trace_id": f"{rng.randrange(16**16):016x}",
                    }) + "\n")
                    lines += 1
    return lines


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="data")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    rng = random.Random(args.seed)
    effects, extra_logs, alerts, deploys = build_incident_effects()

    print("Generating synthetic signals (all data is synthetic)...")
    rows = write_metrics(os.path.join(args.out, "metrics.csv"), effects, rng)
    print(f"  metrics.csv   {rows:>8} rows")
    lines = write_logs(os.path.join(args.out, "logs.jsonl"), extra_logs, rng)
    print(f"  logs.jsonl    {lines:>8} lines")

    with open(os.path.join(args.out, "deploys.json"), "w", encoding="utf-8") as fh:
        json.dump([
            {"timestamp": timestamp(m).isoformat(), "service": svc,
             "version": ver, "author": author, "commit_message": msg}
            for m, svc, ver, author, msg in sorted(deploys)
        ], fh, indent=2)
    print(f"  deploys.json  {len(deploys):>8} events")

    with open(os.path.join(args.out, "alerts.json"), "w", encoding="utf-8") as fh:
        json.dump([
            {"timestamp": timestamp(m).isoformat(), "rule": rule,
             "service": svc, "severity": sev}
            for m, rule, svc, sev in sorted(alerts)
        ], fh, indent=2)
    print(f"  alerts.json   {len(alerts):>8} alerts")

    with open(os.path.join(args.out, "dependencies.yaml"), "w",
              encoding="utf-8") as fh:
        fh.write("# which service calls which (synthetic)\n")
        for svc in SERVICES:
            calls = DEPENDENCIES.get(svc, [])
            if calls:
                fh.write(f"{svc}:\n")
                for c in calls:
                    fh.write(f"  - {c}\n")
            else:
                fh.write(f"{svc}: []\n")

    with open(os.path.join(args.out, "ground_truth.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"synthetic": True, "planted": PLANTED}, fh, indent=2,
                  default=str)
    print(f"  ground_truth.json  {len(PLANTED)} planted "
          f"({sum(1 for p in PLANTED if p['real'])} real, "
          f"{sum(1 for p in PLANTED if not p['real'])} noise)")
    print(f"\nWritten to {args.out}/")


if __name__ == "__main__":
    main()
