"""Find points that are far from normal, and be explicit about what normal means.

The score is a robust z-score: instead of a mean and a standard deviation,
it uses a median and a median absolute deviation, scaled by 0.6745 so the
number is comparable to a conventional z. The reason is that a mean and a
standard deviation are computed from the data being judged, so a large
anomaly inflates the very spread it is measured against and partly hides
itself. A median barely moves.

The harder question is which window "normal" comes from, and this module
computes two answers because they disagree on one of the planted incidents.

  trailing   median and MAD over the previous few hours, skipping the most
             recent half hour so a developing fault does not calibrate its
             own baseline. This is what a monitoring system usually does. It
             adapts to legitimate change, which is exactly why it adapts to
             a slow fault as well and loses sight of it.

  reference  median and MAD per hour of day, taken from the first 24 hours,
             which the generator guarantees are clean. The baseline cannot
             drift because it never updates. Computed per hour of day rather
             than as one number because daytime traffic is heavier than
             night traffic, and a flat baseline would flag every lunchtime.

What the two actually do on the sample data, measured rather than assumed:
on the three faults that arrive in minutes they are indistinguishable, both
flagging every minute of the fault. On the memory leak, which grows over six
hours, both notice the onset at the same moment (+74 minutes, once the climb
clears the threshold), but the reference baseline then holds 79% of the
fault's minutes while the trailing baseline holds 51%. The trailing window
climbs into the fault and loses the back half of it.

That is weaker than the claim this module was first written to make -- that
a trailing baseline would miss the leak entirely. It does not. It sees the
edge and then forgets. Neither strategy is correct in general, which is the
finding rather than a defect, and run_demo.py measures both.

Log templates get a separate rule. A template absent from the reference
period has a baseline of zero with zero spread, and a z-score built on that
is arithmetic rather than evidence. A sentence the system has never logged
before is decisive on its own and needs no statistics.
"""
from collections import defaultdict

import numpy as np
import pandas as pd

MAD_TO_SIGMA = 0.6745
DEFAULT_Z = 6.0


def robust_stats(values, floor_fraction=0.02, floor_abs=0.0):
    """Median and a spread that is never zero.

    A perfectly constant series would otherwise divide by zero and call every
    later wobble infinitely anomalous. The floor is a fraction of the median,
    so a constant 40% memory reading tolerates a little noise before it
    counts as surprising.

    `floor_abs` exists for counts, where a proportional floor is the wrong
    idea. Most per-minute log template counts have a median of zero, so a
    fractional floor collapses to nothing and a single extra line scores in
    the billions -- which is what the first version of this module did, and
    it is why that version reported a thousand log anomalies a day. For
    counted things the smallest meaningful difference is one whole item, so
    callers pass floor_abs=1.0 and get a spread that cannot go below it.
    """
    values = np.asarray(values, dtype=float)
    if values.size == 0:
        return 0.0, max(1.0, floor_abs)
    median = float(np.median(values))
    mad = float(np.median(np.abs(values - median)))
    floor = max(abs(median) * floor_fraction, floor_abs, 1e-9)
    return median, max(mad, floor)


def robust_z(value, median, mad):
    return MAD_TO_SIGMA * (value - median) / mad


def _runs(minutes, max_gap=3):
    """Contiguous stretches of flagged minutes, tolerating short gaps.

    A fault rarely trips a threshold on every single minute; without this,
    one incident becomes forty one-minute anomalies.
    """
    if not minutes:
        return []
    minutes = sorted(minutes)
    runs, start, prev = [], minutes[0], minutes[0]
    for m in minutes[1:]:
        if m - prev <= max_gap:
            prev = m
            continue
        runs.append((start, prev))
        start = prev = m
    runs.append((start, prev))
    return runs


# ---------------------------------------------------------------------------
# Metric anomalies
# ---------------------------------------------------------------------------
def _series_by_key(metrics):
    out = {}
    for (service, metric), group in metrics.groupby(["service", "metric"]):
        group = group.sort_values("minute")
        out[(service, metric)] = (group["minute"].to_numpy(),
                                  group["value"].to_numpy(dtype=float))
    return out


def seasonal_profile(minutes, values, ref_cutoff):
    """How much each hour of day differs from the daily average, learned from
    the reference period.

    Daytime traffic here is roughly twice night traffic. Without dividing
    that out, a trailing baseline whose window sits mostly in the night
    declares every morning a crisis -- which is what the first version of
    this module did, producing 480 anomalies, nearly all of them at 06:30.

    Both strategies use this, so the only thing that differs between them is
    how far back their window reaches. Otherwise the comparison would be
    between a reasonable method and a broken one, which proves nothing.
    """
    ref = [(int(m), float(v)) for m, v in zip(minutes, values) if m < ref_cutoff]
    if not ref:
        return {h: 1.0 for h in range(24)}
    overall = float(np.median([v for _, v in ref])) or 1.0
    by_hour = defaultdict(list)
    for m, v in ref:
        by_hour[(m // 60) % 24].append(v)
    profile = {}
    for h in range(24):
        vals = by_hour.get(h)
        profile[h] = (float(np.median(vals)) / overall) if vals else 1.0
        if profile[h] <= 0:
            profile[h] = 1.0
    return profile


def detect_metric_anomalies(metrics, strategy="reference", z_threshold=DEFAULT_Z,
                            reference_hours=24, trail_minutes=360,
                            trail_gap=30, directions=None):
    """Anomalies in the metric streams.

    `directions` says which way is bad per metric. Latency, error rate, CPU
    and memory are all only interesting when they rise; flagging a drop in
    error rate as an anomaly would bury the real ones.

    Both strategies first divide out the hour-of-day profile, then differ
    only in the window their median and MAD come from:

      reference  the whole clean first day
      trailing   the previous `trail_minutes`, skipping `trail_gap`

    A trailing window cannot see a fault that develops more slowly than the
    window is long, because the baseline rises with the fault. That is not a
    bug to be tuned away; it is a property of the method, and the point of
    running both.
    """
    directions = directions or {
        "latency_ms": "up", "error_rate": "up",
        "cpu_pct": "up", "memory_pct": "up",
    }
    series = _series_by_key(metrics)
    ref_cutoff = reference_hours * 60
    found = []

    for (service, metric), (minutes, values) in series.items():
        direction = directions.get(metric, "both")
        profile = seasonal_profile(minutes, values, ref_cutoff)
        # deseasonalised series: what the value would be at an average hour
        adjusted = np.array([v / profile[(int(m) // 60) % 24]
                             for m, v in zip(minutes, values)], dtype=float)
        flagged, zs = [], {}

        if strategy == "reference":
            med, mad = robust_stats(adjusted[minutes < ref_cutoff])
            for m, v in zip(minutes, adjusted):
                if m < ref_cutoff:
                    continue           # never judge the reference period
                z = robust_z(v, med, mad)
                if (direction == "up" and z > z_threshold) or \
                   (direction == "both" and abs(z) > z_threshold):
                    flagged.append(int(m))
                    zs[int(m)] = float(z)

        elif strategy == "trailing":
            s = pd.Series(adjusted, index=minutes.astype(int)).sort_index()
            shifted = s.shift(trail_gap)
            med_s = shifted.rolling(trail_minutes, min_periods=60).median()
            mad_s = ((s - med_s).abs().shift(trail_gap)
                     .rolling(trail_minutes, min_periods=60).median())
            for m in s.index:
                med, mad = med_s.get(m), mad_s.get(m)
                if med is None or mad is None or not np.isfinite(med) \
                        or not np.isfinite(mad):
                    continue
                mad = max(float(mad), abs(float(med)) * 0.02, 1e-9)
                z = robust_z(float(s[m]), float(med), mad)
                if (direction == "up" and z > z_threshold) or \
                   (direction == "both" and abs(z) > z_threshold):
                    flagged.append(int(m))
                    zs[int(m)] = float(z)
        else:
            raise ValueError(f"unknown strategy {strategy!r}")

        for start, end in _runs(flagged):
            inside = [m for m in flagged if start <= m <= end]
            peak = max(inside, key=lambda m: abs(zs[m]))
            found.append({
                "kind": "metric",
                "service": service,
                "signal": metric,
                "start_min": start,
                "end_min": end,
                "peak_min": peak,
                "peak_z": round(zs[peak], 2),
                "severity": _severity(zs[peak], end - start + 1),
                "strategy": strategy,
            })
    return sorted(found, key=lambda a: (a["start_min"], a["service"]))


# ---------------------------------------------------------------------------
# Log template anomalies
# ---------------------------------------------------------------------------
# A log template is allowed a longer gap than a metric before its run is
# broken in two. Metrics are sampled every minute, so a real fault moves them
# every minute; a fault's log line appears only when the code path runs. The
# memory leak here emits a warning every seventh minute, and at a 3-minute
# tolerance that one fault became 24 separate anomalies.
LOG_RUN_GAP = 10


def detect_template_anomalies(per_minute, z_threshold=DEFAULT_Z,
                              reference_hours=24, min_new_count=5,
                              total_minutes=None, run_gap=LOG_RUN_GAP):
    """Spiking known templates, and templates that are new entirely.

    The two are reported with different `signal` values because they are
    different kinds of evidence. A spike says a known problem got worse; a
    new template says the system started saying something it has never said.

    Two corrections here exist because the first version of this function was
    wrong in ways that produced confident nonsense:

    Counts are judged against the same hour of day in the reference period,
    not against the reference period as a whole. Log volume here follows
    traffic, so a template that appears twice a minute at 03:00 and six times
    a minute at 14:00 is behaving normally. Scoring against a single
    round-the-clock median turned every working day into an incident: 5,430
    log anomalies and six incidents, each running 06:00 to 22:00.

    Minutes in which a template did not appear are counted as zero rather
    than left out. `per_minute` only holds rows for minutes a template
    actually occurred, so taking a median over those rows alone measures the
    median of a template's busy minutes -- which, for anything sparse, sits
    well above its real median and makes ordinary activity look like a spike.
    """
    ref_cutoff = reference_hours * 60
    if total_minutes is None:
        total_minutes = int(per_minute["minute"].max()) + 1
    found = []

    for (service, template_id), group in per_minute.groupby(["service",
                                                             "template_id"]):
        group = group.sort_values("minute")
        observed = dict(zip(group["minute"].astype(int),
                            group["count"].astype(float)))
        minutes = np.arange(total_minutes)
        counts = np.array([observed.get(int(m), 0.0) for m in minutes])

        ref_mask = minutes < ref_cutoff
        seen_in_reference = bool(counts[ref_mask].sum() > 0)

        if not seen_in_reference:
            # Never logged during the clean period. No statistics needed.
            after = [(int(m), float(c)) for m, c in zip(minutes, counts)
                     if m >= ref_cutoff]
            total = sum(c for _, c in after)
            if total < min_new_count:
                continue               # one stray line is not an incident
            flagged = [m for m, c in after if c > 0]
            for start, end in _runs(flagged, max_gap=run_gap):
                inside = [(m, c) for m, c in after if start <= m <= end]
                peak_min, peak_count = max(inside, key=lambda mc: mc[1])
                found.append({
                    "kind": "log",
                    "service": service,
                    "signal": f"new_template:{int(template_id)}",
                    "template_id": int(template_id),
                    "start_min": start,
                    "end_min": end,
                    "peak_min": int(peak_min),
                    "peak_count": int(peak_count),
                    "peak_z": None,
                    "severity": "high",
                    "strategy": "new_template",
                })
            continue

        # Known template: judge each minute against the same hour of day in
        # the reference period.
        by_hour = {}
        for m, c in zip(minutes[ref_mask], counts[ref_mask]):
            by_hour.setdefault((int(m) // 60) % 24, []).append(c)
        hour_stats = {h: robust_stats(vals, floor_fraction=0.25,
                                      floor_abs=1.0)
                      for h, vals in by_hour.items()}
        fallback = robust_stats(counts[ref_mask], floor_fraction=0.25,
                                floor_abs=1.0)

        flagged, zs = [], {}
        for m, c in zip(minutes, counts):
            if m < ref_cutoff:
                continue
            med, mad = hour_stats.get((int(m) // 60) % 24, fallback)
            # A count has to clear the hour's median by at least one whole
            # line as well as by the z threshold. Without this, a template
            # that fires 0 or 1 times a minute has a median of 0 and a
            # floored spread, so a single extra line scores arbitrarily high.
            if c < med + 2:
                continue
            z = robust_z(c, med, mad)
            if z > z_threshold:
                flagged.append(int(m))
                zs[int(m)] = float(z)
        for start, end in _runs(flagged, max_gap=run_gap):
            inside = [m for m in flagged if start <= m <= end]
            peak = max(inside, key=lambda m: zs[m])
            found.append({
                "kind": "log",
                "service": service,
                "signal": f"template_spike:{int(template_id)}",
                "template_id": int(template_id),
                "start_min": start,
                "end_min": end,
                "peak_min": peak,
                "peak_z": round(zs[peak], 2),
                "severity": _severity(zs[peak], end - start + 1),
                "strategy": "reference",
            })
    return sorted(found, key=lambda a: (a["start_min"], a["service"]))


def _severity(z, duration):
    z = abs(z or 0.0)
    if z > 20 or duration > 30:
        return "high"
    if z > 10 or duration > 10:
        return "medium"
    return "low"
