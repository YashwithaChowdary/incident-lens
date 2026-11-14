"""Rank candidate causes, and show the arithmetic.

A tool that prints "root cause: payments" is asking to be trusted. A tool
that prints the three candidates it considered, the score each got and which
component contributed what can be argued with, which is the only way anyone
finds out it is wrong. Every candidate here carries its component breakdown
and the evidence each component was derived from.

Two kinds of candidate are considered:

  deploy    a release that landed shortly before onset, on a service in the
            incident or one it depends on.
  service   a service that started first and sits upstream of the others,
            with no deploy to explain it -- a fault in the service itself.

The weights are set so that:

  * a deploy on the first-affected service, minutes before onset, outranks
    everything, because it explains why the fault started when it did;
  * a service that started first AND sits upstream of every other affected
    service outranks a deploy on a service that was merely collateral.

The weights are a judgement, not a result. They are stated here and
measured in run_demo.py against the planted causes rather than asserted to
be right.
"""
from .config import is_upstream_of, dependency_distance

DEPLOY_LOOKBACK_MIN = 60     # a release older than this is not an explanation
DEPLOY_GRACE_MIN = 5         # a deploy a few minutes after onset still counts


def _deploy_candidates(incident, deploys):
    out = []
    start = incident["start_min"]
    for d in deploys:
        age = start - d["minute"]
        if age > DEPLOY_LOOKBACK_MIN or age < -DEPLOY_GRACE_MIN:
            continue

        parts, evidence = {}, []
        svc = d["service"]
        if svc == incident["first_service"]:
            parts["deployed the service that failed first"] = 40
        elif svc in incident["services"]:
            parts["deployed a service in the incident"] = 25
        elif any(is_upstream_of(svc, s) for s in incident["services"]):
            parts["deployed a dependency of an affected service"] = 10
        else:
            continue                 # unrelated release, not a candidate

        if age <= 15:
            parts[f"landed {age} min before onset"] = 50
        elif age <= 45:
            parts[f"landed {age} min before onset"] = 20
        else:
            parts[f"landed {age} min before onset"] = 5

        evidence.append(f"deploy {d['version']} to {svc} by {d['author']} "
                        f"at {d['timestamp']:%Y-%m-%d %H:%M} "
                        f"(\"{d['commit_message']}\")")
        out.append({
            "type": "deploy",
            "service": svc,
            "label": f"deploy {d['version']} to {svc}",
            "components": parts,
            "score": sum(parts.values()),
            "evidence": evidence,
        })
    return out


def _service_candidates(incident):
    out = []
    services = incident["services"]
    metric_signals = [s for s in incident["signals"]
                      if s["signal_type"] in ("metric", "log")]
    peak = max((abs(s["peak_z"] or 0.0) for s in metric_signals), default=0.0)

    for svc in services:
        parts, evidence = {}, []
        own = [s for s in metric_signals if s["service"] == svc]
        if not own:
            continue                 # only alerted, never actually anomalous

        if svc == incident["first_service"]:
            earliest = min(s["start_min"] for s in own)
            parts["showed the first anomaly"] = 35
            evidence.append(f"first anomalous signal of the incident: "
                            f"{incident['first_signal']} on {svc} at "
                            f"minute {earliest}")

        others = [s for s in services if s != svc]
        downstream = [s for s in others if is_upstream_of(svc, s)]
        if others and downstream:
            share = len(downstream) / len(others)
            parts[f"upstream of {len(downstream)} of {len(others)} other "
                  f"affected services"] = round(25 * share)
            evidence.append(f"{svc} is called (directly or transitively) by "
                            f"{', '.join(sorted(downstream))}")

        if any(s["severity"] == "high" for s in own):
            parts["its own signals are severe or sustained"] = 10

        own_peak = max(abs(s["peak_z"] or 0.0) for s in own)
        if peak > 0:
            parts["share of the largest departure seen"] = round(
                10 * own_peak / peak)
        strongest = max(own, key=lambda s: abs(s["peak_z"] or 0.0))
        evidence.append(f"{strongest['signal']} on {svc} peaked at "
                        f"z={strongest['peak_z']} (minute "
                        f"{strongest['peak_min']})")

        out.append({
            "type": "service",
            "service": svc,
            "label": f"fault inside {svc}",
            "components": parts,
            "score": sum(parts.values()),
            "evidence": evidence,
        })
    return out


def rank_causes(incident, deploys):
    """Candidates, best first. Nothing is discarded: a weak candidate that
    was considered and scored low is information too."""
    candidates = _deploy_candidates(incident, deploys) + \
        _service_candidates(incident)
    candidates.sort(key=lambda c: (-c["score"], c["type"], c["service"]))

    top = candidates[0]["score"] if candidates else 0
    second = candidates[1]["score"] if len(candidates) > 1 else 0
    for c in candidates:
        c["confidence"] = _confidence(c["score"], top, second,
                                      c is candidates[0] if candidates else False)
    return candidates


def _confidence(score, top, second, is_top):
    """How much daylight there is between first and second place.

    A top candidate two points ahead of the runner-up is a coin toss
    reported as a conclusion, which is the failure mode worth guarding
    against.
    """
    if not is_top:
        return None
    margin = top - second
    if top >= 70 and margin >= 25:
        return "high"
    if top >= 50 and margin >= 10:
        return "medium"
    return "low -- the top two candidates are close; treat as a hypothesis"


def explain(candidate):
    """The score as a readable sum, so it can be checked by hand."""
    lines = [f"{candidate['label']}  score {candidate['score']}"]
    for name, value in sorted(candidate["components"].items(),
                              key=lambda kv: -kv[1]):
        lines.append(f"    +{value:<3} {name}")
    for ev in candidate["evidence"]:
        lines.append(f"     -> {ev}")
    return "\n".join(lines)
