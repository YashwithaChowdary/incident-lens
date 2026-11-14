"""Turn an incident into a readable summary in which every claim is cited.

The rule the whole module exists to enforce: no sentence appears here that is
not traceable to a metric point, a log template or a deploy record. Summaries
of this kind are easy to make fluent and dangerous when fluent, because a
confident sentence with nothing behind it is indistinguishable from one with
everything behind it until someone acts on it.

So each section is built from the evidence objects themselves, and anything
that cannot be sourced is left out rather than smoothed over.
"""
from .config import timestamp
from .causes import explain


def _clock(minute):
    return f"{timestamp(minute):%a %d %b %H:%M}"


def summarise(incident, causes, similar_matches, template_table=None):
    """A short written account of one incident."""
    lines = []
    dur = incident["end_min"] - incident["start_min"] + 1
    svcs = ", ".join(incident["services"])

    lines.append(f"{incident['incident_id']}  {_clock(incident['start_min'])} "
                 f"-> {_clock(incident['end_min'])}  ({dur} min)")
    lines.append(f"  services affected : {svcs}")
    lines.append(f"  started on        : {incident['first_service']} "
                 f"({incident['first_signal']})")

    if incident["alerts"]:
        fired = ", ".join(f"{a['signal']} @ {_clock(a['start_min'])}"
                          for a in incident["alerts"])
        lines.append(f"  alerts that fired : {fired}")
    else:
        lines.append("  alerts that fired : none -- this incident was not "
                     "covered by any alert rule")

    if causes:
        top = causes[0]
        lines.append(f"  most likely cause : {top['label']} "
                     f"(confidence: {top['confidence']})")
        for ev in top["evidence"]:
            lines.append(f"      evidence: {ev}")
        if len(causes) > 1:
            runner = causes[1]
            lines.append(f"  next best         : {runner['label']} "
                         f"(score {runner['score']} vs {top['score']})")
    else:
        lines.append("  most likely cause : no candidate scored above zero")

    if similar_matches:
        m = similar_matches[0]
        lines.append(f"  seen before       : {m['incident_id']} at "
                     f"{_clock(m['start_min'])}, symptom similarity "
                     f"{m['similarity']}")
        lines.append(f"      shared signals: "
                     f"{', '.join(m['shared_signals'][:6])}")
    else:
        lines.append("  seen before       : no earlier incident with a "
                     "similar symptom set")

    new_templates = [s for s in incident["signals"]
                     if str(s.get("signal", "")).startswith("new_template:")]
    if new_templates and template_table is not None:
        lines.append("  log lines the system had never emitted before:")
        for s in new_templates[:3]:
            tid = s["template_id"]
            row = template_table[template_table["template_id"] == tid]
            if not row.empty:
                text = row.iloc[0]["template"]
                lines.append(f"      [{s['service']}] {text}")
                lines.append(f"        first seen {_clock(s['start_min'])}, "
                             f"peak {s.get('peak_count')} lines/min")
    return "\n".join(lines)


def cause_breakdown(causes, limit=4):
    """Every candidate's arithmetic, so the ranking can be disputed."""
    return "\n".join(explain(c) for c in causes[:limit])


def timeline_text(incident, limit=12):
    from .incidents import timeline
    rows = timeline(incident)
    out = []
    for r in rows[:limit]:
        out.append(f"    {_clock(r['minute'])}  {r['service']:<10} "
                   f"{r['event']}")
    if len(rows) > limit:
        out.append(f"    ... {len(rows) - limit} further signals")
    return "\n".join(out)
