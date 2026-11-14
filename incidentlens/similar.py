"""Decide whether an incident has happened before.

The question an on-call engineer actually asks at 03:00 is not "what is
broken" but "have we seen this, and what did we do last time". Matching on
the cause would be circular -- the cause is what is being worked out -- so
the match is on the shape of the symptoms:

    the set of (service, signal) pairs that went anomalous

Jaccard similarity over that set. Two bad deploys of the same service four
days apart produce nearly the same set and score high; a database slowdown
produces a different set and scores low against both.

The weakness is stated rather than hidden: this matches symptoms, so two
unrelated faults that happen to break the same services the same way will
look identical. That is a property of symptom matching and the reason the
match is reported as "similar", never as "same cause".
"""
SIMILARITY_FLOOR = 0.5       # below this, not worth surfacing


def fingerprint(incident):
    """The incident reduced to the set of things that went wrong.

    Alerts are left out on purpose. An alert reflects which rules someone
    configured, not what the system did, so including them would make two
    incidents look alike merely because the same alert rule covers both.
    """
    return frozenset(
        (s["service"], _generalise(s["signal"]))
        for s in incident["signals"]
        if s["signal_type"] in ("metric", "log")
    )


def _generalise(signal):
    """Collapse template ids so the same kind of log line matches itself.

    `new_template:57` and `new_template:91` are different ids for what may be
    the same sentence. The id is dropped and only the kind kept, otherwise no
    two incidents could ever match on their logs.
    """
    if signal.startswith("new_template:"):
        return "new_template"
    if signal.startswith("template_spike:"):
        return "template_spike"
    return signal


def jaccard(a, b):
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def find_similar(incidents, floor=SIMILARITY_FLOOR):
    """For each incident, earlier incidents that look like it.

    Only earlier ones: at 03:00 the question is what happened before now, and
    a system that matched forwards in time would be describing a luxury it
    does not have in production.
    """
    prints = {inc["incident_id"]: fingerprint(inc) for inc in incidents}
    out = {}
    for i, inc in enumerate(incidents):
        matches = []
        for earlier in incidents[:i]:
            score = jaccard(prints[inc["incident_id"]],
                            prints[earlier["incident_id"]])
            if score >= floor:
                shared = sorted(prints[inc["incident_id"]] &
                                prints[earlier["incident_id"]])
                matches.append({
                    "incident_id": earlier["incident_id"],
                    "similarity": round(score, 2),
                    "start_min": earlier["start_min"],
                    "shared_signals": [f"{svc}/{sig}" for svc, sig in shared],
                })
        matches.sort(key=lambda m: -m["similarity"])
        out[inc["incident_id"]] = matches
    return out
