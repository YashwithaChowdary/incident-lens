"""Reduce log lines to templates, then count the templates per minute.

135,000 log lines in a week is nothing to a real system and still far too
many to look at. Almost all of them are the same handful of sentences with
different numbers in them:

    handled request id=4f1a9c33 path=/v1/orders status=200 in 42ms
    handled request id=90bb2e01 path=/v1/items  status=200 in 17ms

Masking the variable parts collapses both into one template. What makes that
worth doing is not the compression but what it exposes: a template nobody has
seen before, or a template whose rate suddenly multiplies, is a far stronger
signal than any single line. The fault lines planted in the sample data each
introduce a template that does not exist in healthy traffic, and that is how
they are found.

The masking order matters. IP addresses and UUIDs contain digits, so if plain
numbers were masked first the longer patterns would never match.
"""
import re
from collections import Counter, defaultdict

import pandas as pd

# Applied in order; earlier patterns win.
MASKS = [
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
                re.I), "<UUID>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<IP>"),
    (re.compile(r"\b[0-9a-f]{8,}\b", re.I), "<HEX>"),
    # A number glued to a unit: "56ms", "12.5s", "88%". This rule has to come
    # before the plain-number rule, and the plain-number rule cannot do the
    # job on its own, because \b requires a non-word character after the
    # digits and there is none between the 6 and the m of "56ms". Without
    # this, every distinct millisecond value becomes its own template: the
    # first run of this project produced 3,795 templates and 10,476 spurious
    # "never seen before" anomalies, which chained every service in the system
    # into one week-long incident. The unit is kept, since "took <NUM>ms" and
    # "took <NUM>rows" are not the same sentence.
    (re.compile(r"\b\d+(?:\.\d+)?(?=(?:ms|ns|us|s|m|h|d|kb|mb|gb|b|pct|%)\b)",
                re.I), "<NUM>"),
    (re.compile(r"\b\d+(?:\.\d+)?\b"), "<NUM>"),
]


def mask(message):
    """One log message reduced to its template."""
    out = message
    for pattern, token in MASKS:
        out = pattern.sub(token, out)
    return out


def build_templates(logs):
    """Add a `template` column and return (logs, template_table).

    `template_table` maps each template to an id, its total count and the
    services it appears on, which is what makes a template referenceable as
    evidence later.
    """
    logs = logs.copy()
    logs["template"] = logs["message"].map(mask)

    counts = Counter(logs["template"])
    services = defaultdict(set)
    for template, service in zip(logs["template"], logs["service"]):
        services[template].add(service)

    table = []
    for i, (template, count) in enumerate(
            sorted(counts.items(), key=lambda kv: -kv[1])):
        table.append({
            "template_id": i,
            "template": template,
            "count": count,
            "services": sorted(services[template]),
        })
    table = pd.DataFrame(table)
    ids = dict(zip(table["template"], table["template_id"]))
    logs["template_id"] = logs["template"].map(ids)
    return logs, table


def per_minute_counts(logs):
    """Counts of each (service, template) per minute, as a long table.

    Returned long rather than pivoted because the pivot for 135k lines across
    a week is mostly zeros, and the anomaly detector works series by series
    anyway.
    """
    grouped = (logs.groupby(["service", "template_id", "minute"])
                   .size()
                   .reset_index(name="count"))
    return grouped


def level_counts_per_minute(logs):
    """ERROR and WARN counts per service per minute.

    Kept separate from template counts because severity is a different
    question from novelty: a flood of a known ERROR template and a single
    unknown INFO template are both worth noticing, for different reasons.
    """
    errs = logs[logs["level"].isin(["ERROR", "WARN"])]
    return (errs.groupby(["service", "level", "minute"])
                .size()
                .reset_index(name="count"))
