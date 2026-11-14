"""The shape of the fictional system, and the incidents planted in it.

Everything here is synthetic. Nothing in this project touches a real
production system, and every number it reports is measured on data generated
by `scripts/make_sample_data.py`.

The planted incidents live here rather than in the generator so that the
generator and the self-check read from the same source. If the two disagreed,
a passing demo would prove nothing.
"""
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# The system: eight services and who calls whom.
#
# The dependency map is what lets the pipeline treat a database slowdown and
# the three services that slow down behind it as ONE incident instead of four.
# ---------------------------------------------------------------------------
SERVICES = [
    "gateway", "auth", "orders", "payments", "inventory",
    "search", "notify", "db-proxy",
]

# caller -> services it calls
DEPENDENCIES = {
    "gateway": ["auth", "orders", "search"],
    "orders": ["payments", "inventory", "notify"],
    "payments": ["db-proxy"],
    "inventory": ["db-proxy"],
    "search": ["db-proxy"],
    "auth": ["db-proxy"],
    "notify": [],
    "db-proxy": [],
}

METRICS = ["latency_ms", "error_rate", "cpu_pct", "memory_pct"]

# Healthy behaviour per service: (latency_ms, error_rate, cpu_pct, memory_pct)
BASELINES = {
    "gateway":   (45.0, 0.004, 32.0, 48.0),
    "auth":      (28.0, 0.002, 22.0, 41.0),
    "orders":    (72.0, 0.006, 38.0, 55.0),
    "payments":  (95.0, 0.005, 30.0, 52.0),
    "inventory": (60.0, 0.003, 27.0, 46.0),
    "search":    (120.0, 0.007, 44.0, 40.0),
    "notify":    (35.0, 0.009, 18.0, 36.0),
    "db-proxy":  (18.0, 0.001, 51.0, 62.0),
}

START = datetime(2026, 10, 5, 0, 0, 0)   # a Monday
DAYS = 7
MINUTES = DAYS * 24 * 60

# The first 24 hours are guaranteed clean. The detector uses them as its
# reference period, which is the same discipline as fitting an anomaly
# detector on healthy data only: a baseline learned from data containing the
# fault reports a number the deployed system could never reproduce.
REFERENCE_HOURS = 24


def minute(day, hour, mins=0):
    """Absolute minute index from the start of the capture."""
    return (day * 24 + hour) * 60 + mins


# ---------------------------------------------------------------------------
# Planted incidents. `kind` drives the generator; `cause` is the answer the
# root-cause ranking is supposed to arrive at.
#
# Note on counts: the brief asks for four planted incidents of which one is
# noise, and separately for a repeat of the deploy pattern. That gives FOUR
# real incidents to detect (three distinct patterns plus the repeat), not
# three. The brief's "exactly 3" and its "link the repeat" cannot both be
# true, so this project detects four and rejects the noise, and says so.
# ---------------------------------------------------------------------------
PLANTED = [
    {
        "id": "bad-deploy-1",
        "kind": "bad_deploy",
        "service": "payments",
        "start_min": minute(2, 10, 0),
        "duration_min": 42,
        "cause": {"type": "deploy", "service": "payments"},
        "real": True,
        "notes": "A deploy raises the error rate on payments; orders and "
                 "gateway see it downstream.",
    },
    {
        "id": "memory-leak",
        "kind": "memory_leak",
        "service": "search",
        "start_min": minute(3, 8, 0),
        "duration_min": 360,
        "cause": {"type": "service", "service": "search"},
        "real": True,
        "notes": "Memory climbs for six hours before latency follows. Slow "
                 "enough that a trailing baseline climbs with it and holds "
                 "only half the fault's minutes, against 79% for a fixed "
                 "reference baseline.",
    },
    {
        "id": "db-slowdown",
        "kind": "db_slowdown",
        "service": "db-proxy",
        "start_min": minute(5, 14, 0),
        "duration_min": 55,
        "cause": {"type": "service", "service": "db-proxy"},
        "real": True,
        "notes": "db-proxy latency jumps and spreads to its three callers. "
                 "One incident, not four.",
    },
    {
        "id": "noisy-alert",
        "kind": "noisy_alert",
        "service": "notify",
        "start_min": minute(6, 3, 0),
        "duration_min": 8,
        "cause": None,
        "real": False,
        "notes": "An alert fires with no metric anomaly and no log spike "
                 "behind it. Must NOT become an incident.",
    },
    {
        "id": "bad-deploy-2",
        "kind": "bad_deploy",
        "service": "payments",
        "start_min": minute(6, 16, 30),
        "duration_min": 38,
        "cause": {"type": "deploy", "service": "payments"},
        "real": True,
        "repeat_of": "bad-deploy-1",
        "notes": "The same pattern again, so similarity matching has "
                 "something true to find.",
    },
]


def planted_by_id(incident_id):
    for p in PLANTED:
        if p["id"] == incident_id:
            return p
    raise KeyError(incident_id)


def real_planted():
    return [p for p in PLANTED if p["real"]]


def callers_of(service):
    return [s for s, calls in DEPENDENCIES.items() if service in calls]


def dependency_distance(a, b, limit=3):
    """Hops between two services in either direction, or None if further
    apart than `limit`. Used to decide whether two anomalies belong to the
    same incident."""
    if a == b:
        return 0
    seen = {a}
    frontier = [a]
    for hop in range(1, limit + 1):
        nxt = []
        for node in frontier:
            neighbours = set(DEPENDENCIES.get(node, [])) | set(callers_of(node))
            for n in neighbours:
                if n == b:
                    return hop
                if n not in seen:
                    seen.add(n)
                    nxt.append(n)
        frontier = nxt
        if not frontier:
            break
    return None


def is_upstream_of(candidate, service, limit=3):
    """True if `candidate` is called by `service`, directly or transitively.

    A slow dependency explains a slow caller; the reverse is not true. The
    root-cause ranking needs the direction, not just the connection.
    """
    if candidate == service:
        return False
    frontier = list(DEPENDENCIES.get(service, []))
    seen = set(frontier)
    for _ in range(limit):
        if candidate in frontier:
            return True
        nxt = []
        for node in frontier:
            for n in DEPENDENCIES.get(node, []):
                if n not in seen:
                    seen.add(n)
                    nxt.append(n)
        frontier = nxt
        if not frontier:
            return False
    return False


def timestamp(minute_index):
    return START + timedelta(minutes=int(minute_index))
