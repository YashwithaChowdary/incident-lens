"""Read the four input streams into one common shape.

Four files arrive in four formats: metrics as CSV, logs as JSON lines,
deploys and alerts as JSON, the dependency map as YAML. Everything
downstream works in whole minutes since the start of the capture, because
that is the resolution the metrics arrive at and the resolution an incident
timeline needs. Mixing second-precision log lines with minute-precision
metrics is how "the deploy came after the first error" happens.

Nothing here is clever. It is worth its own module only because every later
stage depends on the timestamps and the minute index meaning exactly one
thing.
"""
import json
import os
from datetime import datetime

import pandas as pd
import yaml

from .config import START


def _minute(ts):
    return int((ts - START).total_seconds() // 60)


def load_metrics(folder):
    """(timestamp, service, metric, value) plus an integer minute index."""
    path = os.path.join(folder, "metrics.csv")
    df = pd.read_csv(path, parse_dates=["timestamp"])
    df["minute"] = ((df["timestamp"] - START).dt.total_seconds() // 60).astype(int)
    return df


def load_logs(folder):
    """(timestamp, service, level, message, trace_id) plus a minute index."""
    path = os.path.join(folder, "logs.jsonl")
    records = []
    with open(path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                # A real log stream contains truncated lines. Dropping them
                # silently would be worse than counting them, so the count
                # is returned and reported.
                records.append({"_malformed": True, "line_no": line_no})
                continue
            rec["_malformed"] = False
            records.append(rec)

    df = pd.DataFrame(records)
    malformed = int(df["_malformed"].sum()) if "_malformed" in df else 0
    df = df[~df["_malformed"]].drop(columns=["_malformed"], errors="ignore")
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["minute"] = ((df["timestamp"] - START).dt.total_seconds() // 60).astype(int)
    return df.reset_index(drop=True), malformed


def load_deploys(folder):
    with open(os.path.join(folder, "deploys.json"), encoding="utf-8") as fh:
        rows = json.load(fh)
    for r in rows:
        r["timestamp"] = datetime.fromisoformat(r["timestamp"])
        r["minute"] = _minute(r["timestamp"])
    return sorted(rows, key=lambda r: r["minute"])


def load_alerts(folder):
    with open(os.path.join(folder, "alerts.json"), encoding="utf-8") as fh:
        rows = json.load(fh)
    for r in rows:
        r["timestamp"] = datetime.fromisoformat(r["timestamp"])
        r["minute"] = _minute(r["timestamp"])
    return sorted(rows, key=lambda r: r["minute"])


def load_dependencies(folder):
    with open(os.path.join(folder, "dependencies.yaml"), encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    return {svc: list(calls or []) for svc, calls in raw.items()}


def load_ground_truth(folder):
    """The planted incidents, if the folder has them. Used only by the
    self-check, never by the pipeline itself."""
    path = os.path.join(folder, "ground_truth.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def load_all(folder):
    logs, malformed = load_logs(folder)
    return {
        "metrics": load_metrics(folder),
        "logs": logs,
        "malformed_log_lines": malformed,
        "deploys": load_deploys(folder),
        "alerts": load_alerts(folder),
        "dependencies": load_dependencies(folder),
        "ground_truth": load_ground_truth(folder),
    }
