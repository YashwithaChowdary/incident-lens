# IncidentLens

Takes a week of logs, metrics, deploys and alerts from a fictional
eight-service system and works out what broke, when, and why — with every
claim traceable to the metric point, log line or deploy record behind it.

**All data in this project is synthetic.** `scripts/make_sample_data.py`
generates it and plants five faults with known causes, so the pipeline's
answers can be checked against something instead of eyeballed. Nothing here
touches a real production system, and every number below was measured on
this repository's own output.

## What it does, measured

On the generated week — 322,560 metric points, 135,559 log lines, 13
deploys, 12 alerts:

| planted fault | real? | detected | existing alert fired | cause ranked first |
|---|---|---|---|---|
| bad-deploy-1 (payments) | yes | +0 min | +6 min | `deploy/payments` ✓ |
| memory-leak (search) | yes | **+74 min** | **+288 min** | `service/search` ✓ |
| db-slowdown (db-proxy) | yes | +0 min | +4 min | `service/db-proxy` ✓ |
| noisy-alert (notify) | **no** | not promoted ✓ | +0 min | — |
| bad-deploy-2 (payments) | yes | +0 min | +6 min | `deploy/payments` ✓ |

Four real faults found, the noise rejected, the planted cause ranked first in
every case, and the repeat linked back to its original at symptom similarity
1.0. The memory leak is the interesting row: the pipeline flagged it 3 hours
34 minutes before the `memory_above_90pct` rule did, because it was watching
the shape of the climb rather than waiting for a fixed line to be crossed.

It also reports one false positive it did not tune away — see
[false positives](#the-false-positives-one-series-produces-all-of-them).

## Run it

```bash
pip install -r requirements.txt
python scripts/make_sample_data.py     # writes data/, ~37 MB
python run_demo.py
python -m pytest test_incidentlens.py -q
```

To see the results as a web page instead of terminal output:

```bash
python build_site.py                   # writes docs/index.html
```

Open `docs/index.html` in a browser. It is one self-contained file drawn from
the same pipeline run, so it cannot disagree with `run_demo.py`, and it can be
hosted as-is with GitHub Pages (Settings → Pages → branch `main`, folder
`/docs`).

On Windows use `py` in place of `python`. `run_demo.py` exits non-zero if any
self-check fails, so it works as a regression gate.

## How it works

```
ingest ─► log templating ─► anomaly detection ─► grouping ─► cause ranking ─► report
                                   │                │              │
                          two competing        dependency      scored
                          baselines            graph + time    candidates
```

### 1. Log templating (`templates.py`)

135,559 lines collapse to **20 distinct templates** (a 6,778× reduction) by
masking the variable parts:

```
handled request id=4f1a9c33 path=/v1/orders status=200 in 42ms
handled request id=90bb2e01 path=/v1/orders status=200 in 17ms
                        ↓
handled request id=<HEX> path=/v1/orders status=<NUM> in <NUM>ms
```

Words are left alone on purpose: the path and the name of the service being
called stay in the template, so `/v1/orders` and `/v1/checkout` remain
separate sentences.

The compression is not the point. The point is that **exactly 3 templates
never appear in the clean reference period**, and they are precisely the
three planted faults:

```
id 17  x554   payment gateway timeout after <NUM>ms req=<HEX> retry=<NUM>
id 18  x363   allocation slow: heap <NUM>% used, gc pause <NUM>ms
id 19  x242   connection pool exhausted, waited <NUM>ms for a slot
```

A sentence the system has never said before is decisive on its own, so new
templates get their own rule rather than a z-score. A z-score against a
baseline of zero occurrences with zero spread is arithmetic, not evidence.

Masking order matters: UUIDs and IPs contain digits, so masking plain numbers
first would stop the longer patterns ever matching.

### 2. Two definitions of "normal" (`anomaly.py`)

The score is a robust z-score — median and median absolute deviation, scaled
by 0.6745 — rather than mean and standard deviation. A mean is computed from
the data being judged, so a large anomaly inflates the very spread it is
measured against and partly hides itself. A median barely moves.

The harder question is which window "normal" comes from, and the two
reasonable answers disagree:

- **reference** — median and MAD from the first 24 hours, which the generator
  guarantees are clean. Cannot drift, because it never updates.
- **trailing** — median and MAD over the previous 6 hours, skipping the most
  recent 30 minutes so a developing fault does not calibrate its own
  baseline. This is what monitoring systems usually do.

Both divide out the same hour-of-day profile first, so the only thing that
differs is how far back the window reaches. Measured coverage of each fault's
minutes:

| fault | length | reference | trailing |
|---|---|---|---|
| bad-deploy-1 | 42 min | onset +0, 42/42 = **100%** | onset +0, 42/42 = **100%** |
| memory-leak | 360 min | onset +74, 286/360 = **79%** | onset +74, 183/360 = **51%** |
| db-slowdown | 55 min | onset +0, 55/55 = **100%** | onset +0, 55/55 = **100%** |
| bad-deploy-2 | 38 min | onset +0, 38/38 = **100%** | onset +0, 38/38 = **100%** |

On faults that arrive in minutes the two are indistinguishable. On the
six-hour leak they see the onset at the same moment and then diverge: the
trailing window climbs into the fault and loses the back half of it.

This is weaker than what I expected to find. I built the comparison
believing a trailing baseline would miss a slow leak entirely. It does not —
it sees the edge and then forgets. The code and this README say so because
the measurement said so.

### 3. Grouping (`incidents.py`)

A db-proxy slowdown that spreads to four callers produces anomalies on five
services. Reporting five incidents would page five teams for one problem, so
two signals join when they are **close in time and connected in the
dependency graph** — within 15 minutes and 2 hops. Time alone would merge
coincidences; connection alone would merge everything, since every service
here is connected to something.

Two rules decide what becomes an incident at all, and both exist because of
specific noise in this data:

- **An alert alone is not an incident.** The planted noisy alert fires with
  no metric movement and no log spike behind it. A cluster needs at least one
  metric or log anomaly. This is how the noise gets rejected, and it also
  rejects the 7 routine `disk_usage_above_70pct` alerts.
- **A single one-minute blip is not an incident.** A cluster needs either a
  second corroborating signal or one signal that is sustained or severe.

On this data, 46 metric + 4 log anomalies + 12 alerts group into **5
incidents with 33 clusters rejected**, each rejection printed with its
reason.

### 4. Cause ranking (`causes.py`)

Every candidate carries its score breakdown, so the ranking can be argued
with. For bad-deploy-1:

```
deploy v2.4.0 to payments  score 90
    +50  landed 3 min before onset
    +40  deployed the service that failed first
     -> deploy v2.4.0 to payments by r.lindqvist at 2026-10-07 09:57
        ("retry payment confirmations more aggressively")
fault inside payments  score 80
    +35  showed the first anomaly
    +25  upstream of 2 of 2 other affected services
    +10  its own signals are severe or sustained
    +10  share of the largest departure seen
     -> payments is called (directly or transitively) by gateway, orders
     -> error_rate on payments peaked at z=252.75 (minute 3507)
fault inside orders  score 23
    ...
```

The weights are set so a deploy on the first-affected service minutes before
onset outranks everything, while a service that started first *and* sits
upstream of every other affected service outranks a deploy on a service that
was merely collateral. Direction matters: `is_upstream_of` is deliberately
not symmetric, because a slow dependency explains a slow caller and the
reverse is false.

The weights are a judgement, not a result. They are stated in the module and
then measured against the planted causes, and the margin between first and
second place is reported as confidence — a top candidate 2 points clear is a
coin toss being presented as a conclusion. Note that bad-deploy-1 above comes
out as *medium* confidence, not high: 90 against 80 is a 10-point margin.

### 5. Similarity (`similar.py`)

The question at 03:00 is not "what is broken" but "have we seen this".
Matching on the cause would be circular, so the match is on the shape of the
symptoms — the set of (service, signal) pairs that went anomalous — scored
by Jaccard similarity. bad-deploy-2 matches bad-deploy-1 at **1.0**; the
db-slowdown matches neither.

Alerts are excluded from the fingerprint on purpose: an alert reflects which
rules someone configured, not what the system did.

The weakness, stated rather than hidden: this matches symptoms, so two
unrelated faults that happen to break the same services the same way will
look identical. The output says "similar", never "same cause".

## The false positives: one series produces all of them

Of 33 rejected clusters, **27 are the same series** — `db-proxy/error_rate`
— and one pair of them slipped through to become INC-005, the single
unexplained incident in the run.

db-proxy's error rate baseline is 0.001, half the next lowest in the system.
A single noisy sample is therefore a large multiple of the baseline and
clears any z threshold; all 29 flags last a single minute and score between
z = 6.74 and 11.24 against a threshold of 6.0. The corroboration rule rejects them one at a time, but where two
happen to land within the 15-minute join window they vouch for each other
and one gets through.

That is the pipeline's entire false-positive budget: **1 false incident per
synthetic week, from 1 of 32 series**. It is reported rather than tuned
away, because the honest fix is a minimum absolute error-rate floor for
very-low-baseline series, not a higher z threshold that would also cost
sensitivity on the leak.

## Four bugs worth recording

Each of these produced confident, completely wrong output, and each now has
a test pinning it:

1. **`56ms` was never masked.** `\b\d+\b` needs a non-word character after
   the digits, and there is none between the `6` and the `m`. Every distinct
   millisecond value became its own template: **3,795 templates and 10,476
   spurious "never seen before" anomalies**, which chained all eight services
   into one week-long incident. Fixed with a unit-aware rule that keeps the
   unit, since `took <NUM>ms` and `took <NUM>rows` are not the same sentence.
2. **Log counts judged round-the-clock.** Log volume follows traffic, so a
   template appearing twice a minute at 03:00 and six times at 14:00 is
   behaving normally. Scoring against a single median turned every working
   day into an incident: **5,430 log anomalies, six incidents each running
   06:00 to 22:00**. Fixed by comparing each minute to the same hour of day
   in the reference period.
3. **A proportional MAD floor on count data.** Per-minute template counts
   have a median of zero, so a floor of 25% of the median collapsed to 1e-9
   and a single extra log line scored **z = 1.3 × 10⁹**. For counted things
   the smallest meaningful difference is one whole item, so the floor is now
   absolute.
4. **Run-gap too tight for intermittent signals.** The leak logs once every
   seventh minute; a 3-minute gap tolerance split one fault into **24
   separate anomalies**. Metrics are sampled every minute and keep the tight
   tolerance; log templates get 10 minutes.

The seasonality problem bit twice — once on metrics, once on logs — and the
first version of the metric detector produced 480 anomalies, nearly all at
06:30, flagging the morning traffic step rather than any fault. Worth noting
that a two-baseline comparison where one side is broken proves nothing, so
both sides deseasonalise identically now.

## A contradiction in the brief

The brief this was built from asks for four planted incidents of which one is
noise, and separately for a repeat of the deploy pattern — which gives *four*
real incidents to detect, not the three it also asks for. "Exactly 3" and
"link the repeat" cannot both be satisfied. This project detects four,
rejects the noise, and documents the contradiction in `config.py` rather than
quietly dropping one to make a number match.

## Layout

```
incidentlens/
  config.py      the fictional system, and the planted faults with their causes
  ingest.py      four input formats to one minute-indexed shape
  templates.py   log lines to templates, templates to per-minute counts
  anomaly.py     robust z-scores, two baselines, seasonality
  incidents.py   grouping by time and dependency graph; what is not an incident
  causes.py      scored candidates with their arithmetic shown
  similar.py     symptom fingerprints and Jaccard matching
  report.py      cited summaries; nothing unattributable
scripts/
  make_sample_data.py   generates the synthetic week (run this first)
run_demo.py             end-to-end, with the self-check
build_site.py           builds the web page into docs/
web/page.html           the page template
docs/index.html         the generated page (GitHub Pages serves this)
test_incidentlens.py    38 tests
```

## What this does not do

- No streaming. Everything is batch over a finished window; a live version
  needs the trailing baseline and loses the coverage shown above.
- No learned thresholds. `z > 6` is a choice, defensible but not derived.
- Symptom-based similarity only, with the limitation stated above.
- The dependency graph is static. Real call graphs change under load, and a
  stale edge would send the cause ranking the wrong way.
- Synthetic data throughout. The faults are clean versions of real failure
  shapes; real incidents overlap, and nothing here handles two at once.
