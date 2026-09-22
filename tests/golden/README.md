# Golden fixtures

Shared, deterministic test data. Every agent tests against the same bytes so that two
packages cannot quietly disagree about what "correct" means.

Regenerate with `make seed` (or `uv run python scripts/generate_golden.py`). The
generator is seeded and reads no clock; running it twice produces identical logical
content. Parquet *bytes* are not guaranteed stable across pyarrow versions, so each
table is pinned by `rows_digest` — a hash over the logical rows — not by file checksum.

A0 seeded these. Any agent may add a fixture. **Nobody edits someone else's.**

---

## `drift_table/` — a table with documented drift at a known snapshot

Three snapshots of a synthetic `orders` table, 2000 rows each.

| snapshot | drifted | what it is for |
|----------|---------|----------------|
| `snap_0` | no      | baseline |
| `snap_1` | no      | second baseline; detectors must find nothing between 0 and 1 |
| `snap_2` | **yes** | the drift |

`manifest.json` states exactly what changed, in `documented_drift`:

* `country = 'PT'` rises from about 1% of rows to about 18%.
* Within `country = 'PT' AND status = 'refund'`, `amount` jumps from
  `lognormal(3.2, 0.7)` to `uniform(400, 900)`.
* `country = 'US'` is the **false-positive control**. A detector that flags it is wrong.

`column_bounds` in each snapshot are Iceberg-style min/max. They are in the fixture
because they are a leak path: the `customer_email` bounds are two real addresses.

## `classification/` — half-labelled, with a ceiling you cannot game

6000 rows, 80/20 time-ordered split.

* `train.parquet` has `label_observed`, which is `null` for about half the rows. The
  true `label` column is **not** in the training file.
* `holdout.parquet` has the true `label`.
* `meta.json` records `bayes_auc`: the AUC of the *true* generating probabilities on the
  holdout. No model can beat it. `target_auc` is that number minus 0.02, which is the
  prediction objective from the brief.

Scoring above `bayes_auc` means the generating process leaked into the features, not
that the model is good. Treat it as a failing result.

`leak_traps` in `meta.json` names three deliberate hazards: a unique `entity_id` that
target encoding will memorise, an `ACME_CORP` merchant category that carries real signal
and will tempt a feature named `is_merchant_ACME_CORP`, and a `label_time` 45 days after
`event_time`.

## `pii_torture/` — every leak path, in one table

Twelve rows of realistic synthetic identifiers. Column names, manifest bounds,
most-common-values, Count-Min heavy hitters, a category histogram, a small cell (n=3),
a quantile over a twelve-person population, a derived feature name and a driver
exception message **all** contain identifiers.

`expected_leaks.json` lists every string that must never appear in any egress artifact.
Render your alert, log line, LLM payload, model card or UI response to text and assert
that none of them appear.

That test is a **backstop**. The control is the taint type plus the gate. A passing
string search on its own proves nothing — most of these leaks are things a regex would
never recognise as sensitive.

## `segment_key_vectors.json` — the normalisation, pinned

Twenty vectors covering column casefolding, value case preservation, predicate ordering,
duplicate collapse, type tagging (`1` is not `"1"` is not `True`), negative zero,
decimal normalisation, `IN` member sorting and escaping, `BETWEEN` ordering, nullary
operators, UTC timestamp formatting and NFC normalisation.

Each vector gives the inputs as `(py_type, literal)` pairs, the canonical string and the
resulting key. If your implementation disagrees with any of these, your implementation
is wrong — the normalisation is specified in full in the
`godwit_contracts.segment` module docstring.

## `sketch_envelopes.json` — three serialised envelopes

One pure statistic (`exact_count`), one opaque summary (`kll`) and one item-bearing
sketch (`count_min`) whose payload contains row values and which must therefore declare
`DATA_VALUE`.

A2 will replace the opaque payloads with real `datasketches` bytes. What downstream
agents agree on today is the **envelope shape**, not the payload encoding.

## `candidates.json` — two candidates

They correspond to the documented drift above. The second has population 34, which is
*above* the default small-cell threshold of 20. That is deliberate: what makes it unsafe
to show is that its segment predicates quote real column values. Small-cell suppression
alone would let it through.
