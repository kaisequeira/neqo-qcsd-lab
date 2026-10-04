# Run a flight for an enrolled group

[The flight command](../tools/rapid_class_mode_flight.py) prepares one defense
setting for the next enrolled group of 1–5 admitted static sites. It preserves
each complete resource graph. The study target remains 50 classes × five
settings × 64 visits: 16,000 formal traces.

Run these commands from the repository root using Python 3.11 or later. The
operator and its hash-bound helpers are included in the clone. Runtime,
enrollment and evidence paths are supplied by the operator; they must be
absolute and refer to real, closed records.

The bundled successor includes the original generic prefix-transport repair.
It follows only sealed inherited decisions, including their complete GET and
deferral records. Its final mount set removes redundant child directories to
match the public deep verifier. The shared resolver supplies the same roots to
formal preflight, collection and readiness; later active attempts are excluded.

## Enroll a group

Use the existing study, current authenticated static context and matching published
execution checkout. The public command creates the next enrollment without
changing earlier batches:

```bash
PYTHONPATH="$QCSD_SOURCE/src:$QCSD_SOURCE" "$QCSD_PYTHON" -B \
  "$QCSD_SOURCE/tools/rapid_rolling_capture.py" enroll \
  --evidence-root "$STUDY_ROOT" \
  --acquisition-root "$CURRENT_STATIC_CONTEXT" --count 5
```

Save the returned `batches/bNNNN/enrollment.json` as `ENROLLMENT`. The count can
be 1–5 and requires that many already admitted sites. Existing failures and
earlier class indices remain accounted for.

The recipe supports original supplied graphs, complete supplementary graphs,
and prospectively declared response-budget successors. Every selected class
must already have its own complete GET admission. A group must have the same
declared response and recording limits; use a smaller group when those limits
differ. Each class uses the same limits across all five settings.

## Stage one setting

Use an installed runtime whose canonical receipt, clean checkout, images and
client agree. Set `LAB_COMMIT`, `NATIVE_COMMIT` and `CANONICAL_SHA256` from those
actual records. Choose a new output directory and name before the flight.

```bash
"$QCSD_PYTHON" -I -B tools/rapid_class_mode_flight.py stage \
  --runtime-build-root "$RUNTIME_BUILD" --clean-runtime-root "$QCSD_SOURCE" \
  --canonical-sha256 "$CANONICAL_SHA256" \
  --expected-lab-commit "$LAB_COMMIT" --expected-native-commit "$NATIVE_COMMIT" \
  --study-root "$STUDY_ROOT" --enrollment "$ENROLLMENT" \
  --output "$FRESH_FLIGHT" --python "$QCSD_PYTHON" \
  --name "$FRESH_NAME" --campaign-seed "$CAMPAIGN_SEED" --mode tamaraw
```

Available settings are `undefended`, `front`, `tamaraw`, `buflo`, and `cs-buflo`.
The output must be a fresh directory under the declared data root, outside
immutable inputs. Staging creates files and earns no scientific credit.

For FRONT or BuFLO, run `amend` before finalizing. It invokes the public
prospective amendment for the whole selected group; BuFLO uses the declared
duration-200 policy. For other settings, proceed directly to `finalize`.

```bash
"$QCSD_PYTHON" -I -B tools/rapid_class_mode_flight.py amend \
  --setup "$FRESH_FLIGHT/setup.json" --setup-sha256 "$SETUP_SHA256"

"$QCSD_PYTHON" -I -B tools/rapid_class_mode_flight.py finalize \
  --setup "$FRESH_FLIGHT/setup.json" --setup-sha256 "$SETUP_SHA256"
```

Save the exact returned setup and plan hashes. Repeated names or changed inputs
are rejected. Preserve every failed flight and use a new directory for a retry.

## Check and capture this setting

The finalized `commands.json` holds the exact commands. The dispatcher records
each actual start, completion and raw log:

```bash
"$QCSD_PYTHON" -I -B tools/rapid_class_mode_flight.py run \
  --plan "$FRESH_FLIGHT/plan.json" --plan-sha256 "$PLAN_SHA256" --step preamble
```

Run `preamble`, `qualify`, `preflight`, `capture`, and `deep` in order. These
check the installed Source/client, response evidence for every selected site,
and one complete visit to the prospectively selected canary site.

After a successful capture and independent deep verification:

```bash
"$QCSD_PYTHON" -I -B tools/rapid_class_mode_flight.py readiness \
  --plan "$FRESH_FLIGHT/plan.json" --plan-sha256 "$PLAN_SHA256" --modes tamaraw

"$QCSD_PYTHON" -I -B tools/rapid_class_mode_flight.py run \
  --plan "$FRESH_FLIGHT/plan.json" --plan-sha256 "$PLAN_SHA256" --step plan
```

The public planner writes `plans/g01.json` and `plans/g01-spec.json` for this
setting. Formal `launch`, `complete-lane` and `verify-lane` use the existing
[rolling study workflow](RAPID-CAPTURE-PATH.md). Other defenses can become ready
independently. A passing canary provides no formal trace credit.

For another original setting with the same sites, `stage` may use
`--reuse-qualification` with the prior group's response-only named set. It
reopens the same current Source, image, client, manifests and implementation;
changed bindings reject reuse. FRONT/BuFLO need their own post-amendment epochs.

Changed scientific verifier bytes require a fresh matching qualification and
canary for each setting. The recipe checks only dependencies transported by
the authenticated manifests inside the image; it adds no caller-supplied
workspace mounts. It grants no historical runtime bridge or new-role parallel
proof. Browser admission follows its separately registered workflow.
Earlier formal samples keep their original immutable epoch and slot identities;
new formal credit requires independently verified complete results.
