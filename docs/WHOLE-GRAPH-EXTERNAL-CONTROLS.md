# Separate browser discovery and Native GET

The public GET adapter recognizes exact producer pairs for discovery versions
1–7. Versions 5–7 additionally bind every separately loaded control module.
The recorded browser image remains the original discovery image; those external
control files are not represented as installed image Source. Discovery inputs
have zero Site and trace credit. Only a subsequent genuine complete Native GET
and public admission can establish eligibility.

The production packages are tracked under `tools/whole_graph_discovery_v1` through
`tools/whole_graph_discovery_v7`. Their entrypoints resolve their adjacent files
and accept explicit paths. They have no dependency on a particular parent
workspace or diagnostic directory. All graph occurrences, request headers,
dependencies and approved origins remain required.

## Fresh version 6 declaration

From a normal clone, supply existing authenticated artifacts through these
arguments:

```sh
python3 -I -B tools/whole_graph_discovery_v6/operator.py declare \
  --source "$discovery_source" --lab-commit 2b990d930358e4a3ba499ae7090f0bd8edb4afeb \
  --browser-image sha256:abc21255157c4c6cc12b1941b8789c82642899b264e88539c2549b66259b10fa \
  --catalogue "$catalogue" --parent-context "$original_context" \
  --source-metadata "$discovery_image_metadata" --count 5 \
  --previous-plan "$previous_plan" --previous-batch "$previous_batch" \
  --output "$fresh_declaration"
python3 -I -B tools/whole_graph_discovery_v6/operator.py check \
  --plan "$fresh_declaration/plan.json"
```

Repeat the previous-plan and previous-batch flags for the exact retained lineage.
The discovery Source must be a clean checkout of the stated original Lab commit
with Native c24da2afeec2944a67c48b38eba957dcd543728d. The original image metadata,
catalogue, original context, predecessor producer files and completed historical
batches are required artifacts. A repository clone alone does not contain or
replace them. Export or transfer their authenticated closure before declaring
on another system. No declaration claims that an image is already installed.

Physical discovery remains a Root action in the declared image with the
declaration's authenticated transport roots mounted read only and only a fresh
attempt namespace writable. Use `verify-input --input <whole-graph-input.json>`
before `tools/rapid_whole_graph_supplement.py` creates a prospective GET context.
The latter binds the currently installed GET Source/runtime separately; it does
not relabel the original browser producer.

The historical partial version 4 reservation for seeds 11–15 is a separate
version7 continuation authority. A normal version6 next-unseen declaration cannot
reuse those reservations. Its original failed seed11 remains retained and
unadmitted. Version7 `declare --original-plan <old-v4-plan> --retained-bindings
<exact-failed11-bindings> --output <fresh>` selects only the four untouched original
rows. Local command positions1–4 are explicitly mapped to original positions2–5.
The historical artifact closure must retain its original reference layout; no
old plan is silently converted or relabelled. The separate Root continuation
controller records actual status/raw outputs and refuses concurrent Docker actors.

Existing GET producer proofs retain their original verifier labels. Changed Lab
adapter bytes require new truthful GET Source/runtime bindings; this Source patch
does not assert old scientific qualification, canary or capture equivalence.
