# A capture study using complete supplied resource lists

This prospective role studies **fixed multi-origin resource replays**: 50 sites,
five settings, and 64 accepted visits per site and setting, totaling **16,000**.
It starts serial capture once one site and its requested setting are ready.
The earlier browser study and its eight accepted traces keep their original
labels and are not included in this new study.

## What changes, and what the result means

Each candidate keeps every supplied URL, in its original order, with its exact
query. The importer adds an explicit primary document as resource 0. All other
resources depend on it. This is a declared replay graph, not an inferred browser
dependency graph. The fixed replay headers and all original graph bytes are
sealed before measurement.

The prerequisite is one successful primary GET, followed by one complete GET of
the entire graph with the ordinary Native HTTP/3 client. Every origin must use
HTTP/3 and a public address. Every request must finish with actual FIN, status,
body length and body hash evidence. The primary must be nonempty successful
HTML; at least one nonempty successful resource must use a secondary origin.
Completed auxiliary HTTP errors are retained as their actual responses. A
redirect, incomplete body, missing resource, unsafe address, cap overflow or
failed Native process does not produce an admission.

The client does not retain response body contents. The new role therefore makes
**no successful browser render, challenge absence, cookie, JavaScript, or
repeated response stability claim**. A 200 HTML response can be an interstitial.
Its hash and headers do not decide that question. Existing primary domain
exclusions and public address checks remain in force.

Browser convergence and the earlier three stability visits are absent from this
role. Current response-only chaff qualification, requested-setting readiness,
complete application graphs, fixed defense settings, ordinary deep verification,
DNS/CPU isolation and failed-lane recovery remain required for formal traces.

## Limits are declared before the first GET

`context-init` declares `--max-response-bytes` (default **16,777,216 per
response**) and `--capture-megabytes` (default **64 per recording**). The same
response budget appears in the GET declaration, prepared manifest, capture plan,
and ordinary g01/g02 campaigns. A different budget requires a different study
declaration. There is no silent fallback to the earlier 1 MiB application cap.

The existing timeout is **120 seconds**; the recorder runs for up to **180
seconds**, including its existing 2-second settling allowance. These are bounds,
not a promise that every supplied graph fits. Overflow and timeout failures keep
all raw evidence and never remove resources or fabricate their lengths.

The unchanged BuFLO parameters also bound incoming opportunities to 6,000
1,200-byte cells at a 20 ms interval: approximately 7.2 MB of advertised credit
before accounting for HTTP framing and reviewed chaff. A 16 MiB response cap
allows measurement of large graphs; it does not promise those graphs fit every
defense. Actual GET sizes and later full-graph defense evidence remain decisive.
This source changes no event budget, cadence, cell size, or defense algorithm.

The existing 120-response chaff qualifier retains its separate **1 MiB cap for
the selected chaff response**. Large application resources remain in the graph.
A site with no usable candidate under that qualifier can fail qualification;
this source does not invent a chaff endpoint or silently alter that contract.
This static role currently uses serial lanes. Parallel activation is a separate
future control extension and does not gate the first serial lane.

## Create a context before the bootstrap and full GET

Use the actual closed runtime binding JSON with exactly these keys:
`source_manifest_sha256`, `lab_commit`, `native_commit`, `image_digest`, and
`client_sha256`. They identify the installed measurement runtime. The external
producer is separately byte-bound; it does not claim to be installed in that
image.

The public CLI is `tools/supplied_static_capture.py`, which bootstraps its own
checkout under Python `-I`. All context and evidence paths should be absolute.
The following are invocation templates, not actual completed operations:

```bash
python3.11 -I -B "$STATIC_AUTHORITY/tools/supplied_static_capture.py" context-init \
  --context "$NEW_CONTEXT" --source "$SOURCE_LIST" \
  --source-sha256 "$SOURCE_SHA256" --runtime-binding "$ACTUAL_RUNTIME_BINDING" \
  --max-response-bytes 16777216 --capture-megabytes 64
```

An optional `--candidate-order /absolute/permutation.json --ordering-rationale
"..."` declares a different initial convenience order **before any GET or
admission**. The JSON must be a permutation of all source positions, with no
duplicate, missing or invented candidate. For the current 73-entry source,
`[22, 1, 2, ..., 21, 23, ..., 73]` puts independently checked Poki first and
leaves every other entry in original order. Queue position 1 then has
`source_position: 22`; GET and terminal records retain both positions. Original
raw Source bytes and every site's resource order/DAG remain unchanged. This
does not grant historical diagnostic or browser traces static-study credit.
Without these options, the original source order remains the default.

Root can execute the new producer with the unchanged installed Native client
before building the thin Lab image for static qualification. Mount the **old
matching collection Source** as `/authority` and set `QCSD_LAB_ROOT=/authority`.
Mount this new external producer checkout separately as `/operator`, read-only.
The executed-image guard still checks the old installed 31-file implementation,
the old matching Source and the actual client. Do not mount this entire new
branch at `/authority` over an old image.

Mount the context and output parent at their **same absolute HOST paths inside
the image**, read-only and writable respectively, and use the existing recorded
Docker operator to retain its actual start, completion and raw output. After the
actual image, mounts and isolation are fixed, its argument suffix is:

```bash
env QCSD_LAB_IMAGE_DIGEST="$ACTUAL_COLLECTION_IMAGE" \
  QCSD_LAB_SOURCE_METADATA=/usr/share/qcsd-lab/source.json \
  QCSD_LAB_ROOT=/authority \
  /opt/qcsd-venv/bin/python3 -I -B /operator/tools/supplied_static_capture.py execute-get \
    --context "$NEW_CONTEXT" --position "$CANDIDATE_POSITION" \
    --get-root "$NEW_GET_ROOT" --max-response-bytes 16777216 --timeout-seconds 120
```

The first actual Native command uses `/usr/local/bin/neqo-qcsd-client run` with
`http-2xx-only-v1` on the exact primary. Only after its actual success does the
second command use `completed-terminal-http-errors-v1` on the exact full graph.
The original neutral manifest remains unchanged. The derived full Native input
adds only the primary's `known_valid: true` approval. Both phases have independent
raw Native files, public DNS records, exact command and process records.

`verify-get` reopens every input and raw output. If execution paths were relocated,
the optional `namespace` command seals the real outer Docker mount mapping and
process logs; verification accepts only that exact mapping, never arbitrary path
substitution. Same-absolute mounts need no namespace record.

## Prepare, enroll, qualify, and capture

`admit --context ... --position ... --get-root ... --traffic-policies ...` writes a
distinct static terminal and prepared workload after reopening the successful
GET proof. The traffic-policy JSON must contain the four current explicit
BuFLO, Tamaraw, FRONT and terminal-primary policy fields. It cannot change an
existing prepared workload or retrospectively approve an earlier failed GET.

`defer-get` records a real failed Native run or a completely verified strict
primary rejection as an **operational deferral** with zero eligibility credit.
A zero process exit alone cannot establish this failure: the rejection verifier
requires the original request, non-2xx response, FIN and raw Native evidence.
`input-decision` can reject only an exact supplied-list
defect or an already excluded primary. Neither manufactures an HTTP/3 failure.

After a matching thin Lab image includes the new prepared-role validators:

The ordinary launcher derives read-only mounts for the original GET evidence
and its declared context at their recorded absolute paths. It authenticates
the proof before deriving those mounts, and carries them through installed
preflight, DNS, collection and deep verification. The retained GET producer,
prepared workload and original measurement labels are unchanged. A matching
thin Lab successor can reuse the verified Native client when its Native Source
and dependencies are unchanged; its installed Lab bytes are checked separately.

1. Use `tools/rapid_rolling_capture.py init-static` with the static context and
   actual capture runtime JSON. The default `init` remains the browser contract.
2. Use ordinary rolling `enroll`, copying the exact admitted workload into the
   runtime's workload root. Initial batches can contain one to five sites.
3. Obtain its current named 120-response qualification with the installed
   matching client and unchanged qualifier. Keep the original sidecar labels.
4. Use ordinary rolling `plan` with the completed named set and canary readiness
   for the requested setting. A failure in another setting does not block it.
5. Launch registered four-visit serial lanes; verify each through the ordinary
   deep path. Restart only a failed same-input lane with its g02 predecessor.
6. Final closure requires exactly 50 distinct enrolled classes and 64 unique
   accepted slots per class and setting. Preparation and diagnostic work grants
   no formal trace credit.

## Reach 50 without changing already admitted graphs

The supplied list has 73 entries and 55 graphs that become multi-origin when
their explicit primary is added. After exclusions and input-only rules,
50 are candidates for a live test. Earlier root-only screening identified
23 promising lists; none of these counts is a count of admitted classes.
Complete ordinary HTTP/3 GETs and chaff qualification may fail; this list
cannot guarantee 50 eligible sites.

A successor context can be created with `context-init --parent-context` and a
new frozen list. It must append genuine complete resource lists after the exact
original candidate prefix, with the same runtime, limits and scientific rules.
Previously declared terminal receipts and their Source labels remain unchanged;
the successor inherits only the sealed completed prefix. Already enrolled sites
continue without restarting their lanes. New entries are measured under the new
context before admission, in their declared order.

The 600-domain catalogue contains domains, not complete resource graphs.
Additional classes need real supplied lists or a separately recorded complete
discovery. This contract does not invent CDN addresses, keep only working
resources from a failed graph, or count a homepage alone as multi-origin.
