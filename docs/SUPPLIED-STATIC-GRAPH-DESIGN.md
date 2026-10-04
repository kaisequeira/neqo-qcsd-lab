# Proposed acquisition of fixed resource replays

**Input importer and zero-credit full GET producer. This does not authorize enrollment,
qualification or capture.** The existing browser study and its receipts remain
on their original rules. The final intended count stays **50 classes × five
settings × 64 accepted visits = 16,000 traces**.

## Why a different acquisition path is justified

The site019 checkpoint 50 records 22 decisions and one eligible site, Poki,
already present in site018. Seven decisions stop at bounded root probes; three
stop at CDP operational errors; two stop because a page does not become quiet
within 30 seconds. No decision in this prefix records a full-resource HTTP/3
coverage failure or a failed multi-origin threshold. Other outcomes include
challenge pages, domain exclusions, a redirect boundary, blocked browser egress,
one DNS pin failure and one unsuccessful exact-page HTTP/3 probe.

These observations do not establish compatibility of the remaining resources.
They show that browser completion currently prevents reaching that measurement.
Reducing the already minimal requirement of one cross-origin resource would
not address the observed failures.

## Scientific claim

The proposed new claim is **classification and comparison of client-only
defences on fixed supplied multi-origin HTTP/3 resource replays**. It measures
the complete declared GET graph against ordinary HTTP/3 servers.

It does not claim that the graph is the complete resource set of a live browser
render, that its dependencies came from a browser, or that cookies, interaction,
CAPTCHA handling, WebSockets, JavaScript, POST requests and other browser actions
were reproduced. No excluded domain becomes eligible by importing its resources.
Existing primary domain exclusions and public-address safeguards remain checks.
Public Native output does not retain body contents, so this role makes **no
challenge-absence or successful browser-page claim**. A complete 200 response can
still be an interstitial; hashes and headers alone do not decide that question.

This change removes browser lifecycle, quiescence and origin convergence as
prerequisites **for the new resource-list role**. Full response completion,
origin coverage, public destination checks, source identity, defence ownership,
DNS/CPU isolation, current chaff qualification and ordinary deep verification
remain necessary. Failed or diagnostic attempts gain no formal credit.

## What the supplied file can provide

The frozen supplied file has 73 domains, 63 nonempty lists and 10 empty lists.
35 lists include at least two listed resource origins; 55 contain a resource
outside the primary domain. None includes its exact primary root document.
The retained root survey has 28 known-valid curated roots; 26 have nonempty
lists and 23 have an outside resource. These are potential inputs, not eligible
classes: every listed resource still needs complete HTTP/3 evidence.

The importer adds the explicit primary root as resource 0, unless it is already
listed. Every supplied address remains byte-for-byte identical, including its
query. The source-order list becomes a declared DAG: primary first, then all
listed resources depend on it. This is a replay design, not a reconstructed
browser dependency graph. Resource types are `Document` for the primary and
`Other` for supplied resources; no MIME classification is invented.

The manually fixed request headers are `accept: */*`, `accept-encoding: identity`
and `accept-language: en-US,en;q=0.9`. They are replay-client headers, not claimed
browser captures. There are no cookies, credential headers or invented response
lengths. Actual public DNS answers and response facts must be established later.

## Working input importer

The [importer](../src/qcsd_lab/supplied_static_graph.py) and
[CLI](../tools/supplied_static_graph.py) produce exactly two files:

- `native-input.json`: a valid bare Native resource manifest.
- `input-binding.json`: the supplied source hash, candidate entry hash, original
  supplied resource-to-ID mapping, primary role, declared DAG, exact manifest
  hash and origins. It explicitly says unqualified input, zero site credit,
  zero formal credit and no browser discovery claim.

Both source-byte identity and the complete mapping are reconstructed during
verification. Deleting a resource, changing headers/dependencies or resealing a
pruned manifest hash does not pass. Outputs are create-only. The importer does
not call DNS, a browser, Native, Docker, enrollment or qualification.

```bash
python3.11 -I -B tools/supplied_static_graph.py \
  --source /path/to/frozen-source.json \
  --source-sha256 "$SUPPLIED_SOURCE_SHA256" \
  --domain "$CANDIDATE_DOMAIN" \
  --output-root /path/to/new-input-directory
```

The bare input intentionally fails the existing research-preparation gate. It
cannot be passed off as a qualified workload by attaching browser-looking
metadata. This checkout changes no existing validator or public study authority.

## Reuse the existing Native measurement path

The existing Native `probe --input-manifest` accepts this graph and preserves
its resource IDs. It uses HEAD and bounded GET fallback: **probe success alone
does not prove that all response bodies were obtained**.

A [working zero-credit producer](../src/qcsd_lab/supplied_static_get.py) uses existing `run --workload` with an undefended
configuration for complete GET observations. Existing
`prepare._probe_response_stability` already makes three full GET runs and checks
the response ledger. It can supply the measurement primitive without invoking
the browser-first `prepare_workload` wrapper.

The exact public Native argument shape is:

```text
/usr/local/bin/neqo-qcsd-client probe --input-manifest native-input.json --output probe-output.json
/usr/local/bin/neqo-qcsd-client run --workload native-input.json --profile live --defense none
  --request-policy as-defined --application-response-policy completed-terminal-http-errors-v1
  --seed 0 --output-dir fresh-full-get --max-response-bytes DECLARED_LIMIT
  --timeout-seconds DECLARED_TIMEOUT
```

These are argument examples, not recorded Native operations. The new producer
rehashes the exact installed client and its ordinary executed-image implementation
receipt, checks explicit image/source/client identities, sets Native's existing
`QCSD_PUBLIC_ORIGIN_ONLY=1` guard and retains actual start, completion, stdout,
stderr and all four Native output files. It resolves every origin before the
run, requires all answers public, and independently checks that each actual
Native remote address is public and appears in the retained answers. Native
resolves again and selects its first answer; **this is not an enforced single-IP
pin**. A changed answer can cause a retained validation failure.

The exact runtime-binding JSON keys are `source_manifest_sha256`, `lab_commit`,
`native_commit`, `image_digest` and `client_sha256`, all taken from the actual
closed installed runtime. The external producer is separately byte-bound; its
new code is not described as installed in the older collection image.

## Execute the new complete GET step

The [public CLI](../tools/supplied_static_get.py) can run inside the declared
collection image. Mount this source tree read-only as `/authority`, the original
source/list input read-only as `/inputs`, and a fresh output parent writable as
`/evidence`. Root supplies the actual image, binding and isolation settings.
Neither the authoring task nor HOST tests execute this command:

```bash
env QCSD_LAB_IMAGE_DIGEST="$ACTUAL_COLLECTION_IMAGE_DIGEST" \
  QCSD_LAB_ROOT=/authority \
  QCSD_LAB_SOURCE_METADATA=/usr/share/qcsd-lab/source.json \
  /opt/qcsd-venv/bin/python3 -I -B /authority/tools/supplied_static_get.py execute \
  --runtime-binding /inputs/runtime-binding.json \
  --source /inputs/source-list.json --source-sha256 "$SUPPLIED_SOURCE_SHA256" \
  --input-root /inputs/imported-candidate --domain "$CANDIDATE_DOMAIN" \
  --output-root /evidence/new-complete-get \
  --max-response-bytes 16777216 --timeout-seconds 120
```

This runs one complete GET of the entire neutral graph, not HEAD, a browser,
enrollment or the 120-response qualifier. The byte cap is explicitly declared;
overflow, truncation, reset, missing resources and unsuccessful primary responses
cannot qualify. Leaf auxiliary 400–599 responses may remain complete observations
under the existing Native policy; every original ID and address is retained.
Primary 0 must be complete, nonempty and 2xx. No expected body is manufactured.
Failures retain the actual output directory and process records, with no proof
publication. Verification uses the same explicit bindings:

```bash
python3.11 -I -B tools/supplied_static_get.py verify \
  --runtime-binding /path/to/runtime-binding.json \
  --source-sha256 "$SUPPLIED_SOURCE_SHA256" --domain "$CANDIDATE_DOMAIN" \
  --output-root /path/to/new-complete-get
```

`full-get-proof.json` has the distinct closed type
`supplied-static-complete-native-get-evidence-v1`. Its complete input reconstruction,
14 raw file hashes, actual Native provenance, every response ID/status/body
length/hash, per-origin H3 endpoint/public remote, unique application streams and
actual FINs, successful `ResourceCompleted` observations, bidirectional packets,
and the existing directional UDP validation are all reopened. Endpoint completion
lists retain resource IDs and FIN stream IDs separately: Native's public responses
do not expose a resource-to-stream ID field, so no guessed association is inserted.
The summary has zero site and formal credit, no browser or challenge-absence
claim and no retained-body claim. A successful process exit or a resealed summary
alone is insufficient. Historical Native 841 output cannot pass an expected
Native 5f source binding.

## Later preparation and enrollment integration

The current complete-GET record is deliberately not preparation. Later implementation must define a separate versioned
`supplied-static-full-GET-preparation-v1` receipt, with these closed fields:

| Field | Required meaning |
| --- | --- |
| `schema_version`, `record_type`, `data_role` | Distinct static role; no browser schema impersonation |
| `declared_at`, `completed_at` | Prospective policy precedes actual measurements |
| `source`, `input_binding`, `native_input` | Reopened raw file references and hashes |
| `domain`, `primary_resource_id`, `dag_policy` | Exact imported candidate and resource 0 |
| `runtime`, `client`, `producer_sources` | Actual installed source/image/client and relevant module bytes |
| `public_origin_evidence` | All-public DNS precheck, native re-resolution guard and actual public destination for every origin; no fabricated enforced pin |
| `response_policy`, `primary_identity_policy` | Existing explicit application response policies |
| `full_GET_runs` | Three actual command/start/completion/log/output inventories, not summary assertions |
| `response_identities` | Every original ID and primary: status, complete body bytes/hash, request headers |
| `completion_proofs` | Original stream/endpoint/FIN and response events, actual complete run, no error |
| `full_list_coverage` | Exact imported ID/address/origin equality; no excluded/pruned resource |
| `udp_payload_qualification` | Existing packet-size/clock evidence from actual observations |
| `qualified_workload` | Typed static prepared workload with expected responses and original source bindings |
| `scientific_credit`, `site_credit`, `formal_accepted_trace_count` | All zero for preparation |

Every full GET run must have a complete Native terminal and all expected
resource responses. Primary 0 requires a successful nonempty complete response
with the explicit limited static-primary claim above. An auxiliary completed HTTP
error may be retained only under the existing explicit completed-terminal-errors
policy, with all its actual evidence; a timeout, missing body/FIN or transport
failure is not a terminal HTTP error. The primary variable-body policy and
auxiliary stable identities remain explicit. A configured byte cap must not
turn truncation into completeness. No HEAD-derived length is a body witness.

Do not claim HTML content type or absence of a challenge from status alone. The
static role must remain explicitly narrower than successful browser-page replay.
If challenge-content exclusion is required in the eventual study, actual body
capture and a separately declared content check are still needed; the current
public Native summary cannot prove it. No body capture or Native output change
is included here.

## Minimum subsequent source integration

1. Root executes and independently reopens the zero-credit full-GET producer on
   actual current Native 5f. The present HOST proof is synthetic contract testing,
   not a current Native measurement. Repeat actual GETs if response stability is
   required by the prospectively selected static preparation policy.
2. Add an explicit prepared-role union in `manifest` research validation and
   class-study validation: browser evidence remains required for browser role;
   static role reopens its own source-list/full-GET evidence. Keep source/image,
   expected-response, UDP payload and chaff requirements in both branches.
3. Add a separately versioned enrollment authority for static terminals. Current
   rolling enrollment explicitly reopens `rapid_site_admission` browser terminal
   and preparation; a bare imported manifest cannot satisfy that API.
4. Use existing current named 120-response chaff qualification on the newly
   qualified static workload. Existing qualification calls research validation,
   so the role union must be complete before invoking it. Fixed traffic settings
   and per-setting canary readiness remain separate from cohort discovery.
5. Start one-to-five-class recoverable lanes through existing ordinary deep
   verification. Final closure still requires 50 × five × 64 unique slots.

There is no Native defence-algorithm change in this design. This is also not an
all-source cache waiver: record old runtime versus new authority accurately and
compare relevant byte-bound dependencies when using established readiness.

## Reach 50 and handle existing evidence honestly

The 23 promising curated cross-origin graphs cannot establish 50 classes.
Continue the fixed candidate order for the remaining supplied lists and retain
every failure. Use the frozen catalogue for further domains, but it contains
domains, not full static graphs. Additional classes need a frozen complete
resource list from a declared source: newly supplied lists or successfully
discovered full browser graphs with an explicit conversion record. A homepage
root by itself is insufficient for a multi-origin class. Do not invent a CDN
resource or choose just working resources from a failed list.

Prospective candidate priority may use controlled root support and available
nonempty lists if declared before new measurements; it changes the sampling
claim and must disclose the full assessed pool and all deferrals. Root support
does not grant graph eligibility. Complete-list HTTP/3 incompatibility can still
prevent reaching 50; the present evidence cannot guarantee a yield or deadline.

For rollout, prefer a **new fixed-resource replay cohort** and keep the earlier
eight browser-role formal traces separately auditable. An optional mixed-role
study would require a prospective amendment describing both roles, per-class
labels and role-specific claims; it cannot relabel browser traces as supplied
static traces or silently pool incompatible claims. Existing accepted visits
would count only if that explicit final-corpus contract and ordinary closure
permit them. No old terminal, failed sample or diagnostic is promoted.
