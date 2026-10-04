# Prepared response budgets for sustained qualification

The prospective `qcsd-prepared-budget-response-qualification-v1` sidecar
(schema 3) and `qcsd-prepared-budget-response-qualification-set-v1` named set
(schema 1) use `response_budget_qualification.py`. Historical sidecars, named
sets, defaults and GET producer source maps retain their original meaning.

The caller explicitly supplies `max_response_bytes`: 16,777,216 for an
ordinary static preparation or 67,108,864 for a prospective budget preparation.
The complete validated preparation must declare the same value. The policy
marker is `prepared-resource-response-budget-v1`; every existing Native epoch
receipt must report exactly that cap. Each candidate still needs three fresh
epochs, 40 complete identity responses per epoch, five parallel requests,
30-second epoch spacing and the unchanged directional UDP limits.

The sidecar binds the new qualifier module hash, unchanged historical qualifier
module hash, current implementation receipt, clean Source, immutable image and
client provenance. The derived Native chaff manifest remains schema 4; its
complete body identity comes from the 120 responses. A larger cap provides no
authority for a truncated body, changed identity, infrastructure error, browser
success, challenge absence or a historical partial response.

The public CLI accepts `qualify-response-chaff --max-response-bytes BYTES`.
Omitting the option invokes the unchanged historical 1 MiB qualifier. The
portable serial flight passes its already validated `capture_limits` value.
Serial campaign loading, frozen-input loading, readiness and rolling planning
select the new reader by the exact artifact type. Historical class pipelines,
full-chaff qualification and parallel scheduling retain their old contracts;
this change grants no new parallel authority.

Publish and install a fresh Lab Source epoch with the existing Native client,
then use a fresh affected flight and qualification namespace. Existing failed
qualification evidence and other pinned epochs remain immutable. HOST tests
use controlled complete epoch receipts and an explicitly bound optional actual
prepared-input fixture; they do not claim installed qualification or capture.
