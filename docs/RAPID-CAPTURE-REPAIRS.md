# Targeted repairs before the rapid capture study

The target remains **50 sites × five conditions × 64 visits = 16,000 accepted
formal traces**. This document explains the repairs prompted by the first
five-condition diagnostic on Poki. The original failed attempts remain failed;
new source needs new captures. See the [capture path](RAPID-CAPTURE-PATH.md) and
[evidence index](EVIDENCE-INDEX.md) for the recorded operations.

## Current Python repairs: 6 October 2026

### Installed package paths and Native receipt shape

The fresh v29 canary passed all ten steps and the next two-worker preparation
passed in 5 minutes 12 seconds. The guardian's authenticated startup also
completed. Installed preflight then failed before worker birth because the
target scheduler hashed CLI sources during import and inferred their locations
from the installed package parent. CLI files live in the explicitly bound
Source checkout. The repair must keep import-time declarations independent of
filesystem layout, while checking actual imported Python bytes and the exact
CLI files from the declared runtime Source during authority validation.

A cheap review of the later BuFLO path caught another defect before a long run:
[its duration validator](../src/qcsd_lab/buflo_duration_budget.py) expected the
method field to contain the defense name. Actual Native receipts use HTTP `GET`;
the defense is separately bound by the resolved configuration and parameter
provenance. The corrected validator and fixtures preserve those checks.
The failed v29 batch remains failed and adds no formal recordings.

The newly planned FRONT setting is reserve V4: a 10,000 microsecond release
window, 9,000 microsecond construction window and 1,000 microsecond preparation
reserve, with its declared 10% bound on pure outgoing padding omissions. The
four historical V3 recordings cannot count under V4. Tamaraw8192 and BuFLO200
also require their exact prospective settings; complete resource graphs and
original per-class budgets remain bound throughout.

### Earlier guardian and selected-input repairs

The v28 parallel batch passed preparation in 5 minutes 11 seconds, then failed
before either worker started. Its guardian's 30-second READY check indirectly
called the complete capture-spec parser, which repeats scientific evidence
checks. The new early parser checks only the sealed schema, paths and runtime
identities. Full graph, scheduling, qualification and lane checks remain after
the handshake and before worker creation. The two actual worker bindings parsed
in 0.45 seconds; this small host check grants no capture authority.

Two further Python changes prepare the other declared conditions. BuFLO's
fixed-target two-worker plan now selects its explicit duration-200 traffic files
through the same validated target authority as the serial plan. Tamaraw and
CS-BuFLO can revalidate a retained complete selected GET for a fresh current
flight, preserving every original resource, admission terminal and capture cap.
They cannot borrow ordinary-only qualification or another defense's practice.

The combined changes passed **68 focused HOST checks**, with no failures,
errors or skipped cases. The verified `c24da2af` Native client remains unchanged;
these repairs require cached Python packaging rather than client compilation.
Actual installed repeats, successful two-worker capture and independent deep
verification are still pending. Keep the failed v28 batch and its exact Source
unchanged. Use a fresh batch for the next actual attempt.

For a fresh Tamaraw or CS-BuFLO selected-class flight, the public staging option
is `--renew-selected-inputs`. Tamaraw also requires its existing explicit
`--tamaraw-configuration-policy`; this option cannot authorize another mode.
Finalization binds `selected_input_renewal` into the practice plan and its
`--selected-input-renewal` reference into formal planning. Qualification, full
practice capture and independent verification remain condition-specific.

## Earlier prospective repairs: 4 October 2026

The combined Native source is `5f075d37`. Its offline build and **45 focused
compiled tests passed**: 31 FRONT and 14 BuFLO cases. The matching Lab source,
including the parallel startup repair, passed **117 focused host checks**.
These are source checks. Matching installation and successful live repeats
are still required, and they add no formal recordings by themselves.

### FRONT: act on a due packet and retain its actual incoming evidence

One full-page diagnostic reached a padding socket 119 microseconds after
its deadline. The packet had been built with about 14 microseconds left.
After handling action input, the V3 runner now immediately processes one
due, fixed, outgoing padding packet through the existing socket path.
Its actual socket timestamp still decides whether it met the deadline.

Another visit completed the page but two incoming cells lacked their
recorded delivery times. The repair retains exact consumed stream ranges
before the controller removes a completed stream. It reconciles them with
the original successful physical receives; it cannot substitute a later
observation or use missing, overlapping or future ranges as delivery proof.
The declared V3 10 ms outgoing padding window and 10% omission limit stay
the same. Repeat both failing seeds on the complete page before admission
to a new formal FRONT lane.

### BuFLO: permit preparation while the actual release is still ahead

The latest live attempt entered preparation 3.7 ms after the nominal
selection time, but 1.3 ms before the actual send release. The entry rule
rejected it. All 242 packets previously sent in that attempt had physical
timestamps within their required windows; the incomplete attempt remains
failed and earns no formal credit.

The new preparation rule permits immediate entry between selection and
release, recording its real lateness, one initial clock read and zero active
wait. It still rejects entry at or after release. Fresh dispatch and staging
checks must remain before release, and clock regression remains fatal.
Outgoing physical deadlines stay at 5 ms and the explicit incoming tolerance
stays at 10 ms. This is a declared client-only adaptation with a potentially
shorter preparation wait; describe that choice in the thesis.

New receipts use raw kernel schema 11, wakeup schema 20 and protected-wait
schema 2. Historical schema 10/19/1 receipts retain their original checks.
The earlier 3.218 ms backward-clock failure remains preserved and unresolved;
this preparation repair does not establish or change its cause.

### Parallel startup: announce the guardian handshake before long checks

The protected child previously repeated costly scientific checks before
announcing READY to a guardian that waited only 30 seconds. The new ordering
authenticates the sealed lifecycle inputs, completes the guardian handshake,
then performs the full scientific checks before worker launch. The original
READY and recovery deadlines remain unchanged. The control-only Source0e
runtime passed all twelve installation operations, reusing its original
verified Native841 client. Actual simultaneous capture and failed-worker
recovery remain to be demonstrated.

## What failed and what changed

| Problem observed | Repair | What must still be checked live |
|---|---|---|
| The prepared homepage body was 58,478 bytes; some complete later responses were shorter. The client advertised credit using the old body estimate, then retired unused credit when the response ended. BuFLO and CS-BuFLO correctly rejected those incomplete cells. | For the explicitly declared variable primary document, start with a one-byte positive floor and learn the actual HTTP/3 frame extents. A due incoming cell may own a retained parser continuation of at most 16 bytes, committed together with the rest of that whole cell. Other resources retain their exact prepared identities. | Fresh complete responses of different sizes, all resources and origins, full incoming cells, and no retired or unresolved scheduled credit. |
| An unlogged incoming packet on one finished connection appeared before the final packet on another connection. The old capture rule rejected it because it considered only the last packet across all connections. The retained old files do not prove when polling stopped. | Record each endpoint's actual final UDP drain time in the client. Attribute captured packets by the full IP/port tuple. Permit an extra incoming packet only after that endpoint's last matched packet and at or after its explicit final drain time. | Exact Native/PCAP matching, stable paired host clocks, fresh final-drain receipts and independent replay of the actual PCAP. No unlogged outgoing packets are permitted. |
| One complete BuFLO attempt delivered all 260 resources and 969 cells but exceeded the old incoming 5 ms window twice, reaching 6.099 ms. | Add an explicit prospective **10 ms incoming credit tolerance**, half the unchanged 20 ms period. Keep the actual lateness measurements and the number of violations under the original 5 ms rule. | Fresh opted-in BuFLO captures must satisfy the selected window, full-cell accounting, terminal delivery and outgoing timing checks. |

The parser repair preserves failure when already advertised credit goes unused
at FIN, when a deadline expires, or when the allocator cannot form a complete
cell. It does not turn an incomplete response into a complete one.

## The BuFLO policy is opt-in

A newly frozen prepared workload selects the policy with:

```json
{
  "preparation": {
    "buflo_incoming_credit_release_policy": "rapid-v5-half-period-10000us-v1"
  }
}
```

This is an excerpt, not a complete workload. It also requires the existing
variable-primary-document and completed-terminal-response contracts. The
client emits a matching source-bound receipt only for BuFLO with **1,200-byte
cells, a 20,000 µs period and the unchanged 5,000 µs Native control interval**.
Missing flags retain the historical 5 ms acceptance rule. Null, unknown,
unbound and conflicting policy or mode receipts reject.

The change applies to incoming credit timing only. Outgoing kernel transmit
deadlines, cadence, cell sizes, complete delivery, graph coverage and response
identity checks still apply. Describe this as a client-only QUIC adaptation
with an explicit incoming timing tolerance when reporting the thesis results.

## Portable independent capture checking

New captures retain endpoint IDs and absolute PCAP timestamps in the temporary
observer trace. Deep verification reconstructs those rows from the sealed PCAP
and Native endpoint tuples, then independently repeats reconciliation.

If the host has no TShark, the verifier runs one offline tool container per
result using that result's immutable image digest. It mounts the result and
the current verifier source read-only and explicitly imports that source. The
image supplies TShark and dependencies; this is not evidence that the current
verifier was installed in an older image. Host seal and frozen-input checks
still run on the host. Historical results without prospective markers retain
their original interpretation.

## Next live check

1. Build the changed client from clean source using the existing cache, and
   verify the installed source and executable bytes.
2. Freeze a fresh diagnostic workload and plan before making live requests.
   Reopen the previous admission under its original context for lineage; do
   not present its receipts as current-runtime admission.
3. Qualify the padding response against the new exact workload and runtime.
4. Repeat the affected settings on the complete graph. Reuse an unaffected
   setting only through the declared dependency checks. Diagnose each failing
   condition immediately and retain every attempt.
5. Deep-verify the fresh results and publish readiness separately for each
   passing setting. Start its next rolling formal lane while other settings
   and site screening continue under their own recorded inputs.

Focused unit and regression tests establish engineering behavior. Installed
byte checks, synthetic 16,000-slot fixtures and additional diagnostic captures
do not count toward the study's **16,000 formal traces**. The active rolling
v6 route does not require all 50 sites or a ten-site shakedown before the next
ready setting starts capture.

## Recovery when no capture worker was created

Some parallel attempts stopped during host startup after claiming lane names,
before creating a capture worker. Their lane directories contain an intent
and lineage, but no worker start record. They need a distinct retirement
record before the existing generation-two recovery can use those sample
slots. A host exit code alone does not prove that no worker ran.

The prospective V4 control contract supports this case through the public
`retire-lane` command, with `--batch-authority`, `--batch-output`,
`--public-started` and `--public-completed`. It verifies the exact original
failed batch, its actual invocation and retained logs, and the reviewed
launcher whose durable preflight precedes worker creation. It rejects a batch
with preflight, worker, result or completion evidence. Under the existing
locks it also requires fresh absence of the original host processes, guardian
sockets, lifecycle ownership and owned Docker containers and networks.

This retirement grants **zero scientific credit**. It preserves the failed
attempt and allows only the existing successor mechanism to retry its slots.
Historical V1–V3 contracts and the final 50 × five × 64 accounting retain
their previous interpretation. The change passed **101 focused and affected
host checks** on the current Native5f source and independent review. Actual
retirement of a failed batch remains a separate operation after live capture
and lifecycle cleanup finish.

- [Retirement implementation](../src/qcsd_lab/rapid_lane_evidence.py)
- [Public rolling command](../tools/rapid_rolling_capture.py)
- [Preflight absence and recovery regressions](../tests/test_rapid_prebirth_retirement.py)

### Reviewed current launcher and verifier limits

The current complete `qcsd-lab` launcher has SHA-256
`35d443b9f092bf8c55137ca7730723c8f542a9b7899889c5e649d90a658885dd`.
Its formal parallel entry validates the full authority, executes the offline
image preflight and durably writes `image-preflight.json`. Initialization
reopens that preflight before allocating either lane's result namespace and
writing `batch-intent.json`. It then closes release preparation before the
first Docker network, router or capture worker is created. The retirement
validator explicitly reviews these complete bytes; matching text in an
arbitrary launcher cannot authorize recovery. The Python operator has its own
original implementation hash and exact recorded nine-argument invocation.

Adding this reviewed launcher does not relax the required failed public
invocation, absent preflight and workers, retained zero-credit records, or
fresh locked process, guardian, ownership and Docker census. Existing failed
batches contain no separately authenticated protocol declaration that could
replace the complete launcher review retrospectively.

The ordinary input layout first authenticates its declared `control_sources`
against the actual imported modules. The existing ordinary parallel contract
also compares each imported control module with its original installed and
frozen Source, including `rapid_lane_evidence.py`. A changed verifier imported
into that contract is therefore rejected before lane retirement, even if the
historical execution checkout is untouched. This whitelist repair alone does not authorize using
a changed external verifier for an existing ordinary batch. Historical Source,
plans and image proofs must remain unchanged; an external recovery observer
would need its own explicit binding while retaining the original scientific
validators. This change supplies no such additional authority and requires
no physical requalification on its own.

## Source

- [Capture policy validation](../src/qcsd_lab/capture_acceptance_policy.py)
- [Endpoint extraction](../src/qcsd_lab/capture.py)
- [Timing and reconciliation](../src/qcsd_lab/fidelity.py)
- [Independent deep verification](../src/qcsd_lab/verification.py)
- [Policy and boundary regressions](../tests/test_capture_acceptance_policy.py)
- [Endpoint tail regressions](../tests/test_endpoint_receive_tail.py)
- [PCAP replay and portable transport regressions](../tests/test_endpoint_capture_replay.py)
- [Collector runtime repair epochs](RAPID-RUNTIME-REPAIR.md)
