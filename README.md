# QCSD lab

Documentation audit: 2026-09-08, Australia/Sydney (AEST, UTC+10)

This repository is the experiment orchestrator for the QCSD Neqo fork. It has
one workflow: freeze a workload, expand a campaign into sequential samples,
capture each Neqo run directly, seal the evidence, and derive plots and a
report afterwards.

The lab does not maintain a second data-processing workflow. A workload is
simply a frozen graph of HTTPS requests. A visit is one execution of that
graph. A sample is one visit under one defence.

The capture specification does not train a classifier or define an open-world
corpus. Fitting and evaluation are separate campaigns over independent visits
of the same frozen workload definitions. A separate offline companion packages
complete sealed results for a five-class closed-world proof of concept; that
export does not make the five fixed domains a representative website
population or evaluate an attacker retrained on defended traffic.

Docker is required for every public command. The Neqo source is the
`neqo-qcsd/` Git submodule.

## Commands

The capture surface is deliberately limited to the `qcsd-lab` forms documented
below. The classifier handoff exporter is a separate offline tool so adding or
changing it cannot alter the implementation receipt already bound by the
qualified defences.

### BuFLO/CS-BuFLO candidate study

`buflo` and `cs-buflo` are client-only QUIC adaptations. They use ordinary
HTTP/3 servers and standard QUIC traffic; they are not bilateral or
paper-equivalent implementations. Until a typed
class-study `validation-attestation.json` independently verifies every gate,
the project status is **five validated defences plus two candidates / nine
selectable modes**, including the `undefended` and `static` controls.

The BuFLO adaptation drains every allocatable 1,200-byte reviewed-chaff cell
after the inclusive ten-second minimum. It now separates schedule stop from
final drain completion: required STREAM work, unconfirmed application sends,
unadvertised credit, parser work, and due controller identities keep the
schedule open, while already-advertised RTT-delayed `MAX_STREAM_DATA` is drain
debt and cannot authorise a replacement cell. All outgoing cells are terminal
at stop; previously advertised incoming credit may be consumed later and must
still reconcile exactly. If only a sub-cell response tail remains, final
completion latches only after all scheduled work and parser leases are
terminal and every pending application parser boundary has cleared. Pending
reviewed-chaff parser boundaries are counted and cancelled with their streams by
standard client-local HTTP/3 cancellation. The resulting unscheduled
defence-control traffic is explicitly receipted and is an expected QCSD-only
difference from the bilateral TCP study; it is never described as
paper-equivalent or as a server padding-complete signal.

The current implementation targets BuFLO summary schema 4, runner-wakeup
schema 11 with nested kernel runner/item/mapping schema 2, and timing-stress
parameter/provenance, execution, and checkpoint schema 4. These are interface
requirements, not evidence of successful execution. Immutable cohort v57
passed build/reference for its historical parent source but admitted no timing
sample after the schema-3 runner rejected global TAI-minus-MONOTONIC drift.
V58 subsequently bound the item-local clock-evidence repair through a clean
build and isolated reference run, but it predates the mandatory pinned-CDP
producer and cannot be completed under the strengthened foundation contract.
V59 then completed a fresh pull/no-cache three-image build for clean Lab
`2cbbb61a59ad8011f2948919c14c3316ed3772a9` and unchanged Rust/gitlink
`ce0d7a21756ce795d6f50d750a1c25e0fa006327`; its build receipt has whole-file
SHA-256 `f8db5c8f0821a1b080135b130c82c78d2b4a930baf5c88d28870225b7b223590`.
It has no browser-egress, pinned-CDP, reference, timing, regression, code,
controlled, or class-study receipt. The Playwright/CDP and browser-supply
hardening documented below postdates that build, so v59 cannot authorise
current source. V60 attempted its build from exact clean Lab
`a20382c658857ca0362fcf877559c8e3320ac376` and the same Rust/gitlink, but
failed before any Docker layer, image IID, or receipt while resolving the
pinned Dockerfile frontend. V60 is consumed and non-evidentiary. Committed Lab
foundation checkpoint `e719219b42826126fdc7771c2dec0463d425a83d` historically
repaired that Docker-configuration boundary. Its clean successor
`69a14ebe48f78d08a8b36d3e573955ec64f00ff9` commits the schema-4 Buildx receipt
integration against the unchanged Rust/gitlink. Clean documentation head
`9d53e08f95c5130c60aadbef8a99273a44d117b5` then exercised that exact
implementation as v61. Buildx record `ubc8xesmc26eep5nywsgg9hiq` failed after
approximately one second during its two-step, zero-cache pinned-Dockerfile-
frontend resolution with
`open /proc/1182923/fd/9/.token_seed.lock: no such file or directory`, before
any Docker layer. No v61 image, IID, schema-4 build receipt, reference receipt,
or later gate exists; static v59 image tags remain exact. V61 is consumed and
non-evidentiary. On 7 September its exact failed build and transaction records
were moved intact to the recoverable audit directory
`/var/tmp/qcsd-v61-retired-audit-1000.v970xxes`; the active lifecycle namespace
is now empty. The archived `RECOVERY` record still truthfully describes the
failed process state as unresolved, so this operational retirement is not
scientific evidence and advances no gate.

The clean post-v61 Lab implementation checkpoint is
`c55b08aa06fbb4ac16e3655d6d3911109d853730`; clean documentation head
`2d96c924e653aa45ffef5964ff216ba6307cbb0c` exercised it with unchanged clean
Rust/gitlink `ce0d7a21756ce795d6f50d750a1c25e0fa006327`. It combines the linked-config
repair with build-execution schema 5, the separate build-completion schema-1
success boundary, dense cohort-allocation authority, host-side build-carrier
admission, completion-bound downstream schemas, the pinned-CDP browser-session
repair, post-`setsid()` exact-command binding, lifecycle signal/admission
linearisation, and exact post-transfer API-service exit classification. The
config remains mode
`0500`, link-count two, and stable beside the lifecycle lock only for its
individual active build lease; it is not a persistent linked host config
between leases. Its name binds the invoking UID, guardian start time and nonce,
and cleanup conservatively censuses separately retained crash residues. The
exact committed source passed
`4424 passed, 16 skipped, 26 warnings in 4975.41s (1:22:55)`. These are
engineering checks, not campaign
evidence. V62 then claimed those exact heads. Its claim and consumed-claim
records are byte-identical, with SHA-256
`c459e8bfac1edc0adf8a200dbb924841e39182e4f1f22e0b9e93a15bb117d62a`.
The checked-in genesis consumed ledger remains the dense prefix v1–v61, with
SHA-256
`32c44e09f536d4cf4e3d8586fc1a5ed2d5cc7cb8fe11e92c60378042488690ad`;
the durable claim nevertheless consumes v62.

V62's zero-cache collection-role build completed as Buildx record
`lqrgsctuz9ff4eu7qbaikxtql` and exported the unreceipted provisional collection
image
`sha256:dc03f05b4faeb3c94973674e3ffda8f87d65fe7a2cdc6122525ea5847cf34211`.
The mandatory `before-prepare` PowerShell backing-volume probe then failed
closed with WSL `UtilAcceptVsock: accept4 failed 110`; contemporaneous kernel
evidence recorded an order-7 allocation failure in
`vmbus_alloc_ring`/`hvs_probe`. No preparation or reference image was built,
and no build-execution, build-completion, reference, or later receipt exists.
The failed transaction is archived intact below
`/var/tmp/qcsd-v62-retired-audit-1000.9HxJv9LV`; its `SUPERVISION` record has
SHA-256
`b0cb14049b52612d331f95e3d4eb253034fdabf8002c15bae9c676d7ec6ce0bb`.
`lifecycle-recover` passes and the active lifecycle namespace is empty.

A later exact backing-volume probe at `2026-09-08T11:43:52Z` passed with one
`Healthy`/`OK` NTFS volume and 323,819,671,552 available bytes. Docker was
healthy with zero running and 11 stopped containers. That operational recovery
cannot retroactively complete v62 or make its provisional image evidentiary.
V63 subsequently claimed exact clean Lab
`d2ff0f6bc439675ab016c94770015456890020ae` and unchanged Rust/gitlink
`ce0d7a21756ce795d6f50d750a1c25e0fa006327`. Its byte-identical durable claim
records have SHA-256
`b4132a9cd750d3436794b1a345394aab3ffd4c39b3a882061115340bac760d34`.
The pull/no-cache collection build completed all 61 stages as Buildx record
`1pmsiyt5ei9ecu40m3m7vd2n5` and exported provisional image
`sha256:67f901a46fea3528a5aef5b6581e4161fd8d42fa697b26ee44a5df493d024c83`.
Buildx completed at `2026-09-08T22:08:33.147923+10:00`; the mandatory
`before-prepare` PowerShell probe then failed by approximately 22:08:39 with
WSL `UtilAcceptVsock:271: accept4 failed 110`, against a contemporaneous
order-7 `vmbus_alloc_ring`/`hvs_probe` allocation failure first explicitly
logged at approximately 22:08:21.9. No preparation or reference
image, build-execution/completion receipt, or later gate exists. The abandoned
transaction is archived intact at
`/var/tmp/qcsd-v63-retired-audit-1000.walSThtT`; its `SUPERVISION` record has
SHA-256
`86bab71f40ec6739b4d84392f2bd0091579113f13016ad6a665fb0efea24c54a`.
`lifecycle-recover` passes and the active lifecycle namespace is empty. V63 is
consumed and non-evidentiary.

After a clean Docker Desktop/WSL restart and repeated exact host-health checks,
v64 claimed clean Lab `81dd702affed4066322faa21ff27f3c7b842ed6b` and unchanged
Rust/gitlink `ce0d7a21756ce795d6f50d750a1c25e0fa006327`. Its byte-identical
claim and consumed-claim records have SHA-256
`fa3af0eb119e791a8ec49d010fe695dd5506bcee3dba2de4f6cd95e3cab0850f`.
The pull/no-cache transaction completed all three roles and published the
schema-5 build receipt with SHA-256
`c50238b3304017dff3cc25a42bfdb3be2f11095a4c6ee6cbe76358c2d7e8c856`
and the schema-1 completion receipt with SHA-256
`8cc62d21c6f0409e12c163d6864cd9aee4156a7866870bad487aced8dcca2ecf`.
The exact collection, preparation, and isolated-reference image IDs are,
respectively,
`sha256:794e9696f48aef21a4eb1087502a0fcb7b61374efa4eeb99d82c90fccf0d3ccb`,
`sha256:368babba9e51251a5ac7b9adea22f10eb088bbd459cc539eae9a40a57f7f1933`,
and
`sha256:33c629712b93e1242142e9a9f97c0fb0b5e03ca31a459b5c08d850666b729ad9`.

The ensuing pinned-CDP launch used that exact preparation image and the
correct managed-policy input, but failed before it could publish a receipt.
Dockerfile `COPY --chmod=0444` had auto-created missing policy parent
directories with mode `0444`, leaving them without a search bit. Clean Lab
implementation checkpoint `18d4ab3144e04f0a012ffcba54d349b4046c4336`
explicitly creates every such
directory as root-owned mode `0555` before the copies and makes the runtime
validator reject any directory with no search bit. The 66/66 targeted tests
pass. This is source-only engineering evidence: it postdates v64 and cannot
repair that cohort. V64 has no pinned-CDP or later receipt; every downstream
scientific counter remains zero.

V65 then claimed exact clean Lab
`9a6a45c9d3adfa1b5d5dacd6c51b08440c07bde6` and unchanged Rust/gitlink
`ce0d7a21756ce795d6f50d750a1c25e0fa006327`. Its byte-identical claim and
consumed-claim records have SHA-256
`677be940a0b5af13ede0f13cd83267b9202d115924c298f23e4b3dcecb9b2ad2`.
The collection image was exported after its embedded Rust tests and strict
Clippy passed. The transaction then failed closed at the
`immediately-before-prepare-build` source reproof: a concurrent documentation
audit's `git status` had refreshed Git metadata sealed at allocation. No
schema-5 build-execution or schema-1 completion receipt was published, and the
unreceipted collection image cannot be used. V65 is consumed and
non-evidentiary; it produced no pinned-CDP receipt or capture and advances no
downstream counter.

V66 then launched from Lab
`d73ee3f67d9c001e5d4abcad64d6f9497ee73ef9` and unchanged Rust/gitlink
`ce0d7a21756ce795d6f50d750a1c25e0fa006327`. It durably published a
byte-identical 7,859-byte claim and consumed-claim pair with SHA-256
`b342cde610ae802c1e12c3ea4b8a4d85daf0dd66e7785c0c2de12b7327d795b4`,
then lifecycle admission failed closed on v65's intact uncommitted static-tag
transaction before any v66 Docker build began. No v66 build-execution,
build-completion, pinned-CDP, or downstream receipt exists.

An exact audit retained the same host boot and Docker daemon identities and
found zero running containers, QCSD Docker objects, build processes, or build
scopes; both v65 build receipts remained absent. The v65 transaction record,
with SHA-256
`36f1bfac0e328197e799bcb4bb756e0733a6b723f1123944ea80083d656729b8`,
was preserved at
`/var/tmp/qcsd-v65-retired-audit-1000.mGz0IvTU`. The active lifecycle
namespace is empty and `lifecycle-recover` passes. This is operational
retirement, not scientific evidence. V66 is consumed and non-evidentiary; v67
is the exact next allocator-authorised cohort and must obtain a fresh
build/completion pair.

Summary schema 4 binds the typed schedule-stop policy, stop timestamp,
sub-cell capacity, direction counts at stop, and exact post-stop advertised
credit drain; historical summary schemas 2 and 3 remain readable but cannot
admit a fresh candidate capture. Historical runner-wakeup schemas 1–10 remain
readable for their pinned source cohorts but cannot admit a fresh candidate
capture; an apparent current-source downgrade is rejected. Schema 7 retains
schema 6's complete metric inventory, including BuFLO exact-incoming retry drives,
resolutions, maximum wake lateness, and callback, quarter-phase, and terminal-
deadline wake-up semantics. Their retained semantics suffix is exactly
`buflo_exact_incoming_retry_wakeups=transport_callback_or_1/4,1/2,3/4,deadline; buflo_exact_incoming_retry_drives=count_owner_endpoint_output_drive_invocations_including_immediate_and_error; buflo_exact_incoming_retry_resolutions=count_drive_invocations_clearing_at_least_one_captured_identity; buflo_exact_incoming_retry_max_wake_lateness_includes_terminal_deadline=true; buflo_exact_incoming_inventory=all_unrealized_slot_owned_adapter_identities_with_same_tick_refresh; buflo_exact_incoming_expiry=one_logical_slot_one_deadline_miss`.
Consequently, maximum wake lateness may be nonzero even when there were no
owner-endpoint drive invocations: the terminal deadline is itself measured.
Schema 7 additionally distinguishes nominal controller timestamps from the
adapter's ceil-normalised not-before instant and floor-normalised deadline,
binds aligned 5 ms and fractional 4.999 ms strict windows, and records the
worst guard's relative entry, release, exit, and deadline instants. It retains
the configured 10,000-microsecond maximum lead fields. The actual admission,
guard, and active-wait boundary is two adapter windows before release—10 ms
for aligned windows and 9.998 ms for fractional windows—and the three remain
coincident. Schema 8 preserves that exact
field inventory and timing contract while appending the immutable semantics
`buflo_exact_release_active_wait_poll=poll_instant_without_arch_spin_hint`.
Schema 9 keeps ordinary-output admission two actual adapter windows before
release but separates it from a one-window release guard and active-wait tail.
Those boundaries are 10 ms and 5 ms for aligned windows, or 9.998 ms and
4.999 ms for fractional windows. On Linux AArch64, the
active wait uses `CNTVCT_EL0` only as a predictive counter: each counter target
is ceil-rounded, each calibration brackets one authoritative `Instant`, and
an authoritative `Instant` confirmation prevents an early dispatch. The
iteration counter covers every ordered, relaxed, unavailable, or fallback
authoritative poll; a predictive calibration therefore accounts for at least
two reads. Successful dispatches have exactly one calibration and confirmation
for the final attempt plus one of each for every early confirmation retry. A
counter regression is a hard failure. Guard dispatch begins at or after the
guard/active-wait boundary, so schema-9 guard receipts contain no passive-sleep
phase and their guard-wait and active-wait totals are identical. Other
platforms use an authoritative-`Instant` fallback. The accepted counter-
frequency range is the inclusive
1,000,000–4,294,967,295 Hz interval; an in-run frequency change fails before
transport dispatch and before any success-metric mutation. Schema 9 partitions
every entered guard into `dispatch-ready` or one of five typed terminal counter
failures: invalid frequency, unavailable counter, non-monotonic counter,
frequency change, or target-calculation error. Dispatch-ready guards alone
populate dispatch-lateness and worst-success evidence; every guard populates
the active-gap evidence. A failure retains its authoritative exit chronology,
counter state, and a null dispatch timestamp in `buflo_exact_release_last_failure`.
The unavailable-counter outcome is a scripted clock-trait failure, not a
recoverable architectural-trap receipt, and target-calculation error is a
defensive-unreachable branch for a valid live guard and accepted frequency.
Production counter access is therefore checked by the target-gated live smoke
test rather than inferred from either defensive outcome.

For historical schema 10, let `W = deadline − release`, where `W` is 5 ms
for aligned adapter windows and 4.999 ms for fractional windows. Ordinary-output admission
is `release − 2W` (10 ms or 9.998 ms before release); guard entry and active
waiting begin at `release − W`; and the strict physical-realisation interval is
`[release, release + W)`. Schema 10 preserves that geometry and the no-catch-up
rule. On Linux AArch64 it adds an
authoritative `Instant` watchdog after every 64 successful relaxed
`CNTVCT_EL0` reads. The virtual counter remains predictive only: a watchdog
that observes release can nominate dispatch, but the existing fresh
authoritative transport check still rejects any instant at or after the
deadline. Receipts count watchdog checks and watchdog-selected dispatches and
retain maximum authoritative-sample gap, authoritative-over-counter lag, and
counter-over-authoritative lead in the aggregate, worst-success guard, and
typed last-failure projections. The serialized
`buflo_exact_release_active_wait_authoritative_watchdog_cadence_validated_guards`
count records each dispatch-ready production guard whose own
`checks_i = floor(R_i/64)`, where `R_i` is that guard's successful relaxed-read
count after ordered calibration reads. Fresh accepted timing-stress evidence
requires that count to equal all guarded releases. A zero-failure aggregate
enforces `64×checks ≤ R < 64×(checks+guards)`, the per-guard dispatch-residue
capacity, and the exact calibration/retry partition; it does not incorrectly
take one floor after concatenating every guard's residual reads. Calibration
and final-confirmation `Instant` samples are additional authoritative samples;
the 64-read cadence applies specifically to successful relaxed `CNTVCT_EL0`
reads.

Every schema-10 integer scalar and histogram count, and every present nested
timestamp, is confined to the Rust `u64` domain. Structural count partitions,
watchdog/read products, and chronology use checked arithmetic and reject
overflow. Where the producer
defines a saturating aggregate, nested-pair and residual validation applies that
behaviour explicitly. The schema-10-to-schema-9 projection removes additive
watchdog fields and maps the production poll-source tag; among retained numeric
identities, it normalises only cumulative wake totals and histogram totals
needed to reconstruct the frozen schema-9 relationships. Saturation is not a
general exception to the other exact partitions.
The retained worst-success guard must satisfy
`active_duration = W + dispatch_lateness − guard_entry_lateness` for one of the
two exact window widths. The typed last-failure record includes exact
iterations, active duration, interruption count/duration, and maximum gap. With
`X = guard_entry_lateness + active_duration`, it must satisfy
`exit_before_release = max(W − X, 0)` and
`exit_at_or_after_deadline = (X ≥ 2W)` even when relative timestamps are
nullable; available timestamps additionally require active duration to equal
exit minus active-wait start.

A sole success/failure pair must reproduce the aggregate's saturating sums,
maxima, and exact two-row histogram. For a mixed aggregate, validation subtracts
the retained worst and, when present, failure records, then checks the remaining
success guards' read/cadence, interruption, counter/active-duration, and
histogram budgets. The claimed maximum must occupy its histogram bucket with no
occupied higher bucket. If `A` is the interruption count, `H` is the number of guard
maxima above 50 µs, and `G` is the histogram-derived duration floor including
the exact maximum, interruption duration is at least
`G + (A − H)×50,001 ns`; residual histograms and dispatch-lateness buckets also
lower-bound the hidden guards' interruption and active durations. Failure
cadence separately accounts for terminal counter reads, and every early
confirmation retry requires a successful relaxed read. The authoritative-
`Instant` fallback carries zero predictive/watchdog/divergence evidence, while
zero BuFLO incoming retry drives requires zero maximum retry-wake lateness.

Aggregate entry lateness is bounded by the retained failure entry or
`5,000,000 ns + maximum dispatch lateness`. Aggregate active-wait time is
bounded by exact retained durations plus that per-success ceiling for each
unretained success, subtracting an unretained owner of the aggregate entry
maximum before one final `u64` clamp. If the per-success addition itself
overflows, the lost headroom makes `u64::MAX` the conservative ceiling.
Active-derived maxima—spin gap, counter gap, calibration span, authoritative
sample gap, and authoritative counter lag—must be reachable from their exact
retained per-metric values or one unretained-success ceiling. A non-zero
at-or-after-deadline count requires maximum dispatch lateness of at least
4,999,000 ns, and every successful guard's actual adapter window is exactly
4,999,000 or 5,000,000 ns. Exact top-level and nested key sets, canonical
string-valued poll sources/phases/failure outcomes, all-present-or-all-null
counter and chronology tuples, the exact empty projection, and positive
counter progress for every early-confirmation retry all fail closed. The
byte-identical Rust/Python schema-10 semantics string is 7,837 bytes with
SHA-256
`fc86adeb78f468c2e01acc55324c561368664991d091e5ab86bb913374f7e0ae`;
the immutable schema-9 semantics hash remains
`6ab6713bde70c803a7f243432277edda4f6b850d732c9246f88413e61f487503`.

V47 exercised schema 10 at clean Lab `236da73c…` / Rust `ba72df21…`. Its fresh
build and isolated reference execution passed, but its first and sole mandatory
timing-stress launch failed terminally. At 70.600 seconds, outgoing slot 7060
was dispatched 5,133,680 ns after release and 134,680 ns after its strict
deadline; paired incoming slot 7061 missed and retired 1,200 scheduled-credit
bytes. V47 is therefore immutable historical evidence, not authority for the
current source.

Runner-wakeup schema 11 retains the schema-10 layout for non-kernel metrics and
adds `buflo_kernel_tx`. Exact BuFLO egress now uses a helper-owned Linux
`SO_TXTIME`/`SCM_TXTIME` transaction against `CLOCK_TAI`: the datagram must be
queued by the release-minus-5-ms cutoff, high-priority strict non-deadline ETF
performs the release, and ordinary traffic remains on a separate FIFO band.
The socket receipt must carry the Linux `SOF_TXTIME_REPORT_ERRORS` flag value
`2`; value `1` denotes deadline mode and is not accepted. The Lab validates
this field as an exact integer rather than accepting a Boolean or numeric
coercion.
The Rust receipt binds TX-scheduler and TX-software error-queue timestamps,
qdisc and clock configuration, thread priorities, privilege drop, scheduler
state, and helper lifecycle. Legacy userspace exact-release guard metrics are
retained as a zero-valued compatibility projection in kernel mode.

The kernel runtime is created before the HTTP/3 handshakes so its helper can be
ready in time, but it remains dormant until the defence start and kernel epoch
are both present and exactly equal. The pre-arm state in which both are absent
is valid. An asymmetric or mismatched arm is a typed slot-invariant failure;
neither exact-release dispatch nor the tick-zero staging wake-up may query the
runtime before coherent arm. When kernel evidence is attached, every retained
schema-10 legacy metric family must be neutral, including iterations, typed
failures, histograms, retry counts, and retry lateness. Only after that proof
does schema 11 normalise the legacy poll source to the architecture-neutral
authoritative-`Instant` fallback and clear its counter frequency. The Lab's
schema-11 semantics are the complete immutable schema-10 semantics followed by
the kernel suffix, not the shorter base semantics.

Raw `buflo_kernel_tx` evidence is insufficient on its own. The Lab captures at
router ingress after the client veth and before netem, verifies the interfaces,
routes, qdiscs, offloads, NAT, capture bounds, and qdisc end state, and requires
item-by-item reconciliation with zero unresolved qdisc or capture drops. A
separately hash-bound `kernel-tx-evidence` sidecar preserves this proof without
altering the accepted sample's five-file inventory. Fresh accepted BuFLO
samples require runner-wakeup schema 11 and successful kernel and Lab evidence;
schemas 1–10 remain readable only for their immutable historical cohorts. The
exact 1,200-byte target, strict adapter-normalised half-open
`[release, deadline)` window, no-catch-up rule, client-only scope, and ordinary
HTTP/3 server are unchanged.

Outgoing-before-incoming logical order remains explicit. The runner drives
only endpoints with accepted scheduled receive credit that has not yet
produced a `MAX_STREAM_DATA` frame. Each
unresolved BuFLO incoming identity remains owned by that exact logical slot
and current endpoint until physical advertisement or the unchanged deadline.
Same-tick identities are refreshed when a slot legitimately moves or fans out,
while a foreign slot cannot borrow the window. Transport callbacks can trigger
another owner-only drive; otherwise the runner falls back to one-quarter,
one-half, three-quarter, and terminal-deadline wake-ups. A fan-out still has
one logical terminal outcome and therefore at most one deadline-miss row.
For an exact BuFLO outgoing/incoming pair, only the already-captured,
identity-bound incoming owner may receive a direct endpoint drive. The direct
path fails closed if the credit owner changes or the original deadline expires.
It does not widen the strict adapter-normalised half-open window, create
catch-up traffic, or change the generic and CS-BuFLO output paths.
CS-BuFLO retains its
three one-quarter, one-half, and three-quarter owner-only retries. The
half-open deadline remains
strict: a release or credit advertisement at or after the deadline is a typed
hard failure and is never caught up. Historical schema 2 receipts retain their
exact 250 microsecond
active-wait semantics and remain readable, but cannot admit a fresh candidate
capture. Five-millisecond active waiting consumed approximately 25% of one CPU
in the historical schema-9/10 userspace path. Current schema 11 instead
measures kernel-helper activity, timer wakeups, and client CPU as performance
evidence; no CPU cost is inferred before fresh capture.

One local engineering probe of the schema-9 hybrid wait exercised 5,000 slots
over 100 seconds with zero misses and zero early confirmations; its maximum
authoritative lateness was 613,529 ns and its maximum predictive-counter gap
was 2,264,322 ns. This is non-formal, non-source-bound development evidence
only. It motivates the captured timing-stress gate but cannot replace or
advance any campaign numerator.

CS-BuFLO local early termination stops defence chaff and credit work, not the
application. If it occurs before the local onLoad analogue, current receipts
count the application receive streams, parser state, and send endpoints handed
back to ordinary HTTP/3 processing. Natural application bytes after that latch
remain in final accounting while the padding basis, estimator samples, rate
transitions, and terminal interval stay frozen at the local-termination state.
Summary schema 4 also binds the asynchronous client-only translation.  Its
directional stop receipt records the application-complete or strict-quiet
phase, target or crossing reason, stop time, progress and target, scheduled and
terminal counters, and provisional invalidation count.  The handoff reconciles
those counters and timestamps with every schedule row: no new opportunity may
be scheduled after the stop, and each already-advertised receive-credit
opportunity must terminalise exactly once before the local latch.  Outgoing
crossings use observed UDP payload; incoming crossings use fully consumed
scheduled credit and do not claim peer-datagram timing or size.  A resumed
natural byte invalidates provisional stop evidence in the implementation, with
the cumulative invalidation count retained in the final receipt.  This drain
is not the paper's server padding-done signal.

The failed v56 prerequisite lineage binds
exact clean Lab `4d2ecd53c56f6d807f71175f62d1acfd44958202` and
Neqo/gitlink `8d4d1a49c098de1850879f4a116e88802a7bd9e4`. Its fresh
pull/no-cache build passed, including the pinned Docker code gate. The whole
build receipt has SHA-256
`626ffe1a69b51707b45e869a0dc5ebbe977d426484fe0c615a4dd9934f36650e`;
the collection, preparation, and reference images are respectively
`sha256:ee75909d19a8e7270c3e444f758ba4dae2b9f82eb5aa1645b3ccce433e365b86`,
`sha256:5ab716464fbc20604715f57fdf969c34d7b89bbc2ab53192994cabb711baba6d`,
and
`sha256:60614b9c705b96a19f0dccb86e7cd6de35549e2688758aae0121ff3df62a636f`.

The isolated v56 reference execution also passed. Its whole-file SHA-256 is
`7c5b1b8a4b65d3c37e2505c059561421aa60e01cab39b9200b0417b315df5f40`;
it used Docker network mode `none`, checked all 15 pinned inputs and all eight
BuFLO profiles, and reproduced the CS-BuFLO aggregate archive ratio
`2.282792444255336` over 3,824 nonzero-baseline records. These build and
reference receipts remain valid for their exact v56 commits only.

The immutable prerequisites for the failed v56 lineage are its
[build receipt](artifacts/buflo-study/build-execution-v56.json) and
[reference receipt](artifacts/buflo-study/reference-execution-v56.json).

The first and only v55 timing-stress launch then failed terminally in 14.366 ms,
before either HTTP/3 handshake or defence arm. The initialised but deliberately
dormant BuFLO kernel runtime was queried by the pre-arm event loop, producing
`QCSD slot accounting invariant failed: BuFLO kernel runtime was active before
defense arm`. The checkpoint records one launch and zero accepted visits and
has SHA-256
`e2150e3ea4e2b8ca44d569b1bcac9e71ec68a76a6d8743bfddc4b14aa878fd4f`.
The timing-error and raw-run receipts have SHA-256 values
`62a2a42a0fe3325e277ff9ed1337aff9356cd22182109eafbd127a8e186c4e34`
and
`048e93fdcff5e5b71ac10c395fd26080304cec5db779c457d02d3240b0f3b17b`.
The raw receipt has a null defence start, four `not_started` resources, and
zero schedule, event, packet, kernel-job, or TX populations. The post-veth
router capture is empty; the direct diagnostic's 11 packets all predate the
measured run and use the wrong port. V55 therefore contains no measured
traffic, is consumed at timing stress 0/12 and regression 0/18, and cannot
authorise post-v55 source.

The terminal evidence chain is the timing-stress
[checkpoint](results/buflo-study-regression-v55/buflo-timing-stress/experiment.json),
[outer error](results/buflo-study-regression-v55/buflo-timing-stress/attempts/visit-000/attempt-01/timing-stress-error.json),
and [raw run receipt](results/buflo-study-regression-v55/buflo-timing-stress/attempts/visit-000/attempt-01/neqo/run.json).

V56 then exercised the post-v55 arm repair. Its first and only timing-stress
launch reached defence arm, but BuFLO kernel job 0 was physically transmitted
in TAI interval
`[1788525850613250847,1788525850613254848]`, entirely before its permitted
half-open interval
`[1788525850617100862,1788525850622100862)`. The serialized fallback had set
`SO_PRIORITY=6` before attaching per-message IPv4 `IP_TOS`; Linux derived a
new packet priority from that later traffic-class control, so the datagram
bypassed ETF through the ordinary FIFO band instead of waiting for its release.
The immutable checkpoint has SHA-256
`c57acb5fe7255d9eaea40ac0f10235efa2f1b8576cbd2632f9f3fc65d291b393`;
the outer error and raw-run receipt have SHA-256 values
`62a2a42a0fe3325e277ff9ed1337aff9356cd22182109eafbd127a8e186c4e34`
and
`bc71dc358f9c57f51302635c5a36cc1106e7739aa4fd9d78b4faf1aa888731f0`.
V56 is consumed at 0/12 accepted timing visits and 0/18 regression cells; its
passed build and reference receipts cannot authorise repaired source.

The post-v56 Rust repair, now committed as
`edf44779db0dacac37b8a71f5ccf5ea102e34c29`, orders native `SCM_PRIORITY`
after all IP controls. On the WSL fallback it removes per-message IPv4
`IP_TOS`, applies socket `IP_TOS` before `SO_PRIORITY`, verifies both armed
values, and restores `IP_TOS` before priority with readback on every path.
IPv6 retains per-message `IPV6_TCLASS`. The Lab now durably preserves raw
qdisc observations for failed runs, and its disposable probe independently
checks ETF/FIFO accounting and post-veth timing without claiming scientific
evidence. The passed engineering probe has SHA-256
`a05b0f299bd97968c6714e5fde408a4bd7b92a42deaa4195b99e38c2077f5885`,
is explicitly `evidentiary=false` and `authorizes_capture=false`, and used the
older v56 image plus dirty repaired source. It therefore diagnoses the host
mechanism but cannot advance a v57 gate.

V57 then bound exact clean Lab
`b7811dab7124ffdde113fae111ef8bab4810ebba` and Rust/gitlink
`edf44779db0dacac37b8a71f5ccf5ea102e34c29`. Its fresh no-cache
[build](artifacts/buflo-study/build-execution-v57.json) and isolated
[reference execution](artifacts/buflo-study/reference-execution-v57.json)
passed; their whole-file SHA-256 values are
`80958d3b593d021c311aeed15c0013bbd6b4aadc1071753ab92e8c4006e03c2b`
and
`f7b12bf025ae836cd72cc6840b5204d02ad463fbb66201329cb4a240757dc436`.
The collection, preparation, and reference images are respectively
`sha256:c143cb5b2c0eae8953c5b6f0a484860bebf014d33eb59a856ae952698d7eb855`,
`sha256:b6fe32138243d25ee2e97d63a834b496e82fe77dbd583d09826ff1cd63836423`,
and
`sha256:94475bbb9b6491be702390abc432eca422c8991b9cdebc7192222a77a0a49199`.

Its sole first timing-stress launch was rejected with zero accepted visits
because global TAI-minus-MONOTONIC offset drift reached 1,566,579 ns against
the historical schema-3 ceiling of 250,000 ns. The immutable
[checkpoint](results/buflo-study-regression-v57/buflo-timing-stress/experiment.json)
and [timing error](results/buflo-study-regression-v57/buflo-timing-stress/attempts/visit-000/attempt-01/timing-stress-error.json)
have SHA-256 values
`c166dadd64adbfb14446015a295b391966af74ade6f4470df412c85be3311df3`
and
`932e343ba9c29fd8944229760ee404fdd67368bfebcaf083ddefd5a84e6b7f5c`.
V57 is consumed at timing stress 0/12 and regression 0/18; its separate
regression-bound code gate, controlled qualification, and all class-study
stages are absent. These receipts are valid only for their historical source
and cannot authorise the current clock-evidence repair.

The newest immutable timing checkpoint is therefore v57, but it contains a
terminal clock-evidence rejection rather than an accepted visit. V56 remains
the newest immutable checkpoint containing measured BuFLO client traffic, and
it also contains a terminal fidelity failure rather than an accepted visit.
The earlier schema-10 v47 comparison binds
clean Lab `236da73cb9091f37f0ea78256a72bd9e9ed62d60`, Neqo/gitlink
`ba72df21b0f6ef0b7607e11928895be83402b063`, collection image
`sha256:2da4c0da8c661a335cc86e9f22b20f52b6b60126ff9e07f493550cf7705d607a`,
preparation image
`sha256:c9d529354c295b47e209188071f426637a1cac424c3f2ec68a220f98a3bbb622`,
and reference image
`sha256:faf4bdc17caaac36e39975d509945393419cdd0c1afd997b7573256c5e3ef5b2`.
Its pull/no-cache build and isolated reference execution passed; their
whole-file SHA-256 values are
`3b1edab74d76baee8c58bb145c344825baa1117d28905e215c8e72eba5e13cbd`
and
`7f5ed067e7d215f6dc42e2f06c70794f0c18257203363ecac9f511b3e01edb42`.

The mandatory v47 timing stress stopped terminally at 0/12 on the first and
sole launch. At the 70.600-second tick, outgoing slot 7060 had release
`70,600,000,804 ns`, dispatch `70,605,134,484 ns`, and deadline
`70,604,999,804 ns`: dispatch was 5,133,680 ns after release and 134,680 ns
after the deadline. The maximum authoritative-over-counter lag was 5,206,204
ns. Paired incoming slot 7061 missed and retired 1,200 scheduled-credit bytes.
The ordinary 18-cell regression, code gate, controlled qualification, and
class-study foundation did not start. V47 is immutable schema-10 evidence and
cannot authorise schema-11 source.

The preceding receipt-bearing checkpoint, cohort v46, binds clean Lab
`b5387ffa43f12173eddfd11cc7c3cfd008f3e2b1`, Neqo/gitlink
`9428ec4fc03e9640369630fedc4ba6443870eb11`, collection image
`sha256:5b83101a7c2f4b1fb42d2e8316cc20087ddc7d4032c4871f5f77be533dd99656`,
preparation image
`sha256:7bd663ec7946378bb57badd007250cf9eb37197c2307bf2acf04e371694d4fa1`,
and reference image
`sha256:abcf75376ef397814487808ec4305a1c7907de6dab2bb132222f42d6b21aeeb4`.
Its pull/no-cache build and complete in-image code gates passed; the immutable
build receipt has SHA-256
`8670b3149830b5c553824aa56c1aa0f3de2c9ac91768cc69fe0f304d9b0db816`.
Its isolated reference gate also passed, with receipt SHA-256
`052a79fd136b3a0562173c29a6304871b24cdf48688bee710df35f79b9f8e8d8`.

The mandatory v46 timing stress accepted visits 000 and 001, then stopped
terminally on the sole authorised launch of visit 002. At the 101.440-second
tick, outgoing slot 10144 and paired incoming slot 10145 had a release instant
of 101,440,000,933 ns and strict deadline of 101,444,999,933 ns. The predictive
counter reported only 4,577,864 ns of progress while authoritative `Instant`
reported 10,321,797 ns: a 5,743,933 ns clock-domain divergence. Dispatch was
therefore observed 5,743,588 ns after target and 744,588 ns beyond the strict
deadline. Both slots terminalised as `DeadlineExpired`, exactly 1,200 incoming
credit bytes were retired, and no partial, suppressed, or catch-up event was
accepted. V46 is immutable at 2/12 accepted and 3/12 launched; it has no
18-cell regression, regression-bound code receipt, controlled qualification,
or class-study foundation.

The previous executed checkpoint, cohort v45, binds clean Lab
`d4288ec7053ed38883f2ba3a1b25a00e8f5622af`, Neqo/gitlink
`9428ec4fc03e9640369630fedc4ba6443870eb11`, collection image
`sha256:d42018722e61f3f2ed8a16dc4133bf8541fd36880226ada04086de033c79263c`,
preparation image
`sha256:45c10d7b7798edb8840c390780dbfc15f16acc6821bbb0e60a27aee2c1fcf4eb`,
and reference image
`sha256:c9b2b1dc50b0ffbbcea51b87602e5cd3d886b9f775563331add4e925259cfe1e`.
Its independent pull/no-cache build and complete in-image test gates passed;
the immutable build receipt has SHA-256
`4e555fd766431cf16e65e7a59aeff56b5a6c4429cc20fc17c47c613db25c7488`.
Its isolated, network-disabled reference execution also passed all eight BuFLO
profiles, the author/source isolation checks, and the 3,824-record CPSP archive
audit at aggregate ratio `2.282792444255336`; that receipt has SHA-256
`adc46319aec83df825bdcc38fe5fa262e6ba18ecfbc889a59717b6dfd3b635ac`.

V45's sole `visit-000` timing-stress launch then passed the operational runtime
contract but failed the former Lab eligibility contract. It produced 5,481
opportunities in each direction at the exact contiguous 20 ms targets from
zero through 109.6 seconds: the mandatory 5,001-opportunity inclusive
100-second prefix followed by 480 paired whole-cell/parser-drain opportunities.
All 10,962 directional events were satisfied; all 5,481 outgoing UDP payloads
were exactly 1,200 bytes; and partial, suppressed, missed, unresolved,
mismatched, and catch-up outcomes were all zero. Requested and consumed
incoming credit both totalled 6,577,200 bytes with no retired or unresolved
credit. Maximum outgoing lateness was 1,013 microseconds, maximum incoming
advertisement delay was 1,004 microseconds, and maximum authoritative guard-exit
lateness was 89,311 nanoseconds, all inside the unchanged strict half-open 5 ms
window. The schedule stopped with 270 bytes available, below the 1,200-byte
whole-cell requirement, and cancelled the remaining 273-byte sub-cell response
tail through the documented client-local drain policy.

The old Lab validator nevertheless required the schedule to stop exactly at
100 seconds and treated physical CSV row order as dispatch order, although
terminal rows are written in resolution order. It therefore rejected this
otherwise valid drain suffix as “not the exact inclusive 100-second cadence”.
The rejection consumed v45 at 0/12 accepted timing-stress visits under the
one-launch rule. V45 has no 18-cell regression, regression-bound code-gate
receipt, controlled qualification, or class-study foundation and remains
immutable, non-authorising failed evidence.

Earlier cohort v42 binds clean
Lab `d15e75f90d19591e4b28350d3f99ba5812b7d6c9`, Neqo/gitlink
`0c81cb2a99ed672117b39e97b6af86d7c6e0f298`, and collection image
`sha256:237c7947ed4932be54005180d54ec262b28630361e313ccf0332a9b00f232620`.
Its fresh pull/no-cache build and isolated reference execution passed; their
outer receipt SHA-256 values are respectively
`91d17d3d0b652ac6d055b4d1237a8f6415db08bcb1a089925cd345508c666b6f`
and `c46b5631a903ffd6d13c66f015b3520182445b5402bfff695c634c2d69acab0b`.
The mandatory timing stress then stopped terminally at 0/12 accepted visits on
the sole launch of `visit-000`. Outgoing slot 3442 was dispatched 9,302,759 ns
after its target and missed its strict half-open deadline; paired incoming slot
3443 consequently missed as well. Exactly 1,200 bytes of scheduled incoming
credit were retired, no catch-up occurred, and no retry was authorised. V42
therefore has no 18-cell regression, regression-bound code gate, controlled
result, qualification receipt, or class-study foundation. It is immutable
failed evidence and cannot authorise current or post-v42 source.

Cohort v43 then bound clean Lab
`1515205dda6d14be4b749efc8318bb05d08338f3` and Neqo/gitlink
`1257a68f1191054983d09f2773d92b166653885d`. Its fresh no-cache collection
build reached the in-image Rust gate, where all 177 `neqo-bin` tests passed,
but workspace-wide all-target Clippy rejected two exhaustive schema-nine test
functions for exceeding its cognitive-complexity threshold. The build stopped
before exporting an image or build receipt; reference and capture were never
started. V43 is therefore a consumed, non-authorising pre-receipt failure and
will not be rerun. The post-v43 fix is deliberately test-only: the two
exhaustive golden tests retain their complete assertions and carry scoped,
reasoned `clippy::cognitive_complexity` expectations. The exact workspace-wide
Clippy command subsequently passed on the corrected source bound by cohort
v44.

Cohort v44 bound clean Lab
`4de4d99dfef01e71842fa8f22d93cf7c7503459f` and Neqo/gitlink
`c7409eb3b486eb3655d5ab812c74cf551f27d205`. Its first independent no-cache
collection build passed all 177 `neqo-bin` tests and workspace-wide Clippy and
exported collection image
`sha256:e421c5a173de71f75a7e6dae157e1c70112f62a40e93054f93fe625235734955`.
The separately rebuilt preparation target then exposed a load-sensitive test
defect: `exact_release_dispatch_orders_cross_endpoint_pair_inside_one_window`
passed in the collection build but failed in the preparation build because the
test slept with Tokio until release and bypassed the production five-
millisecond reservation and predictive wait. The preparation gate ended at
176/177 tests, before Clippy or image export. No v44 build receipt was emitted,
and reference and capture were never started. V44 is therefore a consumed,
non-authorising code-gate failure and will not be rerun. The post-v44 correction
is again test-only: the connected two-origin test now constructs the production
guard, wakes at its unchanged five-millisecond guard, executes the schema-nine
predictive wait, requires dispatch inside the same half-open window, and records
the resulting typed evidence after transport dispatch. The corrected test
passed 100/100 sequential executions and 120/120 executions under 12-way
pressure; production code, parameters, and the hard five-millisecond deadline
are unchanged.

V36 remains useful older diagnostic evidence: its retry-capable ledgers
eventually showed 18/18 regression and 9/9 multi-origin acceptance only after
two approximately 10 ms capture-reconciliation rejections and one actual
paired BuFLO miss with 1,200 retired incoming bytes. Those rejected launches
make v36 non-attesting and cannot be normalised away.

Current engineering source keeps the 20 ms cadence, exact target release,
strict adapter-normalised deadline, and no-catch-up rule. It adds fail-closed
capture scheduling and evidence rather than weakening fidelity: all running
Docker containers are enumerated, study sidecars are confined to CPUs 0–9, the
collection container to CPUs 10–11, and the measured client must run as
`SCHED_RR` priority 1 on CPU 10. In-container monitoring rejects competing
tasks eligible for CPU 10, cgroup throttling, guest-visible steal time, or a
monitor failure. Physical host and hypervisor isolation remain unavailable
and are not claimed.

Before the ordinary 18-cell regression can run, a mandatory excluded timing
stress captures twelve BuFLO visits with exactly one physical launch per visit.
The current schema-4 contract requires an exact inclusive prefix of 5,001
opportunities per direction at targets zero through 100 seconds. After that
prefix, each visit may contain a contiguous, paired whole-cell/parser-drain
suffix on the same 20 ms cadence, up to the configured limit of 6,000
opportunities per direction. Schema 11 queues and independently observes all
5,001–6,000 outgoing opportunities, including `t=0`. The separately reported
post-`t=0` release population is therefore 5,000–5,999 per visit and
60,000–71,988 across the twelve-visit gate; that `N−1` population preserves
the historical timing-sensitivity denominator without pretending that `t=0`
was unobserved. Every prefix and suffix opportunity remains subject to the
unchanged exact-size, strict adapter-normalised half-open window, zero-miss,
zero-catch-up, exact incoming-credit, and complete kernel/Lab reconciliation
requirements.

Logical outgoing-before-incoming order is proven by direction, target, and slot
identity. Physical `schedule.csv` row order records terminal resolution and is
not misrepresented as dispatch order. The aggregate binds the per-visit
opportunity and drain lengths, dynamic post-`t=0` release and byte totals,
post-veth lateness histograms, observed sensitivity, terminal schedule-stop
receipt, sub-cell drain receipt, schema-11 sender jobs, Linux transmit
feedback, qdisc outcomes, and independent observer matches. Authoritative
`experiment.json` is source-, image-, cohort-, network-, parameter-, workload-,
qualification-, and opportunity-contract-bound and cannot pass after a
missing, rejected, or incomplete reserved attempt. The regression receipt
remains bound to the same stress evidence. Current-source captures require
timing-stress parameter/provenance, execution, and checkpoint schema 4, BuFLO
summary schema 4, runner-wakeup schema 11 with nested kernel runner/item/
mapping schema 2, the complete kernel sender receipt, and the separately
validated Lab observer sidecar; timing schemas 1–3 and nested kernel schema 1
remain historical-only.

Timing-stress schema 4 accepts only the exact current `schedule.csv` header:
the historical prefix followed by the complete nullable QCSD suffix in its
defined order. Missing, extra, duplicated, or reordered fields fail before
schedule interpretation. All authoritative runner-CSV paths now share one
canonical Rust-`u64` parser. It accepts only ASCII decimal `0` through
`18446744073709551615` and rejects signs, whitespace, Unicode digits,
fractions, leading zeroes other than `0`, overlong text, and overflow before
timing, size, composition, credit, fitting, plotting, or handoff arithmetic.

Production schema 11 in the v55 execution is exact clean Rust/gitlink
`20daa1df9387e2b50d0105e364a28bffe1bb1cc0`; exact clean Lab
`f93630f886aa3e196754c25baf408953b5369e8d` binds it. V55 proves that source's
fresh build and reference boundaries but its pre-arm failure prevents any
timing, regression, or later-gate authority.

The v55 Lab source retains router UID 0 and only NET_ADMIN/NET_RAW. It shares
the invoking user's single numeric primary GID with each controlled and public
post-veth router and requires the private bind root to be an exact host-owned,
host-primary-GID, setgid mode `2770` directory. Fresh roots are initialised;
pre-existing roots are verified and never silently repaired. Before any
measured client may launch, the router must also prove exact Docker
`HostConfig.GroupAdd`, PID 1 supplementary-group membership, bind-root
UID/GID/mode, setgid inheritance, create/unlink access, and an empty post-probe
root. The correction adds neither `CAP_DAC_OVERRIDE` nor
`CAP_DAC_READ_SEARCH`, does not weaken read-only client mounts, and applies to
both controlled and public ETF paths. V55 built this exact clean source and
entered its first timing launch; the failure occurred in the client before the
router could observe measured traffic.

The post-v56 engineering source was Rust
`edf44779db0dacac37b8a71f5ccf5ea102e34c29` and Lab/gitlink
`b7811dab7124ffdde113fae111ef8bab4810ebba`. It retained the post-v55 arm and
schema-11 corrections, fixed the traffic-class/priority interaction, preserved
raw qdisc evidence on failure, and hardened the diagnostic-probe, interpreter,
Git-provenance, guardian, and signal-supervisor boundaries. V57 bound that
exact source and passed its fresh no-cache build and isolated reference gates,
then its sole first timing launch failed the historical schema-3 whole-run
TAI-minus-MONOTONIC drift ceiling.

Current clean Rust `ce0d7a21756ce795d6f50d750a1c25e0fa006327` and historical
Lab implementation checkpoint `a420d3240b43d92ee0fb1b063ab3c550bd4fbe6f`
retain all physical timing requirements while replacing the obsolete global
gate with nested kernel receipt schema 2. The Lab checkpoint also adds the
source-bound pinned-CDP probe, exact foundation/qualification authority,
create-only fitting source revalidation, strict schema-2 final fitting and
selection receipts, and deep campaign-resume admission. Each direct enqueue
TAI bracket is corroborated by
item-local post-TX MONOTONIC evidence; the REALTIME intersection remains hard,
global MONOTONIC drift is diagnostic, the physical TX interval remains inside
`[release, release + 5 ms)`, and incoming evidence additionally requires
`tx_lower >= enqueue_lower`. The Lab timing-stress contract is schema 4.
Pinned focused Rust passed 23/23 with strict Clippy, host formatting/checking
passed, and Lab clock/timing/parameter 164/164, lifecycle adversarial 8/8, CLI
38/38, and supervisor 215 with seven skipped passed. Those results belong to
the pre-batching lineage. For the post-batching source, the acquisition suite
passed 96/96 and the merged acquisition/watcher/timing/cohort/CLI/successor/
attestation suite passed 450/450. The exact `a420d324…` implementation bytes
then passed the complete Lab suite: 2,910 tests passed, 12 explicit platform or
opt-in tests skipped, and 23 dependency/platform warnings were reported in
1,875.42 seconds. These are engineering checks only. V58's build and reference
receipts bind its parent Lab `c7e8355a…`, not this implementation checkpoint.
Later Lab `a20382c…` added the browser-egress and extended-foundation source;
v60's failed build exposed its Docker-configuration lifetime defect. Committed
Lab `e719219b42826126fdc7771c2dec0463d425a83d` historically repaired that
foundation boundary against the same Rust/gitlink. Clean successor Lab
`69a14ebe48f78d08a8b36d3e573955ec64f00ff9` commits the schema-4 receipt
integration. V61 exercised that implementation through clean documentation
head `9d53e08f…`, but failed during pinned-frontend resolution before a layer,
image, IID, or receipt and is consumed. Clean Lab
`c55b08aa06fbb4ac16e3655d6d3911109d853730`
commits the post-v61 linked-config fix, schema-5 build/schema-1 completion,
dense allocation, host admission, downstream-authority rollout, pinned-CDP
session repair, post-`setsid()` exact-command binding, and lifecycle
signal-linearisation repair against the unchanged Rust/gitlink. The ledger
remains checked in through v61. V62 consumed its durable claim and completed
only the unreceipted collection role before the mandatory `before-prepare`
backing-volume probe failed closed; its intact failed transaction is archived
and the active lifecycle namespace is empty. V63 repeated that host-boundary
failure after its own collection role completed, and is likewise durably
consumed without a build/completion receipt. V64 subsequently passed its clean
schema-5 build and schema-1 completion pair for Lab `81dd702a…` and unchanged
Rust/gitlink `ce0d7a21…`. Its pinned-CDP launch then failed before receipt
publication because the image's automatically created mode-`0444` policy
ancestors were not searchable. Current Lab `18d4ab3…` repairs that source
boundary and passes 66/66 targeted tests, but the fix postdates v64 and is not
image-backed evidence. V65 exported its collection image after the embedded
Rust gate passed, then failed the immediately-before-prepare-build source
reproof when a concurrent documentation-audit `git status` refreshed sealed
Git metadata. It has no build/completion receipt and its collection image is
inadmissible. V66 durably published its claim pair, then failed lifecycle
admission on v65's still-intact uncommitted static-tag transaction before any
v66 Docker build. The exact v65 retirement audit is preserved and the active
lifecycle namespace is now empty. V66 is consumed and non-evidentiary; v67 is
the exact next successor. No pinned-CDP, timing, regression, code-gate,
controlled, or foundation receipt exists, and every downstream scientific
counter remains zero.

The retained post-v55 Lab engineering lineage also hardens durable Docker HANDOFF
retirement. It permits at most one additional read-only absence observation,
and only after the first exact-presence API result is `unknown`; the Docker
daemon and host boot are revalidated before that observation. `present` and
structurally `ambiguous` results fail immediately and retain the root. Exact selection,
root/content validation, HANDOFF digest, manifest, staged-record, helper-source,
and authenticated removal gates remain unchanged, with stage-specific errors.
The complete signal-supervisor suite passed 211 tests with seven skipped and
the lifecycle-retirement suite passed 30 tests. The run supervisor's unused
signal counter was also removed after a real early-signal trap race;
idempotent first-signal latching is unchanged. Direct-signal stress passed
80/80, four timeout/retry cases passed 40/40 after their service-bound margin
was made deterministic, and daemon-timeout tests now use a wide margin above
that bound. None of these local results advances a scientific numerator.

V48 failed during the pre-receipt collection-image build after 230
`neqo-bin` tests passed and three environment-sensitive fixtures failed. It
produced no image, build receipt, reference execution, or capture. V49's
embedded six-command Rust gate passed, including 233/233 `neqo-bin` tests and
strict workspace Clippy, but the build was deliberately cancelled during
release-binary compilation because the Lab launcher repair was still required.
It likewise produced no image or immutable receipt, reference, or capture.
V50 then completed and exported the no-cache collection image, including the
embedded Rust gate, but emitted no build receipt: its first terminal read-only
daemon-identity observation stalled immediately after export and reached the
three-second API-service bound. The build scope had already terminated and the
daemon subsequently returned the same pinned identity, so this was transient
identity unavailability rather than identity drift. The exact v50 image was
removed after a controlled Docker restart and the hash-verified lifecycle
records were preserved outside the active namespace for audit. V48--v50 are
diagnostic, non-evidentiary attempts.

V51 then completed the fresh no-cache build and isolated reference gate for
clean Lab `0eaf8039186315a7dc402fc26feac4dd92c1c6ce` and Rust/gitlink
`e3ea858a31677067da969f50c1ac5aba50592c7c`. The build and reference receipt
SHA-256 values are
`e01929b30dbe48a7008b7fe3495b5a5fdc118b2b0d96a299f849771e1bdcf98b`
and
`6092c5220690d7ac14562f162fc60d8536ad497ed9d1ef37b7603b71130a785d`.
Regression stopped before its first timing-stress sample: the controlled
router was launched with explicit `/usr/bin/python3`, bypassing the image
virtual environment that contains `qcsd_lab`, and its container exited with
status 1 about 196 ms after start. Reproduction against the same image showed
`ModuleNotFoundError` under `/usr/bin/python3` and a successful import under
`/opt/qcsd-venv/bin/python3`. Both controlled and public router launch paths,
and the public-resume admission import, now use the latter interpreter. The
supervisor correctly refused to hand off the stopped container. Both Docker
networks were removed; their durable
handoff retirement stopped within a pre-publication validation region whose
exact failing guard was not retained, and later authenticated stale recovery
validated and retired exactly those two records. No retirement invariant was
relaxed.

V51 contains no `experiment.json`, sample launch, attempt receipt, packet
capture, accepted visit, or eligible regression cell. It is therefore a
consumed infrastructure-failure cohort, not capture evidence: timing stress is
0/12 and regression is 0/18.

V52 then bound clean Lab `002efabd6de1852a34e56e173ebc8e081d48d173`
and the unchanged Rust/gitlink
`e3ea858a31677067da969f50c1ac5aba50592c7c`. Its pull/no-cache build passed
with receipt SHA-256
`0f2ec3466d420ef451ab9844ef8f208d3bbe9a81196259c1446024a59a493d86`;
its isolated reference gate passed with receipt SHA-256
`d5b372c9220ac950f1c357adab0c89b2a61fab0aa2c21520b6e459410e7afb33`.
The first controlled stability run entered Rust as `SCHED_RR` priority 1 on
CPU 10 with `RLIMIT_RTPRIO=1/1`, no-new-privileges set, and cgroup cpuset
`10-11`, but failed the strict scheduler contract because effective capability
mask `0x3100` still included NET_RAW. The inner `setpriv` command had narrowed
the bounding set while only adding to the inherited and ambient sets supplied
by the capture orchestrator. The post-v52 repair clears those two sets before
adding the permitted NET_ADMIN and SETPCAP bits. The strict Rust requirement
of `0x1100` during setup and zero capabilities after the permanent drop is
unchanged.

V52 stopped before creating `experiment.json`, an attempt directory, a PCAP,
or an accepted timing visit. Its timing-stress environment is the sole file in
the result root and has SHA-256
`fcd635d06007a9949c58c6c37b83ef74c76c5e5998b03a4857ac6f8a39cef1c5`.
All three sidecars and both networks were physically removed, but their five
durable HANDOFF ledgers failed retirement before any retirement authority was
published. The surviving evidence does not identify a narrower failed guard.
The official guardian-authenticated `etf-probe` recovery subsequently
validated and retired exactly those five absent-object roots, then reached its
expected disabled-probe exit. The active lifecycle namespace and QCSD-labelled
Docker object set are empty; the preserved kernel-TX root is empty. V52 remains
a consumed infrastructure-failure cohort at timing stress 0/12 and regression
0/18.

V53 then passed the clean no-cache build and isolated reference gates described
above. Its first timing-stress launch created the terminal checkpoint and one
diagnostic attempt but stopped on the router capture-root `EACCES` before the
measured client. All three sidecars and both controlled networks were
physically destroyed. Their five stale HANDOFF ledgers were subsequently
validated and retired through the official guardian-authenticated recovery
path; the active lifecycle namespace and QCSD-labelled Docker object sets are
empty. The empty, mode-`0700` v53 kernel-TX root is preserved unchanged for
audit.

V54 then started a fresh no-cache build from clean Lab
`6475ccdd1367953c453456fb237c13f3e9c610b0` and Rust/gitlink
`e3ea858a31677067da969f50c1ac5aba50592c7c`. The collection image's embedded
Rust gate passed 232 of 233 `neqo-bin` tests, then
`exact_handoff_excludes_realized_credit_from_a_later_guard` failed because its
real monotonic clock counted fixture setup inside the intended logical 20 ms
interval. Buildx reference `wtd8avzrq0if3hfvuhjsfu912` is terminal `Error`.
No image, build receipt, reference execution, timing visit, regression sample,
or other capture was exported. The v53 static image identities remain
unchanged. V54 is a consumed pre-receipt test failure and every v54 gate and
scientific counter is zero.

Restart/re-audit matched the v54 lifecycle state, then removed exactly its two
lifecycle roots and three bookkeeping files. The active lifecycle namespace is
empty. This is operational cleanup rather than candidate evidence. Rust
`20daa1df9387e2b50d0105e364a28bffe1bb1cc0` applies only the existing
`TestMonotonicNowOverride` to that fixture; the passing engineering tests are
recorded above and cannot repair v54 in place.

V55 then passed the fresh no-cache build and isolated reference gates described
above. Its first timing launch failed before defence arm with the immutable
checkpoint, timing-error, raw-run, and packet evidence recorded above. All
three sidecars and both controlled networks were physically removed. Their
durable HANDOFF retirements failed silently during teardown; later
guardian-authenticated recovery found the objects absent and retired all five
roots. The preserved evidence cannot identify a narrower original retirement
guard, so the lifecycle hardening above addresses the bounded transient case
without retroactively claiming a cause. The active v55 lifecycle namespace and
QCSD-labelled Docker object sets are empty. This cleanup is operational, not
candidate evidence.

On 5 September 2026, exact ledger-only recovery separately retired the five
stale v57 `HANDOFF` roots (three run roots and two network roots) after proving
all corresponding Docker objects absent. It issued no Docker-object removal
and left unrelated Docker inventory unchanged. This is operational recovery,
not scientific evidence.

V64 has an immutable clean build-execution/completion pair for Lab
`81dd702a…` and Rust/gitlink `ce0d7a21…`, but its pinned-CDP probe failed before
receipt publication. Current Lab `18d4ab3…` fixes the policy-directory defect
and has 66/66 targeted engineering tests, but has no fresh image-backed build
authority. Pinned-CDP, browser-egress, reference, regression-bound code-gate,
and foundation receipts for the current source are absent. Browser-egress is
0/110, timing stress is 0/12, regression is 0/18, and controlled qualification
is 0/160. Real acquisition observations remain zero.
Pilot fitting, qualification, and compatibility are 0/480, 0/720, and 0/1,080;
authoritative fitting and final qualification are 0/2,000 and 0/600;
certification and canaries are 0/900 and 0/1,000; formal capture is 0/16,000.
Handoff, evaluation, comparison, and attestation are absent. V58 passed only
its clean pull/no-cache build and isolated reference execution for Lab
`c7e8355a8bcf9e3deea138d3a43b3d89d1ebb641` and unchanged Rust
`ce0d7a21756ce795d6f50d750a1c25e0fa006327`; the receipt SHA-256 values are
`124ff428729db55ffe7bf2f024823d8db01ac48b46e5598a3fc4d749dc8d9223`
and `e9a55c93e92c0cc2566984304e06a43ba3660df46828488055befa561c57c69d`.
Its preparation image has no admissible browser-egress or pinned-CDP producer,
so v58 cannot be retrofitted or resumed into the current seven-gate
foundation. V59 completed only its clean pull/no-cache build for Lab
`2cbbb61a59ad8011f2948919c14c3316ed3772a9`
and unchanged Rust/gitlink `ce0d7a21756ce795d6f50d750a1c25e0fa006327`;
the whole-file build-receipt SHA-256 is
`f8db5c8f0821a1b080135b130c82c78d2b4a930baf5c88d28870225b7b223590`.
No later v59 gate ran, and the current browser/CDP source postdates that clean
identity. It therefore advances no current-source numerator. V60 attempted
exact clean Lab `a20382c…` / Rust `ce0d7a21…`, but failed during pinned-frontend
resolution before any Docker layer, image IID, or build receipt. Its static v59
tags stayed exact, its hash-audited runtime ledgers were retired, and
`lifecycle-recover` is clean. V60 is consumed and advances no numerator.
Committed Lab `e719219…` historically repaired the v60 configuration-isolation
boundary; clean successor Lab `69a14ebe…` commits the schema-4 Buildx receipt
integration.
V61 exercised that implementation through clean documentation head
`9d53e08f…`. Buildx record `ubc8xesmc26eep5nywsgg9hiq` failed after
approximately one second with
`open /proc/1182923/fd/9/.token_seed.lock: no such file or directory`, before
any layer, image, IID, or receipt. V61 is consumed and non-evidentiary; its
failed records are retained in the recoverable v61 audit directory while the
active lifecycle namespace is empty. Their unresolved process-state label is
not scientific evidence. Clean Lab
`c55b08aa06fbb4ac16e3655d6d3911109d853730` commits the
linked-config and completion-authority rollout plus the pinned-CDP session and
lifecycle signal-linearisation repairs and post-`setsid()` exact-command
binding. The checked-in genesis consumed ledger remains dense through v61.
V62 is separately consumed by its durable claim: its collection role built,
but the mandatory `before-prepare` WSL backing-volume probe failed before any
preparation/reference image or build/completion receipt. Its archived
transaction does not advance a gate. V63 repeated that collection-only,
pre-prepare failure and is also durably consumed without a receipt. V64 passed
its pull/no-cache schema-5 build and schema-1 completion publication, then
failed the pinned-CDP gate before receipt because the correct policy file sat
beneath mode-`0444`, non-searchable directories automatically created by
`COPY --chmod=0444`. It is consumed and cannot be repaired in place. V65 is the
next consumed cohort: it exported the collection image after the embedded Rust
tests and strict Clippy passed, but a concurrent documentation audit refreshed
sealed Git metadata by running `git status` and made the
immediately-before-prepare-build source reproof fail closed. It published no
build/completion receipt; its unreceipted image cannot be reused. V66 published
its durable claim pair from Lab `d73ee3f…`, then stopped before any Docker build
when lifecycle admission found v65's intact uncommitted static-tag transaction.
After an exact no-owner/no-object audit, that v65 transaction was preserved in
the retired audit directory and the active namespace now passes recovery. V66
has no build/completion receipt and cannot be retried. V67 is the exact next
allocator-authorised cohort. It must pass a fresh build/completion pair,
pinned-CDP gate, 110/110 browser-egress gate, isolated reference, 12/12 timing
stress, 18/18 regression, regression-bound code gate, and 160/160 controlled
qualification before expanded-class acquisition can begin. V55–v66 cannot be
retried. The complete current status and earlier cohort chronology are retained
in the authoritative workspace
[`PROJECT.md`](../PROJECT.md).

The current Lab boundary additionally classifies typed client defence/QCSD
runner errors as `StrictClientDefenseExecutionFailure`. That type and
`StrictDefenseFidelityFailure` are terminal for durable BuFLO/class-study
samples: the attempt is preserved, the stage seals incomplete and stops, and
neither automatic retry nor a later resume may turn it into an accepted cell.
All prerequisite-ordered class-study capture and resume roles also require the
process-local, campaign-identity-bound authority created by the `class-study`
coordinator after it verifies the prerequisite ledger; generic `run` or
`resume` cannot bypass that ordering.

At the historical 4 September 2026 18:17:04 AEST operational checkpoint, a read-only
probe found Docker 29.0.1 healthy on Linux AArch64 with daemon ID
`48f27adb-00f1-41ce-80fe-41360d2eb712`, 12 CPUs, approximately 16.5 GB memory,
and no running containers. The physical volume backing its data VHDX remains
subject to the 64 GiB build-time admission gate. The earlier unrelated
telemetry workload no longer creates a scheduling conflict, but final source
verification and a fresh no-cache build still precede any scientific run.
At the 6 September 2026 documentation audit Docker remained reachable.
Unrelated `telemetry-system` containers were running, so measured-capture
scheduler preflight would correctly fail closed until they are intentionally
stopped; class acquisition does not request that scheduler partition and
remains launchable. Docker also listed one unnamed Dead Rust-test ghost while
exact inspection returned `no such object`. That stale, unlabelled listing is
not selected by QCSD running-container checks and has no safely scoped live
prune route. These are operational conditions only and do not advance a
scientific numerator. Cohort
v32 passed its
fresh pull/no-cache build and isolated reference execution, then stopped in the
first established-mode regression campaign at 4/14 accepted cells. The two
undefended and two Walkie-Talkie cells passed; static, FRONT, Tamaraw, Traffic
Morphing, and WTF-PAD each encountered the same pre-receipt Rust panic on both
workloads. The trace attribution path used eager `then_some(slots[0])`
evaluation for a slotless receive-limit observation with no scheduled owner.
All failed attempts and the incomplete campaign remain preserved. V32 never
reached the four BuFLO/CS-BuFLO regression cells, its code gate, controlled
qualification, or any class-study stage, and cannot authorise corrected source.

The client fix selects scalar provenance only by matching an exact one-element
slot slice and adds a production-path zero-owner regression oracle. The Lab
also recognises Neqo exit 101 plus an exact Rust-panic stderr marker as a
`StrictClientDefenseExecutionFailure`, with the log hash retained, when the
crash prevents `run.json` from finalising its typed error. This closes v32's
fail-open retry path: a future pre-receipt client panic stops a durable stage
after its first preserved attempt.

Historical cohort v33 attempted the required pull/no-cache build from the clean
corrected commits. It completed the collection target and reached
preparation-image export before Docker's ext4 data device reported write I/O
errors, aborted its journal, failed a superblock write, and remounted
read-only. `dockerd` and the waiting `docker-buildx` client terminated with
`SIGBUS`. The Windows C: backing volume was at 100% usage with approximately
1.9 GB free. A controlled Docker Desktop restart remained in `starting` with
engine `_ping` timeouts and was stopped. No v33 build receipt or result exists,
no scientific numerator advanced, and no partial image may be reused. Storage
was subsequently reclaimed, Docker state was deliberately reset, and cohort
v34 produced the newer immutable checkpoint described above. No class-study
foundation, controlled qualification, readiness receipt, or validation
attestation exists.

The build launcher now fails closed on the infrastructure condition that
caused v33. It detects WSL from independent kernel, `/proc`, environment, and
`/run/WSL` signals. On WSL it resolves only an authoritative registered or
configured Docker **data** VHDX (never WSL's logical `df` value, Docker's
`main` VHDX, or an uncorroborated default-path file), maps that exact file to
its Windows backing volume with `Get-Volume -FilePath`, and requires at least
68,719,476,736 available bytes (64 GiB). The rounded reserve exceeds three
times the observed 20,099,104,768-byte VHDX growth between the last two
documented checkpoints. When both a `docker-desktop-data` registration and a
Docker settings location exist, they must resolve to the same candidate VHDX;
conflicting authoritative locations are rejected.

The launcher repeats the storage probe before collection, prepare, and
reference builds and after the reference build. It binds the probe source,
location source, VHDX path, backing-volume identifier, drive, and filesystem
across all four observations. The accepted local Docker context, endpoint,
server attributes, and daemon ID must also remain stable at each boundary and
after all image/source inventory reads; every Docker build and inventory
command names that validated context explicitly. Evidence builds reject all
image-role overrides, use the three fixed role tags, and hold one non-blocking
per-user, daemon-ID-derived host lock shared across checkouts and context
aliases within the current WSL instance. Builds launched by another Unix user
or WSL distribution are outside that mutex; the immutable-ID checks described
below make any conflicting tag mutation fail closed. Each target writes its
immutable ID through a target-specific Docker `--iidfile`; the launcher checks
the tag against that ID immediately and again after all three builds. It also
reads source metadata from every immutable role image and build-input metadata
from collection and prepare, rejecting any cross-role snapshot difference.
Host-side Python parsers run in isolated mode, load the exact source-controlled
validator rather than the caller's import path, and canonicalise the checkout
root before the first command.

All launcher-owned Docker API calls, attached or detached runs, and builds now
require a functioning per-user systemd manager on cgroup v2. Each client tree
runs in a uniquely named transient service or scope with control-group kill
semantics; API calls have whole-tree runtime bounds, while interrupted runs and
builds must prove the exact cgroup empty before cleanup can complete. Exact
helper-source, boot, daemon, endpoint, context, process, scope, status-channel,
container or network, and private nonce bindings are retained for recovery.
Read-only daemon-identity proof permits one fresh, non-overlapping observation
only when its first three-second service returns no identity; a returned
mismatch is terminal, and identity-plus-operation or other mutating Docker
requests remain one-shot. The native service boundary proves the failed first
service and its cgroup terminal before the second observation may begin.
Run/build children remain stopped behind durable birth and supervision
handshakes; source, latched signal, PID, start time, session, and process group
are revalidated immediately before release. The lifecycle guardian separately
waits after `setsid()` until the exact pinned
`/bin/bash --noprofile --norc -p ...` command is visible before periodic
runtime verification begins. A transient empty `/proc/<pid>/cmdline` during
`execve()` is pre-admission construction; after exact binding, command loss or
drift remains fatal. The delayed-`execve()` regression exercises this boundary.
Initial and final admission are linearised inside blocked-signal critical
sections. If a terminal signal is
already pending for the verified ready child, the guardian forwards it once
to that exact process group, publishes neither `GO` nor `ABORT`, retains the
decision channel and lifecycle authority, and serves no new lifecycle lease
while that admission channel remains unresolved. After resolved admission, a
later signal may still use authenticated bounded cleanup leases so ordinary
Docker teardown can finish; an unresponsive child is escalated to exact-group
`SIGKILL` at the deadline. Non-signal admission failures still publish
`ABORT`. An authenticated API-service lease transfer is definitive before the
watcher classifies a launcher exit: if a short cleanup service transfers and
finishes in the same scheduler turn, it follows the post-transfer terminal
proof and returns its real status instead of a false pre-transfer `125`. At the
next launch every lifecycle
root is validated before any Docker mutation, with run/build launcher recovery
preceding connected-network recovery and unresolved build taint preserved. An
authorised create whose object ID remains unavailable does not expire after a
fixed delay: admission stays blocked until the uniquely labelled object appears
and can be authenticated and removed. Malformed, non-monotonic, ambiguous,
cross-daemon, live-owner, unreadable `/proc` or cgroup, or unprovably non-empty
state blocks the command. Systems without functional user-systemd/cgroup-v2
containment are unsupported for evidentiary execution and fail closed. Durable
records live beneath the private `/var/tmp/qcsd-docker-lifecycle-<uid>/`
namespace, and a private per-user lifecycle lock serialises admission and
recovery across checkouts. The acquisition watcher reaches that boundary only
through an internal five-field bridge binding state root, scope root,
request-authority digest, action digest, and source-binding digest; all five
are rechecked after the exclusive lifecycle lock and immediately before
stale Docker-state mutation. The separate acquisition-watcher authority may
contain only its own stale watcher scopes before this Docker admission point;
it cannot inspect or mutate Docker state. The source-binding digest uses an
explicit preimage-contract schema 2 and includes the canonical build-completion
path and SHA-256 in addition to the build execution, foundation,
browser-egress, pinned-CDP, catalogue, provenance, source and preparation-image
identities. The reference-execution receipt is bound transitively through
`foundation_sha256`; it is not a separate field in the watcher's source-binding
preimage.

The host launcher is supported only when all four kernel-reported UID fields
are the same nonzero value, all four GID fields are the same nonzero value, and
`CAP_DAC_OVERRIDE` is absent from its inheritable, permitted, effective, and
ambient capability sets. The launcher and guardian both enforce this before
Docker admission. In historical Lab `e719219…` / `69a14ebe…`, the guardian
exposed an empty anonymous mode-`0500` `DOCKER_CONFIG`; its separate
crash-recoverable `BUILDX_CONFIG` remained linked and mode `0700`. That boundary
was designed to make optional token-seed writes from trusted BuildKit/buildx
public, pinned, credentialless pulls fail into the upstream in-memory fallback.
It was not an immutability claim against a hostile same-UID process. V61 showed
that the anonymous pathname did not remain usable for deferred pinned-frontend
resolution.

That historical configuration-isolation repair is committed at Lab
`e719219b42826126fdc7771c2dec0463d425a83d`, with unchanged clean Rust/gitlink
`ce0d7a21756ce795d6f50d750a1c25e0fa006327`. Its exact affected suite passed
476 tests with eight explicit skips. The separate opt-in live metadata probe
passed 1/1 and observed Docker's `buildx` client plugin at
`/usr/local/lib/docker/cli-plugins/docker-buildx`, version
`v0.29.1-desktop.1`, commit `28f6246ff24e2c05095e8741e48c48dcb2d3b4bc`,
and resolved-target SHA-256
`ceabe0401307ae5db2fe2ec9eff90959db0638a0dbcce52320bde2be20104347`.
These are engineering and host-diagnostic results only; they are not a build
receipt or candidate evidence and do not qualify the current post-v61 source.

Clean Lab `c55b08aa06fbb4ac16e3655d6d3911109d853730` combines the linked-config repair with
build-completion, downstream-authority, pinned-CDP browser-session, and
lifecycle signal-linearisation, post-`setsid()` exact-command binding, and
API-service transfer/exit-ordering changes.
During an individual active
build lease it keeps the empty mode-`0500`, link-count-two Docker config at a
stable non-symlink pathname beside the lifecycle lock; no live linked config is
retained between build leases. Its basename binds the UID, guardian process
start time and nonce. It also adds exact-path removal only after users drain
and a conservative process-reference census for separately retained published
crash residue. The checked-in genesis consumed ledger contains the dense prefix
v1–v61. V62's identical durable claim/consumed-claim records consume the next
version even though its build stopped after exporting only an unreceipted
provisional collection image. Its mandatory `before-prepare` storage probe
failed before a preparation/reference image or build/completion receipt, and
the failed transaction is archived outside the now-empty active lifecycle
namespace. V63 then repeated the same collection-only, pre-prepare failure and
is permanently consumed by its durable claim pair. V64 is likewise consumed
by its byte-identical claim pair. Unlike v62 and v63, it published a clean
schema-5 build/schema-1 completion pair for Lab `81dd702a…` and Rust/gitlink
`ce0d7a21…`; unlike a qualified cohort, it then failed pinned-CDP before a
receipt because the image's policy ancestors were not searchable. Current Lab
`18d4ab3…` contains the source fix only. V65 claimed its documentation successor
`9a6a45c…` and exported a collection image after the embedded Rust gate passed,
then failed the immediately-before-prepare-build reproof after a concurrent
documentation audit refreshed its sealed Git metadata with `git status`. It is
consumed, has no build/completion receipt, and its image cannot be used. V66
then published its durable claim pair but failed lifecycle admission on that
intact v65 transaction before any Docker build. Its exact audit and retirement
left the active namespace empty and recoverable, but cannot advance v66. V67 is
the exact next allocator-authorised value; no current-head build/completion
pair or downstream scientific authority exists.

The build-execution schema-4 integration is committed at clean Lab
`69a14ebe48f78d08a8b36d3e573955ec64f00ff9`. V61 exercised it but failed before
it could emit an evidentiary receipt. A fresh build from committed Lab
`c55b08aa06fbb4ac16e3655d6d3911109d853730` emits schema 5 with schema 4's four nested schema-1
storage observations,
exact IID-bearing command vectors, three distinct role IDs, fixed role tags,
independently re-verifiable per-role provenance, and the nested schema-1
`buildx` provenance envelope. Its four exact observation
boundaries are `before-collection`, `after-collection`, `after-prepare`, and
`after-reference`, distinct from the storage-probe boundaries documented
above. Each observation repeats one canonical identity SHA-256 derived from
Docker's exact `.ClientInfo.Plugins` metadata, the lexical plugin and resolved
root-owned executable identities, the resolved executable SHA-256, and the
exact one-line `docker buildx version`, semantic version, and commit. The four
timestamps must be strictly increasing within the enclosing build interval;
any identity drift stops the sequence before the next image build and prevents
a receipt. Schema 5 further binds the allocator's schema-1 cohort record, a
create-only claim and dense claim chain, and authority reproofs at the declared
boundaries. Receipt absence never makes a version in the consumed ledger
reusable.

Pre-v61, the then-clean schema-4 implementation passed the exact
`uv run pytest -q tests/test_browser_egress_qualification.py` run at 201/201 in
2,619.33 seconds and an isolated
`uv run pytest -q tests/test_buflo_study.py` run at 275/275 in 219.00 seconds.
These are engineering-only, non-evidentiary test results: they create no build,
browser-egress, candidate, or scientific receipt, do not test the current
post-v61 implementation or its schema-5/schema-1 build-success path, and
advance no cohort numerator.

The complete schema-5 envelope is revalidated against the clean source, Docker
identity, no-cache commands, Dockerfile, lockfiles, checkout root, probe hash,
Buildx identity and cohort claim before its create-only write. That execution
receipt alone is deliberately not success. The launcher must publish its
canonical create-only `build-completion-vN.json` sibling at schema 1 only after
exact receipt bytes/stat, source and gitlink, allocation/claim/chain, the
retired per-lease build transaction, lifecycle/cohort/operation locks, and a
final clean-source and claim reproof agree. Current admission requires both
files. Build-execution schemas 1–4 remain available only through explicit
historical opt-in.

The cohort allocator, launcher's checked-ledger reader, generic build receipt
reader, and acquisition watcher distinguish stable directory security identity
(type, device/inode, owner/group, and permission mode) from volatile child
metadata only for ancestor and preclaim walks. Benign unrelated directory-child
churn is tolerated at those walks; it cannot relax the final durable registry,
cohort-claim, or private build-transaction identities, which remain strict.
Mode drift and same-mode pathname replacement also fail, as do changes to exact
regular-file, lock, claim, temporary-file, transaction-root, and registry
identities. The allocator, build reader, and acquisition watcher each completed
a 20,000-iteration ancestor/preclaim churn stress with zero failures after this
repair; deterministic launcher tests cover the same scoped churn and strict
replacement boundaries.

The publisher requires the full receipt stat identity. Later admission through
a Docker bind mount may vary only device, inode, UID, GID, mtime and ctime; it
still requires the canonical relative path, exact bytes, payload and file
hashes, schema/cohort, mode `0600`, link count one and exact size. The completion
projects publication-time stat rather than mount-local metadata. Receipt
loading rejects symlinks, non-regular or multiply linked files, overlong input,
unstable reads, duplicate-key or non-finite JSON, and hashes the same stable
bytes it validates. These controls assume the same-UID owner of the evidence
tree is trusted: workflow “immutability” is not protection against a malicious
later process running as that owner, so adversarial archival integrity requires
an independently protected copy or seal.

The completion identity is carried by current reference-execution schema 2,
code-gate schema 2, study-environment schema 3, pinned-CDP receipt schema 9,
browser-egress foundation schema 3, class-foundation schema 4,
qualification-authority schema 2, controlled-qualification receipt schema 2,
class-readiness schema 3, historical-corpus snapshot schema 2, formal-cohort
manifest schema 3, capture-admission schema 4, and successor
decision/readiness schema 3. The nested pinned-CDP probe contract remains schema
8; successor policy/restart/cohort/plan remain schema 2. Acquisition provenance
remains schema 5 with checkpoint 2, active-batch 1, terminal 3 and completion 2.
Readers used by current admission, mutation, or publication paths reject the
immediately preceding schema. Where explicitly supported, separate historical
inspection callers opt in without gaining current mutation or publication
authority. Schemas 3–5 record builds through
`docker --host <pinned-local-endpoint>`; schema 2 used the pinned context. No
schema-5 execution/completion pair or downstream current receipt has been
emitted.

Earlier on 1 September 2026, a read-only probe found only about 2.19 GB
available on the backing C: volume and Docker again exposed data-device I/O
errors. That was operational context, not scientific evidence. The obsolete
Docker state and redundant local caches were subsequently removed. Docker
29.0.1 was reinitialised with daemon ID
`48f27adb-00f1-41ce-80fe-41360d2eb712`; v34's four schema-2 backing-volume
observations then passed with a minimum 523.92 GiB available. The Ubuntu WSL
distribution-aware Docker proxy is required so bind mounts resolve against the
actual checkout. This recovered state enabled v34 but does not transfer its
source-bound evidence to v36 or any prospective fresh source.

The authoritative current heads, progression, and evidence ledger are
maintained in
[`../PROJECT.md`](../PROJECT.md); the exact extended-class protocol and
matrices are maintained in [`../CLASS-STUDY.md`](../CLASS-STUDY.md).

### Non-evidentiary ETF capability probe

The public `./qcsd-lab etf-probe` entry point composes its disposable Docker
bridge/veth diagnostic through the mandatory durable lifecycle helper. The
guarded shell owns creation, signal handling, exact-object cleanup, handoff
retirement, and finalisation; direct Python execution cannot mutate Docker.
This implementation has synthetic test coverage. The passed live engineering
probe cited above used the older v56 image plus dirty repaired source; there is
no clean capability or campaign-evidence result for current source. Neither
v58's build/reference receipts nor v59's build-only receipt converts that older
probe into evidence for current source.

The schema-1 receipt is explicitly `evidentiary=false` and
`authorizes_capture=false`. A passing receipt could demonstrate only that one
host, kernel, Docker engine, and image exposed the prerequisite PRIO/ETF,
timestamping, socket-priority, and cleanup mechanics at that instant; it could
not satisfy or advance any reference, code, qualification, capture, or
final-attestation gate.

### Prospective 100-class final campaign

`classifier-multiorigin100-v1` replaces the earlier unexecuted five-class
candidate formal stage. Its pinned Tranco receipt and deterministic 600-domain
catalogue are checked in under `config/class-study/v1/`; all 600 candidates are
currently unassessed, so this is runnable infrastructure rather than acquired
evidence. The public acquisition runner admits one exact prepared page per
candidate only after matching start-window observations at 30 seconds, 24
hours, and 72 hours, then freezes 120 pilot classes and finally 100 study
classes plus 20 reserves across five fixed rank strata.

The catalogue contains 120 candidates per stratum, so only a 20% technical
eligibility yield is needed to obtain each stratum's 24 pilot classes. This
margin was fixed before acquisition; selection still uses the first eligible
domains in the pinned hash order and never defence, classifier, latency, or
bandwidth outcomes.

The candidate-domain boundary governs the primary navigation identity and
redirects, not subresource origins. Discovery iteratively converges the full
set of eligible public HTTPS GET origins and resources, then complete
preparation retains rendered resources from every approved origin.
Document-navigation origins are seeded per page, so optional pages cannot
contaminate one another's origin graphs. The limits of 32 approved origins,
512 audited origins, and eight convergence passes are technical, fail-closed
admission bounds, not an origin-count selection rule or an intentional
multi-origin exclusion. Exceeding any cap or failing to converge rejects the
whole class rather than truncating its accepted workload.
Every discovered **eligible public HTTPS GET** subresource is retained in an
accepted, converged workload. Observed non-GET and non-HTTPS requests are
audited exclusions outside this replay construct; their mere presence does
not reject the class or authorise omission of an otherwise eligible resource.
Authentication/account state remains inadmissible, and an eligible graph that
cannot converge or reproduce complete approved-origin coverage still fails
closed. The fresh browser load inside final preparation must reproduce the
converged origin set: a newly observed unapproved eligible HTTPS GET fails that
probe and forces reconvergence on a retry, and persisted complete-coverage
evidence rejects any `origin not approved` exclusion independently. Both
single-origin and naturally multi-origin classes are eligible. Multi-origin
status and origin count affect neither eligibility, ranking, quota, nor cohort
membership, and no acquisition or selection stage intentionally omits
eligible multi-origin resources or classes. The closed-checksum handoff
reports each realised class's origin count, together with the origin histogram
and single-/multi-origin totals, in
`dataset.json.resource_origin_profile`.

The current passive-render contract is fixed before navigation: a
1365×768 viewport at device scale factor 1, disabled cache, bypassed and
blocked service workers, and no scroll or scripted interaction. After the
`load` event it observes for at least 10 seconds and then requires a full
3-second interval with neither a relevant request/target event nor an active
network request. That quiet interval starts only after the 10-second minimum,
or after the last later event. A page still non-quiescent 30 seconds after
`load` receives a typed whole-candidate rejection. The compatibility
`settle_ms=10000` field records only the minimum observation duration, never
the actual cutoff; the hash-bound render receipt records navigation, load,
last-event, quiet-start and cutoff monotonic times, active IDs/count, and the
cutoff reason, together with router shutdown readiness and the terminal
shared-worker prearm summary. Passive-render and render-observation schema 2
and discovery-event-audit schema 3 are required for fresh evidence.
Consequently, the admitted graph covers passive activity in
this exact bounded render, not resources requiring scrolling, interaction,
account state, or activity beginning after the hard cap.

Browser discovery is bound to
`playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v10`,
Playwright 1.57.0, and the full Chromium revision 1200/version 143.0.7499.4
distribution. A receipt-schema-6 image-build patch changes only the two pinned
Playwright `crBrowser.js` and `crPage.js` auto-attach expressions, and activates
their target filters only for an exclusive QCSD driver process. Driver starts
hold a process-wide lock only until the Node driver has inherited the exact
ownership marker; active and ordinary browser lifetimes may then overlap.
Every Chromium launch uses the immutable `/usr/local/bin/qcsd-chromium` path
and a fixed child environment. Node-driver overrides, a different executable
environment value, altered package/browser trees, unsafe ownership or modes,
and mutable default-image ancestors fail before acquisition.

The root page then uses Chromium's public non-flat CDP transport to recursively
adopt page-related iframe, dedicated-worker, and shared-worker targets while
each child is paused. The separate public browser session holds only guarded
shared workers, and uses page-only target discovery to reject any sibling
popup/page in the root browser context. Dedicated workers retain their
immediate policy path. A guarded shared-worker bootstrap request remains held
until the non-flat adopter has issued every initial setup envelope; the
terminal summary requires every hold to be released after setup and no hold to
remain pending. Every child acknowledges `Debugger`, `Network`, cache/service-
worker bypass, recursive auto-attach, and an explicit target-information
barrier before resume; the root page and iframe sessions also enable request-
stage `Fetch`. Actual `Network.requestWillBeSent` occurrences alone create
replay-resource ledger entries. `Fetch.requestPaused` remains the before-I/O
policy gate and is reconciled against that Network evidence, including
Chromium's page-owned interception of dedicated-worker requests and the guarded
shared-worker session's own interception.

Request identities include the session path, target ID and generation, Network
request ID, and occurrence index; only unique page/iframe redirect migration is
accepted. Target attach, information-change, detach, and destruction activity
resets render quiescence independently of network traffic. Acceptance requires
zero active requests, router shutdown readiness, and zero pending shared-worker
prearms for the complete quiet interval. Target crashes, sibling pages,
unsupported related targets, ambiguous/cross-generation reuse, cache or
service-worker responses, unmatched Network/Fetch or terminal events, traffic
emitted before setup acknowledgement, or unresolved setup/policy work at the
deliberate shutdown boundary fail closed. A hard-cap rejection uses a separate
abort-and-context-disposal lifecycle, preserving the original typed passive-
render evidence even if cleanup itself encounters an error.

Each accepted preparation seals a content-minimised, replayable event
projection: sequence and relative time, target/session/frame/generation,
Network and Fetch IDs, method and URL, redirect identities, policy outcome,
terminal outcome, unique resource-or-exclusion occurrence mapping, and raw
initiator evidence. It contains no request headers, cookies, response bodies,
or payload secrets. An independent verifier reconstructs FIFO Network/Fetch
association (including explicitly counted internal Fetch restarts), terminal
closure, redirects, and latest-preceding dependency edges before accepting the
manifest. `Debugger` is enabled before any relevant target resumes so recursive
`initiator.stack.callFrames` evidence is available. Non-network schemes such as
`data:` are recorded as non-interceptable exclusions and do not falsely require
a Fetch event. The sanitised projection, render receipt, contract and their
digests are bound through preparation, longitudinal stability, and cohort
assembly. Raw CDP headers/bodies are deliberately not retained; the resulting
claim is exact conformance of the sealed projection and derived graph under the
pinned instrumentation, not archival replay of Chromium's unsanitised protocol
stream.

The create-only `./qcsd-lab test pinned-cdp` command exercises the real pinned
Playwright 1.57.0/Chromium 143.0.7499.4 topology in the exact preparation image
named by a versioned no-cache build receipt and its completion. Current receipt
schema 9 embeds the unchanged probe-contract schema 8 and binds the exact
driver receipt and browser identity, public-CDP v10 policy, successful HTTP
response inventory, shared-worker prearm terminal summary, and sanitised
target-lifecycle generation/count evidence. It runs as the host UID:GID with all
capabilities dropped and Docker networking disabled, while a local
in-container server proves cross-site iframe, worker/shared-worker,
duplicate-URL, redirect, and complete shutdown behaviour. Success publishes a
canonical hash-bound receipt containing only minimised topology counts and
booleans. The receipt binds its cohort, build receipt and payload hashes,
collection source, exact preparation image/source, observed isolation, and
probe contract. The current driver creates both a page-owned CDP session for
page/iframe interception and a distinct browser-owned session for
`BrowserSharedWorkerGuard`; guard/router startup precedes browser activity,
and both sessions are closed during cleanup. Mock regressions bind that
ownership and routing, but only this live pinned probe can produce the receipt.
It also proves real/effective/saved/filesystem UID/GID identity,
zero permitted/effective/inheritable/ambient capabilities, no-new-privileges,
and a loopback-only interface inventory. Mocked tests and the deliberately
non-evidentiary development-image diagnostics cannot substitute for that
receipt. The receipt producer and current browser contract postdate v59, so no
older cohort can acquire this evidence retroactively; v60 failed before it
produced a preparation image or build receipt, v61 repeated the
pinned-frontend path-lifetime failure before any layer, image, IID, or receipt,
and v62 and v63 each stopped after their collection role when the mandatory
`before-prepare` storage probe failed through WSL interop. V64 passed its clean
three-role build/completion boundary and launched this gate against the exact
preparation image and correct managed-policy input, but failed before receipt:
`COPY --chmod=0444` had auto-created the missing policy parent directories as
mode `0444`, so they could not be searched. Current Lab `18d4ab3…` explicitly
creates those roots as mode `0555` and rejects any unsearchable directory; its
66/66 targeted tests are source-only evidence. V65 subsequently exported its
collection image after the embedded Rust gate passed, but the transaction
failed before the preparation build after a concurrent documentation audit
refreshed sealed Git metadata with `git status`. It published no
build/completion or pinned-CDP receipt, and that image cannot be used. The next
cohort, v66, stopped even earlier: lifecycle admission found the intact v65
static-tag transaction before any Docker build. Its exact retirement audit does
not make either cohort reusable. The next attempt therefore requires a fresh
v67 no-cache build/completion pair. Pass the canonical receipt to the foundation
command as `--pinned-cdp-receipt "$PINNED_CDP"`. It is the sixth
explicit foundation hard gate: the foundation binds the receipt and payload
hashes, its exact build binding, and the fixed probe-contract hash, and requires
`build finish <= probe recorded_at <= foundation recorded_at`. Acquisition
initialisation then reconstructs that typed foundation in the preparation
image; the host acquisition watcher independently reopens the same frozen
foundation, build, probe, contract, isolation, topology, and chronology on
every start or recovery. No ambient or replacement probe path can be supplied
after the foundation is created.

Packet-observed browser-egress qualification is the seventh explicit
foundation hard gate. Its current 110-vector inventory covers the ordinary
full-Chromium production profile and isolated, non-production positive/negative
control pairs for DNS prefetch, preconnect, speculation prefetch/prerender, and
Reporting/NEL. The paired controls deliberately prove mechanism eligibility;
only the fail-closed production profile is admitted to public class acquisition.
The final receipt must bind the exact vector order and digest, fixed Chromium,
wrapper, managed policy, fixture certificate, resolver topology, effective
command-line projection, packet captures, build receipt, and preparation image.
The checked-in
[`browser-egress-qualification-v1.json`](config/class-study/v1/browser-egress-qualification-v1.json)
manifest has SHA-256
`d2990612f613fba7fa887c2f2677064fab3fbd7dc51977c0cfab9cb0dcaa3fc6`;
its expanded 110-vector digest is
`9fecbeb7988fcb28d82803026ef9f3948d1494b14cc5a0930585e6e51e3a4179`.
The checked-in
[`browser-egress-chromium-argv-v1.json`](config/class-study/v1/browser-egress-chromium-argv-v1.json)
command-line contract has SHA-256
`458f51042d64433c089e5c43ab1167bbfa337ed4b6bda5e9d0d4efc0edf99c36`.
The checked-in TLS private key is deliberately public, non-production fixture
material for `fixture.test`; it must never be trusted or reused outside this
closed qualification topology. Its bytes are hash-bound by the qualification
contract, and the image installs the fixture-only copy as root-owned mode
`0400` while masking that configuration directory from every non-fixture role.
Every production and qualification browser launch must contain exactly one bare
`--disable-quic`, must reject `--enable-quic`, and must load the sole managed
policy with `DnsOverHttpsMode=off`. These browser-preparation restrictions close
Chromium alternative-destination paths; they do not alter the later Neqo replay,
which remains ordinary HTTP/3 over QUIC. The gate proves the exact pinned switch,
policy, resolver and packet-observation contract rather than claiming that a
Chromium HTTP/3 mechanism was exercised.
Development probes advance no numerator, and no such current-source receipt
exists yet.

The same complete graph is now independently rederived at every downstream
evidence boundary. For each accepted fitting, pilot-compatibility,
certification, canary, and formal sample, the verifier derives the runtime
manifest from the admitted prepared manifest and requires `run.json` to match
its full response identity and canonical endpoint-origin set. It also checks
the campaign, application/runtime manifests, qualified chaff, mode-appropriate
parameter/provenance inputs, seed, request policy, and launch limits. This is
applied uniformly to all nine selectable modes; no defence may project the
application workload to one origin or discard a resource. The prospective
formal handoff uses schema 3 and repeats the nine input hashes/limits in every
sample row before rechecking them against the sealed source result and copied
run receipt. For a schema-11 BuFLO sample it additionally copies the three
kernel-TX sidecar files into a separate checksum-closed subtree and binds their
source/copy identities in a nullable row field; this does not change the
accepted sample's five-file inventory.

Formal export is unavailable until the independently reconstructed
post-formal historical snapshot verifies the exact ordered formal blocks
1–10, their first-launch and promotion-authority hashes, common source,
runtime inputs, no-cache build identity, and pre/post acquisition timing. The
schema-3 handoff copies that receipt to
`inputs/class-study-historical-post-snapshot.json` and binds both its file and
payload SHA-256 in `dataset.json`. Handoff verification—and therefore every
evaluation launched from the handoff—reconstructs that binding again; a list
of sealed class results alone is not export authority.

This is an allowance and preservation rule, not a multi-origin sampling quota.
The final 100 classes have not yet been acquired, so their realised
single-/multi-origin split is unknown and cannot honestly be promised in
advance. Whatever split results from the precommitted order and technical
gates is reported rather than altered.

The endpoint is one contemporaneous paired corpus over the same frozen 100
classes and visit indices under `undefended`, FRONT, Tamaraw, Traffic
Morphing, WTF-PAD, Walkie-Talkie, BuFLO, and canonical CTSP CS-BuFLO. Ten
temporal blocks contain two visits per class and mode, giving 16,000 formal
captures. Before any formal block, all 100 classes must first pass a single-
launch 900-cell certification under all nine selectable modes, including the
non-defence `static` control. `static` is excluded from the efficacy corpus;
CPSP CS-BuFLO remains a controlled ablation rather than a tenth mode.
The campaign must not be called **ready** or **guaranteed** until all 100
selected classes have passed acquisition and admission, every applicable
fitting and qualification gate has verified, and all 900 certification cells
have been accepted and independently verified. Unit tests, synthetic fixtures,
or a partial certification do not satisfy that claim.
Certification permits exactly one started attempt per class/mode cell. Each
excluded canary sample and each authoritative formal sample permits at most
three total attempts across resumes; every failed or interrupted attempt
remains sealed and cannot be relabelled or omitted.

Traffic Morphing, WTF-PAD, and Walkie-Talkie receive separate, excluded
fitting evidence: 480 pilot fitting captures and 2,000 final fitting captures,
with 720/600 live qualification executions and a 1,080-cell pilot
compatibility screen. The final cohort is not admitted from classifier
performance. Its optional Walkie-Talkie graph contains only pair-specific WT6
profiles with frozen capacity evidence at both endpoints; untested alternate
pairs are not inferred feasible. Publications are create-only and fail-closed;
campaign results resume through `experiment.json`, while acquisition resumes
only through its own `checkpoint.json`. The full protocol, exact matrices,
current class-study scientific-numerator ledger, and claim boundary are in
[`../CLASS-STUDY.md`](../CLASS-STUDY.md).

Numeric fitting provenance remains schema 1. The post-qualification final
fitting provenance and the final-selection input are schema 2 because they now
bind the exact qualification authority used to prepare and collect their
evidence. No final fitting or final-selection artifact was executed or
published under the earlier pre-publication schema-1 shapes; their validators
reject schema 1 explicitly as non-evidentiary rather than treating it as a
legacy evidence format.

#### Fail-closed generational successor policy

The 20 reserves are not an automatic substitution queue. A class may be
removed only through a create-only, hash-bound successor decision reconstructed
from a sealed, incomplete, exact 900-cell first-launch certification. The sole
authorising failure is an `undefended` cell whose failure has stage `fidelity`,
type `StrictPreparedResponseIdentityFailure`, and details naming that same
cell's `workload_id`. The same typed, same-workload prepared-identity failure
may occur under a defended mode only as non-authorising corroboration, and only
when that class already has the undefended proof. It cannot add a class to the
replacement set. A `StrictDefenseFidelityFailure`, a
`StrictClientDefenseExecutionFailure`, a defended-only or unrelated
prepared-identity failure, any other correctness failure, or a capture,
infrastructure, interruption, or unclassified failure blocks the whole
successor decision. Manual reclassification is forbidden.

Defence/QCSD fidelity failures during regression, controlled qualification,
fitting, qualification, compatibility, certification, canaries, or formal
capture are release-blocking client implementation defects to preserve,
diagnose, and repair. They never authorise dropping or relabelling a class,
activating a reserve, pruning its approved-origin/resource graph, weakening a
fidelity or acceptance threshold, or selecting/fitting around the failure.
Repairs may change only the client defence/controller/transport integration,
runner, or Lab validation path; ordinary HTTP/3 servers remain unchanged and
no symmetric or server-side defence deployment is permitted. If the unchanged
contract cannot be met client-side, the stage remains blocked.

Every client-side code repair starts a new create-only immutable cohort with a
new source/image binding. It repeats the complete build/reference/regression/
code/controlled foundation and every downstream fitting, qualification,
compatibility, certification, canary, or formal pairing invalidated by that
binding; predecessor-source results cannot be spliced into the new cohort.
Only the producer-recomputed, same-class `undefended`
`StrictPreparedResponseIdentityFailure` above can authorise generational class
replacement.

Both `StrictDefenseFidelityFailure` and
`StrictClientDefenseExecutionFailure` are terminal for the durable sample.
The exact attempt is preserved, the dependent campaign seals incomplete and
stops immediately, and neither automatic retry nor a later resume may turn it
into an accepted cell. Durable verification rejects any receipt history that
contains such a terminal failure followed by another attempt.

Successors are recursive but remain anchored to the original frozen 120-class
pilot and its qualified one-to-one 60-edge graph. Every generation also binds
its exact immediate predecessor cohort, assembly, final selection,
foundation/source/build identity, and, after generation one, predecessor
successor-restart receipt. The selection excludes the union of every proven
failure from all earlier generations, so a failed class can never re-enter;
subject to that constraint and the fixed rank quotas, it maximises unchanged
classes from the immediate predecessor and then uses frozen pilot order. Each
generation receives a distinct hash-derived
`classifier-multiorigin100-v2-gNN-<digest>` study identity and matching hidden
launch namespace.

Every generation starts fresh authoritative downstream evidence: all 2,000
fitting captures, 600 full qualification executions, and the complete 900-cell
first-launch certification must pass before successor readiness can exist.
Predecessor fitting, qualification, and certification outputs cannot be reused.
If cumulative failures leave no quota-feasible 50-edge matching, reserve/graph
capacity is exhausted and the process stops for a new acquisition cohort; it
does not relax a quota or infer a new edge. Replacement is forbidden after any
authorised formal capture has started.

Successor selection does not alter page admission. An activated reserve keeps
the exact admitted prepared workload and its complete approved-origin/resource
graph from the original acquisition assembly lineage. Single-origin and
naturally multi-origin classes remain eligible, origin count remains neither a
selection signal nor a quota, and projecting a multi-origin graph to fewer
origins or resources is forbidden. The public `class-study` actions
`successor-policy`, `successor-decision`, `successor-restart`, and
`successor-verify` expose these boundaries without reusing the v1 fresh-layout
namespace.

A sealed incomplete successor certification must also reopen the complete run
binding for every accepted cell under every mode before it can authorise a
decision. BuFLO and CS-BuFLO cells additionally reopen their current typed
algorithm chronology. Only failed cells follow the separately constrained,
producer-recomputed prepared-response identity path described above.

Fresh class-study commands use one canonical path graph: generated campaigns
live only in `config/classifier-multiorigin100-v1-campaigns/`, admitted
workloads remain in `config/workloads/`, cohort receipts live under
`config/class-study/v1/`, fitted bundles are direct children of `artifacts/`,
and final named qualification sets are published below
`config/chaff-qualification-store/sets/`. The host launcher derives and checks
those paths through `qcsd_lab.class_layout`; alternate or symlinked fresh roots
fail before Docker launch. Result resume and verification instead use the
hash-bound frozen `inputs/` tree and do not reinterpret it as a live workspace
root. Exact directories and prospective command fragments are listed in the
[canonical-layout section](../CLASS-STUDY.md#26-canonical-fresh-workspace-layout).

Every container-launching `class-study` coordinator action invokes the exact
checkout's `qcsd_lab.class_build_admission` module under `/usr/bin/python3 -I`
before `require_docker` or stale Docker-state recovery. For actions carrying
current build authority, the general host gate follows every direct and
transitive authority consumed by the requested action and requires them all to
resolve to one canonical build-execution schema-5/build-completion schema-1
pair, one clean source identity, and the same collection, preparation, and
reference image IDs. Conflicting, rebound, historical, cross-build, or
malformed authority carriers fail before Docker access. The host
`acquisition-watch` entry is separate: its private acquisition admission is
source- and build-completion-bound before it delegates a bounded coordinator
action; it is not itself described as a general build-authority carrier.
Frozen resume authority is reconstructed from the role-specific result inputs;
successor actions are restricted to their immutable restart plan. These gates
close build and image selection only: the in-image coordinator still performs
the complete scientific validation.

Base, non-successor cohort and campaign actions additionally require the
current acquisition-completion carrier. `fit-numeric` and `prefix-specs`
require the exact frozen `--capture-result`. These requirements are resolved on
the host before Docker access or stale-state mutation.

After `acquisition-init` has created the canonical provenance and
`checkpoint.json`, supervise the long 30-second/24-hour/72-hour acquisition
from the host with:

```shell
./qcsd-lab class-study acquisition-watch
```

The supervisor validates the catalogue, the foundation's exact browser-egress,
pinned-CDP, and no-cache-build authority, the prepare-image digest, provenance, and checkpoint
before doing any work. It invokes one
bounded `acquisition-run` action only when work is due and resumes from the
same `checkpoint.json` when the command is restarted. An action may advance a
deterministic compatible pair, but never more than two candidates or five live
page workers. Starting from the catalogue-order anchor, selection scans later
candidates in immutable catalogue order and pairs the first one with the same
priority and stage; a probe partner must also share the probe identifier, and
the combined retained page count must fit the five-worker cap. Incompatible
intervening candidates are skipped for that action. The anchor runs alone only
when no later candidate satisfies every compatibility condition. The
coordinator checkpoints the active batch and pending attempts before parallel
work and merges outcomes in catalogue order. Page navigation is a separate
action completed before a baseline is armed. A paired baseline uses one
atomically recorded timestamp;
the baseline action then waits interruptibly to the `t+30s` window and runs the
capped page batch without another Docker/status launch. The host watcher waits
for the `t+24h` and `t+72h` windows. It creates no alternative state or
completion receipt. The optional `--heartbeat-seconds` value controls
signal-responsive host wait slices and must be a finite number from one
through five seconds; it does not poll Docker at that frequency.

The current acquisition uses provenance schema 5, checkpoint schema 2,
active-batch schema 1, terminal schema 3, and completion schema 2. Its
provenance embeds the exact action-timing contract at nested schema 2 and the
baseline-scheduling contract at nested schema 2; the checkpoint carries the
append-only `baseline_batches` ledger and nullable transactional
`active_batch`. Genuine committed producers exist for acquisition schemas 1,
3, and 4; schema 2 is preserved against its declared intermediate verifier
contract but has no committed producer or artefact. All acquisition schemas
1–4 remain verification-only and cannot be resumed or used to publish new
evidence. The immutable public limits are two candidates per action and five
simultaneous live pages. The production watcher always invokes
`acquisition-run` with two as its bound; the supported value one exists only
for internal and deterministic test use, not as a production watcher tuning
control.

Status separates unfinished states from immediately actionable work.
It reports `acquisition_schema_version=5`, `checkpoint_schema_version=2`,
`maximum_candidates_per_action=2`, `global_live_page_cap=5`, and either a null
`active_batch` or a summary with the exact `batch_id`, `stage`, `published_at`,
`candidate_ids`, `live_page_count`, and `attempt_count` fields.
`due_now_count`, `finalisable_count`, and `missed_window_count` are disjoint
subsets of `probing_count`, and their sum cannot exceed `probing_count`:
finalisable candidates need only deterministic terminal/publication recovery
and are not counted as live due probes. `work_due_now` is true when
`recovery_required_count` is positive, any of those three counts is positive,
or `pending_count` is positive while `pending_start_blocked` is false.
Completion requires all 600 candidates terminal,
`recovery_required_count=0`, `finalisable_count=0`, no active batch, zero
pending or probing candidates, and no `next_due` value.

The 60-second browser navigation timeout and 30-second passive-render cap are
component limits, not a whole-attempt duration claim. The launcher instead
applies a configured whole-action policy: `SIGINT` at 1,800 seconds, an inner
hard kill after a 120-second cleanup grace, and an outer user-systemd backup
with `RuntimeMaxSec=1920s` plus a final 120-second stop grace. A completed
navigation or probe ledger attempt longer than 1,800 seconds is invalid;
interrupted attempts remain interrupted and are never promoted to completed
attempts. The whole-process cut-off is externally enforced and currently has
process-status evidence rather than a separate per-action duration receipt.
Direct `class-study acquisition-run` and `acquisition-status` invocations lack
the watcher's create-only scope authority and fail before Docker access.

Operationally, the serialised batch schedule is still much longer than 72
hours. A 40-minute action-start reservation covers the configured 2,040-second
outer cut-off, a 310-second status envelope, and a 50-second scheduler margin.
It is enforced between baseline batches and their `t+24h` and `t+72h` action
starts, including cross-offset collisions; the members of one recorded batch
share its reservation. With zero work and all candidates forming compatible
pairs, the best-compatible earliest-next greedy projection creates 300 batches,
places the last baseline 32 d 5 h 20 min after the first, and places its
earliest `t+72h` probe at 35 d 5 h 5 min. This is not a guaranteed duration.
Whenever no later compatible partner exists for an anchor, singleton fallback
can raise the batch count towards 600: the
all-singleton projection places the last baseline at 65 d 11 h 5 min and its
earliest `t+72h` probe at 68 d 10 h 50 min (approximately 68 days). Neither
projection is a globally optimal or universal lower bound; deliberately
delaying an earlier baseline can change the final endpoint. Navigation,
preparation, Docker, network, retries, and
interruptions add real wall time. The configured cut-off is a policy bound,
not a call-tree-derived guarantee of successful completion.

### Retained focused candidate workflow — not the class-foundation bootstrap

The following `buflo-study` workflow is retained as the command reference for
the earlier focused three-mode, 1,500-sample design. It is not the
`classifier-multiorigin100-v1` endpoint, and neither its receipts nor its
versioned attestation can substitute for the class-study
`validation-attestation.json`.

Do not use the block below to bootstrap the current extended class study. The
authoritative sequence is the
[class-foundation and acquisition bootstrap](../CLASS-STUDY.md#27-foundation-and-acquisition-bootstrap):
after its fresh build it runs the pinned-CDP probe, the 110-vector
browser-egress `create`/`verify` gate, isolated reference conformance, the
integrated 12-visit timing-stress and 18-cell regression gate, the
regression-bound code gate, the 160-cell controlled gate and qualification,
then creates and verifies the class-foundation attestation. The retained block
below deliberately creates neither the pinned-CDP receipt, browser-egress
qualification root, nor class-foundation attestation.

The versioned coordinator exposes nine fail-closed actions: `reference`,
`qualify`, `historical-snapshot`, `freeze-cohort`, `code-gate`, `capture`,
`export`, `evaluate`, and `verify`. The following Bash sequence is the complete
retained focused-study workflow. It assumes the fixed create-only destinations do not yet
exist and that `REFERENCE_ROOT` names the absolute directory containing the
pinned external paper, author-source, and archive inputs. Set `COHORT_VERSION`
in the calling environment to the allocator-authorised positive integer. The
shell prologue rejects malformed or already-published destinations;
`./qcsd-lab build` additionally requires the checked-in consumed ledger to be a
dense prefix and the requested version to be its exact successor before it
publishes the claim. Receipt absence does not make a pre-receipt failure
reusable. The checked-in genesis ledger remains dense through v61, while the
durable v62 claim/consumed-claim pair consumes v62 after its partial failed
build. V63's second durable claim/consumed-claim pair likewise consumes v63
after its collection-only failure. V64's byte-identical durable pair consumes
v64; its build/completion pair passed, but its pre-receipt pinned-CDP failure
prevents reuse. V65's byte-identical durable pair also consumes v65: only its
collection image was exported before the immediately-before-prepare-build Git
metadata reproof failed, so no receipt or image is reusable. V66's
byte-identical durable pair consumes v66: lifecycle admission found the intact
v65 static-tag transaction before any Docker build. The audited transaction is
now preserved outside the empty active namespace, but v66 remains
non-evidentiary. V67 is the exact next permitted value and must be built from
the current exact clean source before any downstream gate runs.

```bash
set -euo pipefail
REFERENCE_ROOT=/absolute/pinned-reference-inputs
: "${COHORT_VERSION:?export COHORT_VERSION as the allocator-authorised positive integer}"
[[ "$COHORT_VERSION" =~ ^[1-9][0-9]*$ ]] || {
  echo "COHORT_VERSION must be a canonical positive integer" >&2
  exit 2
}
[[ ! -e "artifacts/buflo-study/build-execution-v${COHORT_VERSION}.json" &&
   ! -e "artifacts/buflo-study/build-completion-v${COHORT_VERSION}.json" ]] || {
  echo "COHORT_VERSION already has a create-only build evidence destination" >&2
  exit 2
}
REFERENCE="artifacts/buflo-study/reference-execution-v${COHORT_VERSION}.json"
QUALIFICATION="artifacts/buflo-study/qualification-v${COHORT_VERSION}.json"
CONTROLLED_ROOT="results/buflo-study-controlled-v${COHORT_VERSION}"
REGRESSION_ROOT="results/buflo-study-regression-v${COHORT_VERSION}"
CODE_GATE="artifacts/buflo-study/code-gate-v${COHORT_VERSION}.json"

# On WSL, first require 64 GiB on the actual Docker data-VHDX backing volume.
# Serially builds the three fixed roles with --pull --no-cache and --iidfile,
# repeats the backing-volume, daemon, and Docker-selected Buildx identity
# checks at their exact boundaries, creates the schema-5 build receipt, and
# publishes its schema-1 completion sibling only if all authorities remain
# stable through final clean-source and claim reproof.
./qcsd-lab build --cohort-version "$COHORT_VERSION"
./qcsd-lab buflo-study reference \
  --reference-root "$REFERENCE_ROOT" --destination "$REFERENCE" \
  --cohort-version "$COHORT_VERSION"

# Run and bind the nine-mode regression before the code gate. The wrapper
# provisions the isolated networks and holds the acquisition lock.
./qcsd-lab buflo-study capture --stage regression \
  --cohort-version "$COHORT_VERSION" --destination "$REGRESSION_ROOT"

mapfile -t REGRESSION < <(python3 -c '
import json,sys
v=json.load(open(sys.argv[1], encoding="utf-8"))
for key in sorted(v["campaigns"]): print(v["campaigns"][key])
' "$REGRESSION_ROOT/regression-results.json")
[[ "${#REGRESSION[@]}" -eq 3 ]] || {
  echo "regression checkpoint must report exactly three result roots" >&2
  exit 1
}
REGRESSION_ARGS=()
for root in "${REGRESSION[@]}"; do
  REGRESSION_ARGS+=(--result "$root")
done

./qcsd-lab buflo-study code-gate "${REGRESSION_ARGS[@]}" \
  --cohort-version "$COHORT_VERSION" --destination "$CODE_GATE"

# Execute all four controlled network profiles only after the regression-bound
# code gate passes.
./qcsd-lab buflo-study capture --stage controlled \
  --cohort-version "$COHORT_VERSION" --destination "$CONTROLLED_ROOT"
mapfile -t CONTROLLED < <(python3 -c '
import json,sys
v=json.load(open(sys.argv[1], encoding="utf-8"))
for key in sorted(v["profiles"]): print(v["profiles"][key])
' "$CONTROLLED_ROOT/controlled-results.json")
CONTROLLED_ARGS=()
for root in "${CONTROLLED[@]}"; do
  CONTROLLED_ARGS+=(--controlled-result "$root")
done

# This action revalidates controlled160, creates or resumes the exact public5
# sustained-chaff set, verifies it, then publishes the typed receipt.
./qcsd-lab buflo-study qualify "${CONTROLLED_ARGS[@]}" \
  --cohort-version "$COHORT_VERSION" --destination "$QUALIFICATION"

SMOKE="$(
  ./qcsd-lab buflo-study capture --stage smoke \
    --cohort-version "$COHORT_VERSION" \
    --reference-receipt "$REFERENCE" \
    --qualification-receipt "$QUALIFICATION" \
    "${REGRESSION_ARGS[@]}" \
    --destination "artifacts/buflo-study/smoke-admission-v${COHORT_VERSION}.json" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["details"]["captured_results"][0])'
)"
REHEARSAL="$(
  ./qcsd-lab buflo-study capture --stage rehearsal \
    --cohort-version "$COHORT_VERSION" \
    --reference-receipt "$REFERENCE" \
    --qualification-receipt "$QUALIFICATION" \
    "${REGRESSION_ARGS[@]}" --result "$SMOKE" \
    --destination "artifacts/buflo-study/rehearsal-admission-v${COHORT_VERSION}.json" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["details"]["captured_results"][0])'
)"

PRE="artifacts/buflo-study/historical-pre-formal-v${COHORT_VERSION}.json"
COHORT="artifacts/buflo-study/formal-cohort-v${COHORT_VERSION}.json"
./qcsd-lab buflo-study historical-snapshot --snapshot-phase pre-formal \
  --cohort-version "$COHORT_VERSION" --destination "$PRE"
./qcsd-lab buflo-study freeze-cohort \
  --cohort-version "$COHORT_VERSION" --cohort-id "buflo-formal-v${COHORT_VERSION}" \
  --historical-pre-snapshot "$PRE" --destination "$COHORT"

mapfile -t FORMAL < <(
  ./qcsd-lab buflo-study capture --stage formal \
    --cohort-version "$COHORT_VERSION" \
    --reference-receipt "$REFERENCE" \
    --code-gate-receipt "$CODE_GATE" \
    --qualification-receipt "$QUALIFICATION" \
    "${REGRESSION_ARGS[@]}" --result "$SMOKE" --result "$REHEARSAL" \
    --historical-pre-snapshot "$PRE" --formal-cohort "$COHORT" \
    --formal-window-hours 12.5 \
    --destination "artifacts/buflo-study/formal-admission-v${COHORT_VERSION}.json" |
  python3 -c '
import json,sys
for root in json.load(sys.stdin)["details"]["captured_results"]: print(root)
'
)

POST_ARGS=()
FORMAL_ARGS=()
for root in "${FORMAL[@]}"; do
  POST_ARGS+=(--result "$root")
  FORMAL_ARGS+=(--formal-result "$root")
done
POST="artifacts/buflo-study/historical-post-formal-v${COHORT_VERSION}.json"
./qcsd-lab buflo-study historical-snapshot --snapshot-phase post-formal \
  --cohort-version "$COHORT_VERSION" \
  --historical-pre-snapshot "$PRE" "${POST_ARGS[@]}" --destination "$POST"

HANDOFF="handoffs/buflo-study-formal-v${COHORT_VERSION}"
EVALUATION="artifacts/buflo-study/evaluation-formal-v${COHORT_VERSION}.json"
./qcsd-lab buflo-study export --formal "${POST_ARGS[@]}" \
  --cohort-version "$COHORT_VERSION" --destination "$HANDOFF"
./qcsd-lab buflo-study evaluate --formal --handoff "$HANDOFF" \
  --cohort-version "$COHORT_VERSION" \
  --bootstrap-draws 10000 \
  --dlsvm-wall-seconds 45000 --destination "$EVALUATION"
```

Formal evaluation deliberately pauses for a human comparison review. Create
`artifacts/buflo-study/comparison-review-vN.json` with the exact schema enforced
by `validate_comparison_review`: it must hash-bind and substantively classify
every original-study anchor/metric pair as `expected` or `resolved`, explain
the transport/dataset/protocol context, and retain `paper_equivalent: false`.
The retained focused workflow's terminal verification and attestation command
is:

```bash
REVIEW="artifacts/buflo-study/comparison-review-v${COHORT_VERSION}.json"
ATTESTATION="artifacts/buflo-study/validation-attestation-v${COHORT_VERSION}.json"
REGRESSION_VERIFY_ARGS=()
for root in "${REGRESSION[@]}"; do
  REGRESSION_VERIFY_ARGS+=(--regression-result "$root")
done

./qcsd-lab buflo-study verify --formal --destination "$ATTESTATION" \
  --cohort-version "$COHORT_VERSION" \
  --reference-receipt "$REFERENCE" \
  --code-gate-receipt "$CODE_GATE" \
  --qualification-receipt "$QUALIFICATION" \
  "${REGRESSION_VERIFY_ARGS[@]}" "${CONTROLLED_ARGS[@]}" \
  --smoke-result "$SMOKE" --rehearsal-result "$REHEARSAL" \
  "${FORMAL_ARGS[@]}" \
  --capture-admission "artifacts/buflo-study/formal-admission-v${COHORT_VERSION}.json" \
  --formal-cohort "$COHORT" --handoff "$HANDOFF" \
  --evaluation-receipt "$EVALUATION" --comparison-review "$REVIEW" \
  --historical-pre-snapshot "$PRE" --historical-post-snapshot "$POST"
./qcsd-lab buflo-study verify --cohort-version "$COHORT_VERSION" \
  --attestation "$ATTESTATION"
```

The build command requires one explicit `--cohort-version`; subsequent
`buflo-study` actions retain their historical default only for compatibility.
New successful builds from the committed implementation emit
build-execution schema 5 plus build-completion schema 1. A code,
parameter, workload, chaff, or acceptance-rule change after rehearsal instead
starts a new positive version: first run
`./qcsd-lab build --cohort-version N`, then pass the same option to every
`buflo-study` action. Each build creates, and never replaces,
`artifacts/buflo-study/build-execution-vN.json` and its canonical
`build-completion-vN.json` sibling. Qualification sets, rendered
campaign inputs, reference execution, freeze/admission receipts, captures, and
final verification are all checked against that exact receipt/completion pair
and its collection, prepare, and reference image IDs. A direct public `run`
derives N from its capture admission; `resume` derives it only from the frozen
`inputs/capture-admission.json`, so neither command can be redirected to a
different cohort. Keep all earlier versioned evidence.

For this retained focused workflow, the exact result arguments are the
immutable result roots reported by the
preceding stage; the coordinator rejects missing, extra, relabelled, or
source-mismatched roots. The staged matrix is 18 test-only nine-mode regression
samples, 160 controlled qualification samples, 20 public smoke samples, 40
public rehearsal samples, then ten formal blocks totalling 1,500 focused
samples. Formal admission additionally requires one exact clean no-cache image,
the executed isolated reference receipt, the hash-bound code-gate receipt, at
least 12.5 declared hours, and three times the storage projected from the
verified smoke and rehearsal data. Cohort v15 and later prospectively freeze
exactly 10,000 block/workload bootstrap draws and their deterministic seed
contract; formal evaluation rejects any different draw count.
`experiment.json` is the only resume checkpoint. The coordinator automatically
resumes the one prospectively selected root, preserves failed/interrupted
physical-launch accounting, caps each study sample at three total launches,
and never rewrites accepted samples. Rerun the same `capture` command with its
existing `--capture-admission` instead of its `--destination` after an
interruption.

The reference image runs with networking disabled and checks the pinned paper,
author-source, and CPSP archive bytes. The collection image never contains the
author implementations. The dedicated handoff and evaluator do not modify the
sealed `classifier-multiorigin5-v2` corpus, and classifiers receive only
identifier-free timestamp, direction, and observer-frame length.

New focused formal exports use handoff schema 2. A nullable
`kernel_tx_evidence` row field is populated only for schema-11 BuFLO and copies
exactly `router-capture.pcapng`, `router-receipt.json`, and
`kernel-tx-evidence.json` into
`kernel-tx-evidence/<sample>/`. `SHA256SUMS` closes this separate subtree; deep
verification replays the evidence against the copied `run.json`, router
receipt, and capture. Historical focused schema 1 remains readable only for
non-formal compatibility, while formal validation requires schema 2 and
reopens the original sealed result roots even when optional deep replay is
disabled. The accepted source sample still has exactly five files. No
current-source focused handoff exists.

### `build`

```shell
: "${COHORT_VERSION:?export the allocator-authorised positive cohort version}"
./qcsd-lab build --cohort-version "$COHORT_VERSION"
```

Builds the collection, workload-preparation, and isolated reference images
from the current Lab checkout and Neqo submodule. The requested positive
version must be the exact successor of the checked-in dense consumed-cohort
ledger, and both create-only build destinations must be absent. The launcher
requires exact clean raw-byte Lab and Neqo checkouts before the first Docker
build; there is no development-mode or dirty-source override. The clean source
identities, lockfiles, image IDs/digests, four-point Docker-selected Buildx
identity, and cohort claim authority are bound into the schema-5 build receipt.
The build becomes successful only when its schema-1 completion sibling is
published after the final authority reproof. Current admission rejects a
missing completion or historical build schema; generic historical reading
requires explicit opt-in.

### `prepare`

```shell
./qcsd-lab prepare example https://example.com/ https://example.com
```

For a cohort that must retain its complete approved multi-origin render graph:

```shell
./qcsd-lab prepare example-r2 https://example.com/ \
  https://example.com https://static.example.com \
  --require-complete-coverage
```

The arguments are a new workload ID, a page URL, and one or more explicitly
approved HTTPS origins. Preparation:

1. observes the page with Chromium;
2. removes unsafe or unapproved requests, sensitive headers, and credentialed URLs;
3. probes the retained requests with the same Neqo client used for capture;
4. checks repeated status, byte count, and body identity;
5. freezes the concrete request headers and dependency graph in
   `config/workloads/<id>.json`.

Discovery pauses every request before transmission. Only explicitly approved
HTTPS `GET` requests are continued; other methods and origins are aborted and
recorded as exclusions. `--require-complete-coverage` additionally requires at
least one rendered resource from every approved origin and rejects preparation
if any approved rendered resource is unavailable over HTTP/3. Its frozen
coverage-admission receipt makes that stricter contract auditable. Without the
flag, the historical behaviour remains: HTTP/3-unavailable resources and their
orphaned dependency closure may be excluded when the navigation root remains
valid.

Preparation refuses to overwrite an existing ID. Chromium is not used during
measurement. There is no runtime header-policy switch: the exact safe headers
stored on each resource are the request input.

### `derive-chaff-prefix-specs`

```shell
./qcsd-lab derive-chaff-prefix-specs
```

Creates one atomic, create-only `config/chaff-prefix-specs/v2/` directory
containing the six standalone schema-2 prefix-pack specifications. The
specifications project the exact sealed schema-5 Walkie-Talkie numeric profiles
through the fixed sender-framing cell and frozen prepared manifests into
every-component activation and capacity stages. They do not consume live
response-qualification evidence or a schema-6 artifact. The source artifact
must have its sealed raw hash and the v2 destination must not already exist.

### `qualify-chaff`

```shell
./qcsd-lab qualify-chaff
```

Qualifies all six frozen workloads as one create-only transaction. For each
workload, three independent unshaped runs issue the exact qualified parallel
cohort, `max(5, required_chaff_streams)` and at most 20, using the frozen
selected same-origin resource and its existing `Accept`, `Accept-Encoding`,
and `Accept-Language` values in their original order. They derive one stable
response identity. Three separate production prefix-pack runs then prove every
moulded component's exact full-packet targets: cumulative application and
required-chaff requests pass through FIN, every required chaff-request STREAM
range and FIN is peer-acknowledged, and no targetless STREAM bytes are emitted.
The command
embeds the exact receipts in each sidecar and publishes all six files together
under `config/chaff-qualification-store/v2/`; any pre-publication validation or
network failure leaves that canonical directory absent. A failure after the
atomic rename can leave a complete canonical directory that requires explicit
audit. It requires the exact clean Lab/Neqo checkout and executable embedded in
the preparation image and does not use fitting or campaign samples.

The staged prefix proof broadly drains HTTP/3/QPACK output before its
transcript. At every activation gate, application and required-chaff request
output, request-causal HTTP/3 control output, and QPACK encoder output must all
be empty. Post-warmup client QPACK decoder-stream output is recorded but
excluded from that completion predicate because this fixed critical-stream
role is not a dependency of the already transmitted request prefix.

### `qualify-response-chaff`

```shell
./qcsd-lab qualify-response-chaff \
  getbootstrap-home-r3 \
  cloudflare-quiche-r3 \
  hyper-basic-client-r2 \
  serde-home-r1 \
  rfc9114-text-r1
```

Publishes the five-class FRONT/Tamaraw chaff evidence as one create-only
transaction under `config/chaff-response-qualification-store/v2/`. The public
batch requires exactly five unique workload IDs with five distinct primary
HTTPS origins. It keeps application requests unchanged and creates a separate
chaff-only request namespace: `Accept` and `Accept-Language` are copied exactly
from the prepared resource, while `Accept-Encoding` is forced to `identity`.

For each workload, eligible known-valid same-origin candidates of at least
1,200 prepared body bytes are ordered deterministically by prepared body size,
resource ID, and URL. Each attempted candidate receives three independent
connection epochs separated by at least 30 seconds. One connection per epoch
issues 40 requests as eight sequential waves of at most five concurrent
requests, so a candidate qualifies only after 120 exact completions. Every
completion must have the same successful identity-encoded response status,
body length, and body SHA-256. Only an explicit identity or capacity rejection
advances to the next candidate; transport, DNS, timeout, or protocol failures
abort the transaction. Publication is atomic, and no v2 sidecar hash exists
until that exact five-file transaction succeeds from a clean build.

The unqualified command above is the immutable legacy route to the canonical
set directory named `v2`. The fresh classifier lineage instead uses an
explicit safe set name and a campaign binding:

```shell
./qcsd-lab qualify-response-chaff --set classifier-multiorigin5-v2 \
  getbootstrap-home-r4 cloudflare-quiche-r4 hyper-basic-client-r3 \
  serde-home-r2 rfc9114-text-r2
```

This publishes create-only under
`config/chaff-response-qualification-store/sets/classifier-multiorigin5-v2/`;
the parent `sets/` directory is tracked so a clean clone never creates it as an
unreviewed side effect. Each consuming FRONT/Tamaraw campaign must declare
`chaff_qualification_set: classifier-multiorigin5-v2`. The selected five
sidecars are copied into the result's frozen `inputs/chaff-qualifications/`
tree, so resume and verification never consult the live set. Omitting the
campaign field preserves the exact legacy `v2` lookup.

The fresh `classifier-multiorigin5-v2` set was qualified from clean Lab
`44d19f3cf787ef9b0c1eaa121758874fa6e49a67` and clean Neqo
`6aceaac85243d6e0e34354108e010705d3c83088` using preparation image
`sha256:5b4f8268118dbfb37d0c520510a616ff8e24b67b7ceb2b394f97c353be7d9ff5`.
Its audited five-file aggregate SHA-256 is
`9df4d34dc0a7b767e6fb3b2429bd8638ec33914da95ab05733d99b02a38488f8`:

| Workload | v2 set sidecar SHA-256 |
|---|---|
| `getbootstrap-home-r4` | `a3274a15e7c74554fc91efbe71c3d22e0e94843c1008105339bf30cd03309a0a` |
| `cloudflare-quiche-r4` | `5fa1b048aec8294d28086942045829ac2efa6db69aa74eccfb7045949d0c9b84` |
| `hyper-basic-client-r3` | `7d95b91a38530db1d5db3e6bfbbe7019aff0b8ed705292b9db05ee46daa42327` |
| `serde-home-r2` | `d4f71ecc7782d395c711af06fb9f2cfc407dd0c60a35aaffc024f39acf41165c` |
| `rfc9114-text-r2` | `bd528f882ff471fee5bb6e9a21fea44c2d13d46faa863f784b3b67ea10f55f7d` |

That image is qualification provenance, not the acquisition collection image.
The later sealed acquisition used clean Lab
`8988a48a8e43cc9d47505cae12ee7758bc7fa5ee`, clean Neqo
`6aceaac85243d6e0e34354108e010705d3c83088`, and collection image
`sha256:38c24b0c5c4a06b223a904e896e1e38401c78fffbe6edab0f17846bb66a04de2`.
The distinction remains important because the qualification image above is not
the source receipt for any of the 2,500 formal samples.

The historical legacy POC5 exact-five cohort was qualified atomically from
clean Lab Q6 `0d0b1984c1d87b0502899cc451f1ed6ab6463d03`, tree
`2c44a2d00473676776eafbbd7883e4ed739d16de`, and clean Neqo F3
`6aceaac85243d6e0e34354108e010705d3c83088`. The qualification collection and
prepare/actual images were respectively
`sha256:91151da64ead1aff662f207107aa06fa2d16c62378f2989043193beca22a24ac`
and
`sha256:e5f1c8153b4238700f06339d94c046ca3d8f5aad14375ae6642ea7785b792881`,
under build tag suffix
`q6-0d0b1984c1d8-6aceaac85243-20260817T191330Z`. Their `source.json` SHA-256
was `a82950c006023d11972913021fd14ad88332c8a8ff028f223472e31d3bd164f0`,
their raw implementation-receipt SHA-256 was
`ebf2eadf174d2fbc43156907b4fd76d3dcf5f2f1f13af606ead404a3d2168a27`,
and every sidecar binds implementation-receipt aggregate
`4137ed63d23c52b897f47c26ed62f1c97e13f0a173b51438c4bcf20979adc5d5`.
The exact Q6 collection image completed its deterministic prerequisite suite
with 732 passed and two environment-gated skips, then passed all three
Linux-local live prerequisites before qualification.

The deterministic first candidate (`candidate_index: 0`) qualified for all
five workloads without a rejected candidate. Across 15 independent connection
epochs, 600 stable identity completions produced 61,277 packet observations:
54,444 incoming and 6,833 outgoing. All 120 request waves completed; the ten
within-workload inter-epoch gaps ranged from 30.030177204 to 30.065013514
seconds, the maximum observed UDP payload was 1,200 bytes, and no oversized
packet was observed. Its historical legacy sidecar and derived-manifest hashes
are:

| Workload | Sidecar SHA-256 | Derived schema-4 manifest SHA-256 |
|---|---|---|
| `getbootstrap-home-r3` | `60ff5642bac12a73d0efcfbf74728946cb42d58aae5c18a4d0e9efa6641c899b` | `dd44865c7a0452c2e603c0bfa07994a054a4c1753a08045273f7d542167b4a12` |
| `cloudflare-quiche-r3` | `895c31ce388cf20ace53afeba2abd2f7a03f85054bf3bed37a47db389f8b45ac` | `0c8dab88862df196d303d5f69b177bde8553b978e6acc72d091772540cd6eb1c` |
| `hyper-basic-client-r2` | `24996a0978cda7a9858f39fef720abe3ebc5243cec5eb52943acadcfe79f0468` | `ab36ef6920b106c4f8bd625c8b5e9dc40f7fbca1ab7cb315a224f8b00219bd57` |
| `serde-home-r1` | `7367ef8b340bb5e4624b213f9d78e1008ad2f8e61f3939ab87c504e622d23d52` | `96a361270e81631f0fd50eb676e37cb33aae915319396766f16cc3cf2e198a7f` |
| `rfc9114-text-r1` | `8d35815100de1b1ab8b5beb2c819ba5fdf5d032e3c144d553df911cec62d74ac` | `ad5faeebb1cc186c5b79df01d66315481ba18f623a4afdb65a8ec06fa1709b58` |

P6 published these exact files as the canonical legacy POC5 response cohort
under `config/chaff-response-qualification-store/v2/`. They remain frozen
compatibility evidence and are not the fresh `classifier-multiorigin5-v2` set
or acquisition provenance.

The now-historical P5 exact-five cohort was qualified atomically from clean Lab Q5
`af3403d60f5be008dc88cc52c6ce8ec5a34bc47c`, tree
`7110eebb2e4763a9e197d3c5be8f6b55b0b2feb9`, and clean Neqo F3
`6aceaac85243d6e0e34354108e010705d3c83088`. Q5 is the documentation
acquisition child of the test-only controlled-fixture repair
`32f8f4d816cf05ebc483cc547732d146225493c9`; the production Linux-local
capture-integrity implementation remains
`47c91bb36dcddd3943253ee16141febbaf9041e8`. The qualification collection and
prepare/actual images were respectively
`sha256:73c2530d0c14bd272e88a3dff147018fd30d4aa5e848988f3714fb7b1484b990`
and
`sha256:cd238e21e89706e257de75dd94282224bb40ebe70cbc0615511be4072eab2e7a`,
under build tag suffix
`q-af3403d60f5b-6aceaac85243-20260817T171051Z`. Their `source.json` SHA-256 was
`2847eea1cd0988cbb51f3b5086cb4e326011ebfe1bb68136a5b9143501063f35`,
their raw implementation-receipt SHA-256 was
`4db3b6448e988c4674e94c0a7584b63b352fd1115d4dfb8124f6e1b7845c80d9`,
and every sidecar binds implementation-receipt aggregate
`4d96ca1ce6d0711ae8ca4e1c125b8b83451daab683e626c90c95b5c39c37afbb`.
The exact image passed all 731 local prerequisite tests before qualification.

The deterministic first candidate (`candidate_index: 0`) qualified for all
five workloads without a rejected candidate. Across 15 independent connection
epochs, 600 stable identity completions produced 61,726 packet observations:
54,454 incoming and 7,272 outgoing. All 120 request waves completed; the ten
within-workload inter-epoch gaps ranged from 30.013367067 to 30.062120752
seconds, the maximum observed UDP payload was 1,200 bytes, and no oversized
packet was observed. Its historical hashes are:

| Workload | Sidecar SHA-256 | Derived schema-4 manifest SHA-256 |
|---|---|---|
| `getbootstrap-home-r3` | `cbc90b4f4f1021fc51140cfe23d133dbce17e1f81d34eaa70639be42370ad4ca` | `9a3e3bc6648a91ca0c6ebc884aaa2bfd271c64d1efab087d4594e71a28e785c9` |
| `cloudflare-quiche-r3` | `2506c96d3aee4b145e3ba816f3ee64fe47e2e71df65f3d75d40126694aa01c1e` | `cff7a5fcfddb4d4419efdd80a85b1172942a4c2c8ffa4fc558cc4f2672416589` |
| `hyper-basic-client-r1` | `aee4f47953c89026e4583e2cfd8db1bc78ffa1bfcd6af1f0e9813b2b31a37f51` | `b9407104892141af34581b138aa81d6a58353c1e66fa0a3023ab5c3589d90ef5` |
| `serde-home-r1` | `773f4e4a0c9ecfc50ed59a7787e9102e58b25941fdae874c53d43da4b798903b` | `165436bf45941105d2f29d1b3193564cb416b3e4a3bad4ab441a1819163480b9` |
| `rfc9114-text-r1` | `b77dd117607ce698bcc4ad7da12367621a12baafbc7805f5ff13cf11557eee6c` | `2bb2bf65644172d338496eadba17524d9a5521bf4dff130c42f3482c3081a600` |

P5 `f215b538e043a26038aae8bb93e8926f3de6d322`, tree
`257fb2b0f7433b96279927c109f3397a6d1be733` and parent Q5, published those
exact files. Its final collection and preparation images were respectively
`sha256:3f4f10a47b72d3d280ad1bbed4dc0338e7823abdf62e6304b4e674a3777375ea`
and
`sha256:fbb2560054f5cdc8b789b50698fc093b3d14fe0ef76d101baba913f99b666fdb`,
under build tag suffix
`p5-f215b538e043-6aceaac85243-20260817T175203Z`. Their `source.json` SHA-256
was `370b6b6e1edbbec5137f04381e13db4187263f16e735b68584671c6afa2123f3`,
their raw implementation-receipt SHA-256 was
`6f99ba3b443ee35fb6cd258dc02178ff973cae0fc8a74b6cfd126a0224ea78bd`,
and their implementation-receipt aggregate was
`dda2dfd54b10da49234e14744a844a0befaac90f6694395508cbbb721d61634e`.

The excluded P5 rehearsal at
`results/research-classifier-poc5-rehearsal-1200/20260817T181058.212792Z`
sealed `incomplete`: 30 planned, 28 accepted, 24 eligible, and two terminal
failures. Its evidence-index SHA-256 is
`04a4d40a9c09bc8618eec8322d68df07508994a12968535a5e37883c96bae89b`
and its `experiment.json` SHA-256 is
`89338ae55eb4a7124b42dec28386247dfc5c0abd034af51718d8418e5f0cfdfd`.
All 35 retained attempts passed the Linux-local capture-clock gate with one
constant-offset segment, zero modeled steps, and exact direct-runner packet
reconciliation. The failure was therefore not Windows, WSL, or capture-clock
instability. Hyper r1 had frozen resource 0 at 6,165 bytes and SHA-256
`96411b4e30fa8e579eebf6f9b2b7604ccb7335e990266a2da893fe4ff7426c40`,
while all ten retained Hyper executions returned 5,917 bytes and SHA-256
`59974039ec7fdcbc0461fd86f91fddc294ed7c2eb3cd46f96352be0687eaf106`.
Each of the six Tamaraw attempts correctly failed one slot with
`ReceiveCreditRetired` and exactly 243 retired bytes; the four undefended/FRONT
captures matched each other but not the frozen prepared identity.

The create-only replacement `config/workloads/hyper-basic-client-r2.json`
has SHA-256
`11baf7f3fe0db6f9c86af51fbc4100b2b5f1683385f7f9d30fefd33349569d6f`
and records three stable preparation runs at the new 5,917-byte identity,
with 1,200-byte maximum UDP payloads and zero oversized packets. Q6 changed
only the active POC5 Hyper binding to r2 and kept Neqo F3 unchanged. Because
the workload ID is an input to deterministic defence ordering and to every
Hyper sample seed and ID, Q6 also reselected the ten paired campaign seeds
prospectively from
`2026082001..2026092000` using plan expansion only. The 2,500-sample plan has
unique sample IDs and seeds, every class/defence/position cell occurs 32--35
times, and only three of 45 cells fall outside 33--34. At that POC5 boundary,
canonical legacy response-store `v2` contained only the Q6/F3 exact-five cohort
published by P6. A clean P6/F3 final-image build, excluded 30/30 rehearsal, and
verified interface handoff were required before its formal acquisition could
restart from baseline-01. No P5-bound interface handoff, formal capture, or
classifier export was run.

The immediately preceding, now-historical exact-five cohort was qualified
atomically from clean Lab Q3
`06cacddc21ab0ded9422d445723f60f37c530363` and clean Neqo F3
`6aceaac85243d6e0e34354108e010705d3c83088`, tree
`691209bdd616c25759d508f1af0547904b8ce058`, whose parent is F2
`a8378520b9740be782bfe526cdb3eb05e6665571` and whose exact patch hashes to
`a4b17821f8c119af9f022a609dd33e40be4f196fcad397b04ba444d859c4a7f8`.
The qualification collection image was
`sha256:bea517984b866d0c413ccc3d7c381e07a586a86eac5660717a9b8a809b4da382`;
preparation produced, and the qualification actually used,
`sha256:227a931f5ae410fe298285d69a1d5d7b403ba026970949e5b30723d86b66b68a`.
The qualification build tag suffix was
`q-06cacddc21ab-6aceaac85243-20260815T211610Z`.
Every sidecar binds implementation-receipt aggregate
`558705bb0560ee3a87140670de7140ac087e9a0bf5ab13c1215f214f618f5ea4`.
The deterministic first candidate (`candidate_index: 0`) qualified for all
five workloads. Across 15 independent connection epochs, 600 stable identity
completions produced 61,875 packet observations: 54,573 incoming and 7,302
outgoing. Within every workload, consecutive epochs retained at least the
required 30-second gaps, the maximum observed UDP payload was 1,200 bytes, and
no oversized packet was observed. Its now-historical hashes are:

| Workload | Sidecar SHA-256 | Derived schema-4 manifest SHA-256 |
|---|---|---|
| `getbootstrap-home-r3` | `9b868b3b083c3acca66d6d05c7c9962e3aad28750defbdbe21a340fb054c1148` | `7fb560f246c90b2ad3eaf937f7a97f3bf9661f244fd10fd84e86753db51ddf3d` |
| `cloudflare-quiche-r3` | `c9dacbabdd2861c5ef505fa572f7f1b9407084c7002a5ef28057b66c12788246` | `51e90afbd48747f9a776eeb9fb80158b38f4a909d9fd35932ceb4c7fb1edd80a` |
| `hyper-basic-client-r1` | `92b5090ba4b4d228db652f7d435da3d29867f9ffe221a835e4f6d965cd6840d9` | `2fa47f098191f2c72f9abcf90b4b2f7b0edef1d21bc480c93fc18f5f988df514` |
| `serde-home-r1` | `19fa46e8da00b6af47090ae9857335b9db966a3b55dc9c0592059cdceb2eafc4` | `d463076c6baf2a01fd94d534fae8015f99d523a54ebd4a9dc9d95d4109cf1f11` |
| `rfc9114-text-r1` | `f43285364a01de0f5024632995b83f034911c5d3c7c5770396b240f07c5fcf62` | `0152f1137aa31e5371ad4792829485710cb9218192cf115bc7bbdfa0a26ae797` |

P3 `507cb04c38babcdc0050ddb064007a962efee0a2`, tree
`a600c16c2ef71852ec4002c10f1a09ac03f84280` and parent Q3, published these
exact files without alteration. Its clean final collection and preparation
images were respectively
`sha256:361ab7d677b1399bd0140f75d6cf7a9a30d350a7232fbd5529c1b2b9ddc000bd`
and
`sha256:db75500ff909ffae9fef32967820ec335fc880fb436c96f0db3a120a8911bce1`,
under build tag suffix
`p-507cb04c38ba-6aceaac85243-20260815T215336Z`. Their source receipt
`source.json` had SHA-256
`590b4a856f7d8420329c90aba1d026edfcfbc75767ad9dc27fe75954c59f61dd`;
the raw implementation receipt had SHA-256
`c998823eb1b065e161e9397d079ff10155d0d55870580afe5efd058f9b03c1c4`
and final execution implementation-receipt aggregate
`1115efbaca78ef8eab8bdf5551a598250a82af3812d3a23a2bee820ee600c1a6`.
No rehearsal, interface handoff, formal capture, or classifier export was
launched from P3.
The five historical files remain byte-exact recoverable from P3 and frozen
evidence.

That cohort remains valid historical evidence, but is ineligible for current
execution because the qualification receipt inventories every
`src/qcsd_lab/*.py` file and the Linux capture-integrity implementation commit
`47c91bb36dcddd3943253ee16141febbaf9041e8` changed `capture_session.py`,
`fidelity.py`, and `orchestrator.py`. Q4
`570851923bfaa24aa967f947c38f305138145776`, tree
`11f6946091247f17520958ab29014b7aa04dee1f`, is the documentation/deletion
child of that implementation commit and intentionally has no canonical
response-store v2. Its uniquely tagged qualification collection and prepare
images were respectively
`sha256:ef2e6a6b9464c34d80657c787d0b1fb15eb8ee03539db141c8cb4b7bcf5cc236`
and
`sha256:228fe4b3a8cf1287dc0d6fdc9a1ba627e1f6393f9d456de105c506f4111a9c88`,
under suffix `q-570851923bfa-6aceaac85243-20260817T164038Z`. Their
`source.json` SHA-256 was
`3d7448fc0025aa20d741ee6cffadca3b5b9312bd327853cfc47619b18819f43f`,
their raw implementation-receipt SHA-256 was
`a45875a057a495d5f5a6c30de7fd697bedc28dc856248e1eb3bdfbd2511d873f`,
and their implementation-receipt aggregate was
`6c1f190c8e5bfbf7951ea8aba081bb44ada4ffdc264089ff640fad89dca8a050`.

The Q4 image passed all 729 deterministic tests, with only the two
launcher-gated live tests skipped. Its first local-only `test live` then
passed the canonical capture path but exposed a stale controlled-test fixture:
the fixture relabelled a historical schema-five Walkie-Talkie profile as
schema six without deriving the added sender-framing cell. Neqo correctly
rejected that inconsistent test configuration before capture-clock
reconciliation. No public response qualification, rehearsal, interface
handoff, formal capture, or classifier export was launched from Q4. Commit
`32f8f4d816cf05ebc483cc547732d146225493c9`, tree
`d713ca9f665935a4dd953e242a636d2063ffc784`, repairs only the controlled
test fixture by deriving the current mold and matching prefix specification;
it does not change production capture semantics or Neqo F3. Q5
`af3403d60f5be008dc88cc52c6ce8ec5a34bc47c` is the documentation acquisition
child of that repair. Its clean image passed all 731 local prerequisite tests,
and its atomic exact-five qualification is the historical cohort published by P5.

The immediately preceding five-file transaction succeeded atomically from
clean Lab qualification source
`fcc6af4394b2b2f7dee5f8b1a214cd7673a9e0e8` (Q2), clean Neqo
`a8378520b9740be782bfe526cdb3eb05e6665571` (F2), qualification collection
image
`sha256:29a6e0adaa65d88e1e30afd3722f20f976fe14ed0676fb28d0448ec9155c0700`,
and prepare/actual qualification image
`sha256:ef5a3e7bcd20e8841f6c32064d40fcf94be48380f390146d5c039a49fc3665c0`.
Every sidecar binds implementation-receipt aggregate
`a8384fd28e9b22c0a683138c0d7a039db3abf927bcc6bd15ffc936bdf2f352a0`.
The deterministic first candidate (`candidate_index: 0`) qualified for all
five workloads. Fifteen independent connection epochs produced
`5 × 3 × 40 = 600` stable identity completions and 62,007 packet
observations. Within each workload, consecutive epochs retained at least the
required 30-second gaps, the maximum observed UDP payload was 1,200 bytes, and
no oversized packet was observed. Its historical hashes are:

| Workload | Sidecar SHA-256 | Derived schema-4 manifest SHA-256 |
|---|---|---|
| `getbootstrap-home-r3` | `4b63acf9dfa58413500cf8eaa34fc326a71a74d6c5df3404378543ea5ae707cf` | `c2dc6643caa028e137d717adf4fc13561b1e3c07bfbad28bef2267c0ed20fc92` |
| `cloudflare-quiche-r3` | `5728dda8668bc4aca816495d87c56038a7ed267b3e902518cdd7bd84b990c3d2` | `0b7794ebdf2155901f7398c95602e111e27087ce5f945a22b198391aa1054277` |
| `hyper-basic-client-r1` | `e30e877f068a199688948357b19c61803f94cad57123382e79812492750ab55e` | `7b5a2755a6bf47010289df74d40dc45aeaf58c30dd2a8ce32fc928eaa7b70332` |
| `serde-home-r1` | `86b6d3fcdc208e50b71e5cf957770a9e6319dae39a2e87b9d884f713c0ec3da4` | `e433468dcfee5c2ff6de7d4376588e7c104f60d13977894412ee58a04c88a212` |
| `rfc9114-text-r1` | `e55414ca9da748f17b89c02d762b1ac39f74acb349ed60d67833c1d5999e627b` | `20ce6ddd56b4684179c0cec8cac12bcef7ce8ef9327d954c2ecfe2239ec84bd9` |

That exact batch was published without alteration by P2
`8a8d605166bfc27c6a7b8907162119e055ca7ca2`. The clean final P2 collection
and preparation images were respectively
`sha256:a971810d2d26f7b87d380c96ae3516890b0715267a717879a4f93316caa96122`
and
`sha256:82434c67e194d29dc26c0cfa90014f01a2473c61ea92e9213c47ea1afc55297d`.
Q2, F2, P2, both qualification images, both final P2 images, the implementation
receipt, and all five files and derived manifests are now historical and
excluded from the replacement source lineage. The hashes remain recorded
verbatim for recovery and audit; none is active canonical evidence.

The fixed transaction published from clean Lab qualification source
`2290b1f1a100d0d36f2d5ada405d9c26d382716d` (Q), clean Neqo
`867246557ec719fc34552b60abf624895be2706c` (F), qualification collection
image `sha256:7b556344d65339e5cb399c37f7fe2a84ea248c9608e193f12269018c4ca47920`,
and prepare/actual qualification image
`sha256:5d85e8d7d090e5a29e77fe5751c65c70299e2cf1fc709cb62c3fde50c16e191d`.
Every sidecar binds implementation-receipt aggregate
`33fe7032e9bf35efb7bb4d3d84b7e2733f4e81a455baef0df1df0120687e2c35`.
That complete transaction is now superseded because the qualified acquisition
implementation changed in Neqo. All five deterministic first candidates
(`candidate_index: 0`) had qualified, for
`5 × 3 × 40 = 600` stable identity completions. Each epoch's 40 completions
used eight waves of five requests (`8 × 5`), epochs retained the 30-second
gaps, and the receipts recorded a maximum UDP payload of 1,200 bytes with zero
oversized packets. Its historical hashes are:

| Workload | Sidecar SHA-256 | Derived schema-4 manifest SHA-256 |
|---|---|---|
| `getbootstrap-home-r3` | `0bef93532273f59718e1fc4123eccfa6833922ff34f0d22cc9cf6cf03963cb5d` | `f411d539e656a5abd6a49c94da5a60d4e2898f141b1ebf86e48b2d2bd2ca4372` |
| `cloudflare-quiche-r3` | `d9dc5898464e7cb05f37fe9faf758250a72eaf14209913d7f2e56ffd31ced6ac` | `5d51d0f68d67c1847f49df01640c0ea6ca0a303dc3b567a4dc81f1ed5aef190a` |
| `hyper-basic-client-r1` | `4f8f51722d0c9a3d1d696f845bf2ee91ff45f3387b62c472115f682b5c353428` | `3fc7f34b90e9cbc423dc1f727bf157c5b3910b30bb61c2a52eef7a74cebf8a55` |
| `serde-home-r1` | `ee1f97b15a4f93702eda6c98b6578a2eb958df6f0f6a5129ab6b0a9d27ce3ca1` | `edb21e2792dfe59dd0c30f586709e5310e5b6ba5744a0c0a5ce334bd7746f797` |
| `rfc9114-text-r1` | `1d75fcf42ba170eabe76f5184adcc9551a4b3360d3e869f694108055360541af` | `e9dfb138adbdb18d43bf2c70eb34240dc54894a8e58aa1766853e4fbfdf178b6` |

Those exact files remain recoverable from Lab publication commit
`d5543406359528b1382222d8ef3d3cffd67b7d4d` and from frozen sealed results.

The earlier superseded five-file transaction was atomically published from clean Lab
commit `9953cf3a9a29a2cb5f6aaf02439cd13f318b6b39`, clean Neqo commit
`a3bd748c1b3f4e24f7dc88f673365e6842db51a7`, and qualification image
`sha256:c38afc629613bc8e7a5a82b55ad83a7e5787a51f780f14a199e9429be124ff43`.
Its historical hashes are:

| Workload | Sidecar SHA-256 | Derived schema-4 manifest SHA-256 |
|---|---|---|
| `getbootstrap-home-r3` | `37e5e6933b337872b49889886e5930f3aa1a7778032bc9ed85a0372885e8e95d` | `330a8d41db984fc43c0c324e091cfba2906871a47ee06d7fb9c2de0aac1db32a` |
| `cloudflare-quiche-r3` | `e8fe81526aec5fa9af2c1c03ad4f093732ecc738a02bd2dd997104dc253a1957` | `38dfa66be8b0a55857845853c237a37014fe47095328d8d32187871277c3ac3e` |
| `hyper-basic-client-r1` | `816d6bcc0c43cf0d672fc0f21cc0dd871d80fa9ca24ebcadcbc81b48d33a3bed` | `ffc24029a219246cd40060cd70953e4cf0a3590e59a700ec6c6f72ce7800b54d` |
| `serde-home-r1` | `46abffb21b7f93ebe328f56ad82819fcced1586aa3966de2d733fa7a5133018f` | `91ad7a33ed70cfcf4bc1b062e747b1371bad00ca16171ee3539f40755f18c9d3` |
| `rfc9114-text-r1` | `d76a4ff366a6b8dce65b42cca02d2a55c6333e649b28316fcdfe58b060d34c2f` | `9fb65d16532ff6290aa530e4829f87167cd784a30bfb68e5d7d921acd5da8fc5` |

Those exact files remain recoverable from Lab commit
`88569f268260b36f0c4ccfc36681f7a42887b66c` and from frozen sealed results.
All five previously recorded response-store v2 transactions, including Q5/P5,
are historical only. Canonical legacy `v2` retains only the POC5 Q6/F3 cohort
published by P6.
Commit `47c91bb36dcddd3943253ee16141febbaf9041e8` remains the causal production
implementation change, while `32f8f4d816cf05ebc483cc547732d146225493c9`
repairs only the prerequisite's controlled schema-six fixture.
No historical sidecar, implementation receipt, image, rehearsal, formal
sample, or export could be mixed into that legacy POC5 Q6/P6 lineage. At that
boundary, a clean P6/F3 final-image build, an excluded 30/30 rehearsal, and a
verified interface handoff were required before formal acquisition could
restart.

Each response-store v2 file is sidecar schema 2 and derives a schema-4
`qcsd-qualified-chaff-manifest` with `qualification_scope: response-only` and
the exact request-header primitive. It contains neither Walkie-Talkie
prefix-pack fields nor a fitting-artifact binding. Historical response-store
v1 sidecars and their schema-3 runtime manifests remain frozen-compatible
verification inputs, but a frozen cohort cannot mix schema 3 and schema 4.
This narrower evidence is valid only when every defended runtime kind is FRONT
or Tamaraw; a baseline-only campaign needs no chaff qualification, while
campaigns containing another defence continue to require the full-v2
qualification contract. FRONT and Tamaraw are algorithmic and require no
fitting, but they still require response qualification and all ordinary
runtime-fidelity gates.

### `run`

```shell
./qcsd-lab run <campaign.yml>
```

Validates and freezes the campaign inputs, executes its samples, and prints the
new result directory. A run is successful only when every planned sample is
accepted and eligible. A terminal incomplete run is still retained and sealed
for diagnosis.

Generic `run` is intentionally unavailable for prerequisite-ordered
schema-two class-study roles. Launch those campaigns through `./qcsd-lab
class-study capture`, which verifies the exact prerequisite ledger and grants
one process-local authority bound to the campaign, cohort, assembly, and any
successor identity before delegating to the orchestrator.

The checked-in `smoke.yml` defines the post-fit, 14-sample external evaluation:
Cloudflare QUIC and Bootstrap Introduction, one independent visit
each, the `as-defined` request policy, and all seven then-established
selectable modes: five research defences plus two controls. It
uses `research-1200`, the fixed seed `2026081204`, the mechanical
`static-control-1200.csv`, and the one create-only production bundle under
`artifacts/research-1200/`. The contract-5 predecessor is archived read-only at
`artifacts/research-1200-superseded-schema5-0a141768/`; it is verification-only
and rejected by current preflight. The canonical schema-6 bundle is published
from the sealed 120-sample fitting result and verifies. The independent result
at `results/research-smoke-1200/20260814T023209.708923Z` is complete: all 14
samples were accepted and eligible on their first attempt, with zero failures.
Both `verify` and `analyze` passed. The raw SHA-256 values of its
`evidence.sha256` and `experiment.json` are respectively
`59371aedf7dfa7ce289cce25766af763ede405d2f62527dc16c0d7882b42203a`
and `1cd8c415751736aa43677fac67f1bea666b941a47ae90d3658bf7cb2bf17d248`.

### `resume`

```shell
./qcsd-lab resume results/<campaign>/<run-id>
```

Continues one exact interrupted or incomplete result. Resume first checks the
frozen inputs, running source fingerprint, accepted sample hashes, and any
existing seal. It re-derives the campaign identity, purpose, limits, workload
records, defence bindings, seeds, and execution order from those frozen files;
editing and re-hashing `experiment.json` cannot change the run contract. It
never repeats accepted samples. If a successful attempt was
validated but interrupted around its atomic promotion, resume completes that
promotion from its recorded hashes without another network request. Otherwise
it removes only the partial working directory of an interrupted, unpromoted
attempt; completed failed attempts remain evidence.

For legacy generic campaigns, `max_attempts` is the automatic retry budget for
each invocation and an explicit `resume` begins a new operator-authorised retry
epoch for still-incomplete samples. BuFLO-study and schema-two class-study
campaigns use a stricter durable total instead: every physical collector launch
counts against the same per-sample limit across resumes, and an interrupted
launch is retained as a failure tombstone. Accepted samples remain immutable.
To avoid bypassing timing controls across a process restart, every previously
attempted origin waits one full configured cooldown before the first resumed
request.

The same coordinator-only rule applies to prerequisite-ordered class-study
resume. Use the `class-study` resume action with its required evidence roots;
generic `resume` cannot recreate the coordinator's identity-bound authority.
For durable BuFLO/class-study samples, a terminal
`StrictDefenseFidelityFailure` or `StrictClientDefenseExecutionFailure` is not
a retryable interruption: resume verifies and preserves the sealed incomplete
checkpoint, then stops.

### `verify`

```shell
./qcsd-lab verify <campaign.yml>
./qcsd-lab verify results/<campaign>/<run-id>
```

For YAML, `verify` is a non-executing preflight. It validates workload and
parameter files and prints the sample count and exact seeded execution order.
The checked-in `smoke.yml` now resolves the exact-six v2 qualification bindings
and current schema-6 bundle and preflights to exactly 14 samples. Reviewed
fixtures and the historical schema-5 artifact remain invalid substitutes.

For a result directory, `verify` checks the evidence index, exact authoritative
file set, every file hash, the experiment schema, frozen-input fingerprint,
the configuration re-derived from `inputs/campaign.yml`, each accepted
sample's artifact binding, and the external parameter receipts. Missing,
changed, additional, rebound, or path-escaping authoritative files fail
verification.

For `artifacts/research-1200`, `verify` requires the exact four-file fitted
bundle, checks the common provenance receipt and all artifact hashes, validates
source-result identity and sample contributions, requires exact Traffic
Morphing and Walkie-Talkie workload coverage, and runs the runtime-schema
checks. A fitted bundle is not a campaign result and does not have its own
`evidence.sha256`.

### `analyze`

```shell
./qcsd-lab analyze results/<campaign>/<run-id>
```

Verifies the sealed evidence, builds a complete replacement in a temporary
directory, and atomically replaces `derived/`. It creates:

- `summary.csv` with per-sample and paired-baseline metrics;
- deterministic SVG comparisons for every complete eligible paired visit;
- aggregate application-latency and wire-overhead SVGs;
- a self-contained `report.html` with its SVGs embedded.

The trace comparison preserves the tested QCSD view: incoming/outgoing
packet-time density, controller-action overlays, signed Ethernet-frame-size
scatter, an application-completion marker, and a shaded defence tail. No PDF
or qlog is produced. Deleting `derived/` and rerunning `analyze` reconstructs
it from `capture.pcapng`, `run.json`, and `schedule.csv` without modifying or
resealing evidence.

### Offline classifier-pilot handoff

The classifier exporter is intentionally not a `qcsd-lab` capture command. Run
the separate Docker wrapper from this checkout after every source result
verifies:

```shell
./classifier-pilot export classifier-poc5-v2 \
  results/research-classifier-poc5-baseline-01-1200/<run-id> \
  results/research-classifier-poc5-paired-01-1200/<run-id> \
  results/research-classifier-poc5-baseline-02-1200/<run-id> \
  results/research-classifier-poc5-paired-02-1200/<run-id> \
  results/research-classifier-poc5-baseline-03-1200/<run-id> \
  results/research-classifier-poc5-paired-03-1200/<run-id> \
  results/research-classifier-poc5-baseline-04-1200/<run-id> \
  results/research-classifier-poc5-paired-04-1200/<run-id> \
  results/research-classifier-poc5-baseline-05-1200/<run-id> \
  results/research-classifier-poc5-paired-05-1200/<run-id> \
  results/research-classifier-poc5-baseline-06-1200/<run-id> \
  results/research-classifier-poc5-paired-06-1200/<run-id> \
  results/research-classifier-poc5-baseline-07-1200/<run-id> \
  results/research-classifier-poc5-paired-07-1200/<run-id> \
  results/research-classifier-poc5-baseline-08-1200/<run-id> \
  results/research-classifier-poc5-paired-08-1200/<run-id> \
  results/research-classifier-poc5-baseline-09-1200/<run-id> \
  results/research-classifier-poc5-paired-09-1200/<run-id> \
  results/research-classifier-poc5-baseline-10-1200/<run-id> \
  results/research-classifier-poc5-paired-10-1200/<run-id>
./classifier-pilot verify classifier-poc5-v2
```

The retained legacy POC5 contract binds one workload to each of five distinct
class origins: `getbootstrap-home-r3` to `getbootstrap.com`,
`cloudflare-quiche-r3` to `cloudflare-quic.com`,
`hyper-basic-client-r2` to `hyper.rs`, `serde-home-r1` to `serde.rs`, and
`rfc9114-text-r1` to `www.rfc-editor.org`. Ten acquisition blocks each
contribute a 100-sample baseline result (20 visits per class) and a 150-sample
paired result (ten visits per class under undefended, FRONT, and Tamaraw). The
exact total is 1,500 undefended, 500 FRONT, and 500 Tamaraw captures. The
exporter separately retains the earlier schema-1 six-class and stable3
pipeline contracts and rejects mixed lineages.

The wrapper runs the exact collection image with networking disabled, all
capabilities dropped, the checkout and result evidence read-only, and the
handoff output writable as the invoking UID/GID. Direct
`uv run python tools/classifier_handoff.py ...` execution is an internal
developer path for controlled fixtures only: a native host process lacks the
executed qualification receipt required to verify these research results.

The destination must not exist. Export is create-only and atomic. Every input
must be a complete sealed result in which all planned samples are accepted and
eligible. Inputs are read-only; the exporter verifies each evidence seal before
copying anything and rejects duplicate sample IDs, mismatched block cohorts,
symlinks, or an existing destination.

Attempt acceptance and export apply the same Linux-local timing gate. Every
primary direct capture must use one reconciled, evidence-eligible
constant-offset clock segment with zero steps and timestamp residuals no larger
than 10 ms. The collector brackets each Linux realtime reading with repeated
Linux monotonic readings and charges both pairing uncertainties against the
same 10 ms elapsed-difference budget. A timing-repaired or anchor-drifted
attempt is retained as a bounded retry failure and is never promoted.
Fresh captures must record the `host` timestamp type and both endpoint pairing
uncertainties. The exporter retains read compatibility for historical sealed
four-anchor results that predate those fields; an explicit non-`host`
timestamp type is always rejected.

The handoff is self-contained:

```text
handoffs/classifier-poc5-v2/
  README.md
  dataset.json
  samples.jsonl
  SHA256SUMS
  raw/
    <opaque-sample-id>.pcapng
    <opaque-sample-id>.pcap
    <opaque-sample-id>.run.json
  stripped/
    <opaque-sample-id>.pcap
  traces/
    <opaque-sample-id>.csv
```

The formal handoff contains 2,500 samples: 7,500 files under `raw/`, 2,500
stripped PCAPs, 2,500 CSV traces, and the four top-level receipt/inventory
files. That is 12,504 regular files in total; `SHA256SUMS` governs the other
12,503 files and deliberately excludes itself.

`raw/` preserves byte-exact PCAPNG evidence, a full-packet classic-PCAP format
conversion, and the corresponding Neqo run receipt for a trusted collaborator
who needs to build a different projection. Both capture formats are restricted
material: they contain real endpoint metadata, absolute times, and QUIC Initial
traffic from which handshake metadata may be recovered; the run receipt also
contains URLs and request configuration. They must not be the default
classifier input.

`stripped/` contains synthetic classic PCAP with nanosecond timestamps. Every
packet uses the same fixed documentation-only MAC addresses, TEST-NET IPv4
addresses, and UDP ports; its UDP payload is all zero. It preserves only the
relative packet time, client-relative direction, packet count, and Ethernet
`frame.len`. It is deliberately not a replayable QUIC exchange. `traces/`
provides the same model-facing projection directly as
`relative_time_ns,direction,length_bytes,signed_length_bytes`, with client
egress positive and server ingress negative.

In the schema-2 POC handoff, `class_label` is the approved origin hostname and
`workload_id` retains the exact frozen request-graph identity. `samples.jsonl`
maps each opaque sample ID to those identities, defence, request policy, visit,
source result, shared `acquisition_block_id`, split, and exported file hashes.
The exporter rejects overlapping or out-of-order acquisition blocks.
Undefended samples from
acquisition blocks 01--08, 09, and 10 are respectively `train`, `validation`,
and `test`; all FRONT and Tamaraw rows are `inference` and
`inference-only`, regardless of their temporal block. The exporter derives and
validates these assignments rather than accepting a caller-supplied split list.
`dataset.json` binds the checked-in campaign, source result, and evidence-index
hashes, declares the projection, and summarizes classes, defences, blocks, and
splits. `SHA256SUMS` closes the exported file inventory. These receipts protect
handoff integrity;
they do not replace the authoritative result seals.

Verify the portable inventory from inside the handoff root:

```shell
cd handoffs/classifier-poc5-v2
sha256sum -c SHA256SUMS
```

For the retained schema-1 pilots, `--splits` entries still align with result
roots in command-line order. POC5 instead requires all twenty roots in the
exact baseline/paired order shown above. `verify` rechecks the closed handoff
inventory, protocol counts, split policy, and all hashes without reading the
original result directories.

Josh should train from `traces/` or `stripped/`, use `class_label` as the
prediction target, and fit preprocessing, features, classifiers, and
hyperparameters only from undefended `train`/`validation` rows. The undefended
`test` rows provide the clean baseline; FRONT and Tamaraw are locked
inference-only conditions. Paths, `run.json`, defence/controller schedules,
and other metadata are not model features.

### `fit`

```shell
./qcsd-lab fit results/<fitting-campaign>/<run-id>
./qcsd-lab verify artifacts/research-1200
```

`fit` first fully verifies a complete sealed fitting result with exactly six
workloads, ten visits per workload, the `as-defined` and `half-duplex` request
policies in that order, only the undefended baseline, and the
`research-1200` profile. All 120 samples must be accepted and eligible.

It then deterministically and atomically creates exactly:

```text
artifacts/research-1200/
  traffic-morphing.json
  wtf-pad.json
  walkie-talkie.json
  provenance.json
```

The common `provenance.json` receipt hashes the three runtime files and binds
the source evidence, contributing samples, profile, ceiling, fitting decisions,
and workload coverage. It contains no timestamp or absolute path. An identical
rerun is idempotent; different content at the fixed destination is rejected.
The fitting result is never modified. No fitted research bundle exists until
this command succeeds against the real 120-sample result.

### `test`

```shell
./qcsd-lab test
```

Runs the deterministic Python suite in the collection image. It does not use
the public Internet or start a research campaign.

### `test pinned-cdp`

```shell
: "${COHORT_VERSION:?export the cohort version bound by a completed build}"
BUILD="artifacts/buflo-study/build-execution-v${COHORT_VERSION}.json"
PINNED_CDP="artifacts/buflo-study/pinned-cdp-execution-v${COHORT_VERSION}.json"
./qcsd-lab test pinned-cdp \
  --cohort-version "$COHORT_VERSION" \
  --build-execution-receipt "$BUILD" \
  --destination "$PINNED_CDP"
```

Runs only the real-browser recursive-target probe in the preparation image
bound by the exact cohort build/completion pair. That image checksum-downloads only
the pinned arm64 Chromium revision-1200 archive, safely extracts its fixed
466-file distribution, and revalidates the archive, executable, browser
manifest, complete Chromium distribution, complete Playwright package before
and after its two-file conditional patch, and the create-only driver receipt.
The launcher rejects an alternate
build or destination path, a conflicting image override, a symlink, and an
existing destination before the probe. It runs as the invoking UID:GID, drops
every capability, and uses Docker network mode `none`. Its guarded writable
mount can create the one requested receipt but over-mounts every pre-existing
sibling evidence object read-only. The loopback HTTP server exercises a
cross-site iframe, dedicated and shared workers, duplicate URLs, a redirect,
request-stage interception ownership, and deliberate context shutdown. A
failure or interruption publishes no receipt. Before launch the wrapper also
requires the exact clean Lab/Neqo checkout embedded in the preparation image,
so dirty or alternate launcher/module bytes cannot claim the guarded execution
contract. The repository's separate opt-in Chromium integration tests exercise
real sibling-popup rejection and five overlapping drivers (one exclusive and
four ordinary), including marker isolation, native-worker behaviour, and clean
teardown; these remain code-gate tests rather than acquisition samples. This is
an environment and foundation gate, not a public-network acquisition or
scientific sample.

### `test browser-egress`

```shell
: "${COHORT_VERSION:?export the cohort version bound by a completed build}"
BUILD="artifacts/buflo-study/build-execution-v${COHORT_VERSION}.json"
BROWSER_EGRESS="artifacts/buflo-study/browser-egress-qualification-v${COHORT_VERSION}"

./qcsd-lab test browser-egress create \
  --cohort-version "$COHORT_VERSION" \
  --build-execution-receipt "$BUILD" \
  --result-root "$BROWSER_EGRESS"
./qcsd-lab test browser-egress verify \
  --cohort-version "$COHORT_VERSION" \
  --build-execution-receipt "$BUILD" \
  --result-root "$BROWSER_EGRESS"
```

`create` admits the create-only root and begins the ordered 110-vector live
chain. If and only if it is interrupted after that root has been published,
continue with the same arguments and replace `create` with `resume`; never
delete the root or invoke `create` again. `verify` is read-only and succeeds
only after the final receipt and closed raw/projected inventory deep-verify.
The resulting root is passed to `class-study foundation` as
`--browser-egress-qualification-root "$BROWSER_EGRESS"`.

### `test live`

```shell
./qcsd-lab test live
```

Starts two controlled local HTTP/3 servers and runs the direct-capture
acceptance tests. This is the bounded networking gate for capture startup and
tail coverage, exact endpoint filtering, interface-offload checks, UDP-payload
ceiling enforcement, runner/PCAP reconciliation, and overlapping connections
to distinct origins within one sample. It exercises the canonical sealed
baseline workflow plus a direct, explicitly nonauthoritative schema-6
Walkie-Talkie wire check with test-local A/R/C inputs. It is not evidence for
the six-workload qualification, does not authorize a campaign artifact, and
does not consume public fitting visits or create research artifacts.

## Profiles

- `live` uses a 1200-byte ceiling and deliberately reduced FRONT, Tamaraw, and
  event limits for bounded smoke tests.
- `research-1200` copies every non-size value from the tagged published source
  profile and changes only the common UDP ceiling and every defence packet-size
  field from 1450 to 1200. FRONT remains 900/1200 packets over 0.1–2.5 seconds;
  Tamaraw remains 5/20 ms with modulo 100; published data-driven budgets remain
  unchanged. This is the study's explicit source-default 1200-byte adaptation,
  not an implicit CLI default.
- `published` retains the tagged source's 1450-byte settings for compatibility
  and controlled source comparison. Modern Neqo, different workloads, and a
  different network mean that selecting it is not an exact reproduction of the
  paper experiment or its results.

All campaign and parameter receipts use those exact spellings. A
`research-1200` schedule or artifact containing a 1201-byte target is invalid.

## Campaigns

A campaign has one schema:

```yaml
schema: 1
name: example
purpose: evaluation            # smoke, fitting, or evaluation
seed: 20260806
profile: research-1200         # live, research-1200, or published

workloads:                     # ID maps to visit count
  prepared-site-a-r1: 1        # evaluation/fitting require preparation receipts
  prepared-site-b-r1: 1

request_policies:
  - as-defined                 # or half-duplex

defenses:
  - undefended
  - front
  - tamaraw
  - name: static-control
    kind: static
    schedule: ../defense-params/static-control-1200.csv
    mode: chaff-only
  - name: traffic-morphing
    kind: traffic_morphing
    parameters: ../../artifacts/research-1200/traffic-morphing.json

limits:
  timeout_seconds: 120
  max_response_bytes: 1048576
  capture_seconds: 180
  capture_megabytes: 64
  max_attempts: 3
  per_origin_cooldown_seconds: 30
  settle_seconds: 1
```

Workload IDs resolve only through `config/workloads/<id>.json`. A workload
contains concrete resources: URL, safe request headers, dependencies, and
preparation provenance where available. It does not carry an evaluation role
or an implicit repetition count.

Purpose is an evidence constraint, not another execution engine. `smoke`
permits the checked-in reviewed fixtures, `fitting` is restricted to
undefended samples, and `evaluation` requires the sealed research bundle
whenever a data-driven defence is selected.

`as-defined` starts every request whose declared dependencies are satisfied.
That can create overlapping streams and connections. `half-duplex` additionally
waits for the current application stream to finish before starting another.
It is an execution policy, not a second workload format.

Static consumes a signed schedule file. The checked-in
`static-control-1200.csv` is four alternating 1200-byte events at 25, 30, 35,
and 40 ms. The 25 ms startup lead lets the asynchronous client provision its
chaff stream before the first exact slot. It is a mechanical schedule-loading
and direction control, not a fitted defence or effectiveness result. Traffic
Morphing, WTF-PAD, and Walkie-Talkie consume a JSON parameter file with an
adjacent receipt: smoke fixtures use `.provenance.json` beside each file,
while the research bundle uses one shared `provenance.json`. Campaign loading
validates these files, their defence/profile binding, and their hashes before
a network run, then freezes copies under `inputs/`. Reviewed engineering
fixtures are permitted only for a `smoke` campaign; an evaluation campaign
requires sealed fitted artifacts.
The fitted Walkie-Talkie source envelopes remain in the raw HTTP/3
request-stream cell domain, and pairing still minimizes the base symmetric
element-wise-mould padding cost. The runtime mould is a separate adaptation: it
adds one 1200-byte sender-framing cell to every positive outgoing component and
one 1200-byte receiver-continuation cell to every positive incoming component.
The sender cell carries QUIC/HTTP/3 STREAM framing and mandatory control
overhead that is absent from request-stream offsets. The receiver cell exceeds
the configured 1000-byte parser allowance and is held as a causal event rather
than eager ordinary credit.

The client provisions the exact workload-specific one-shot chaff cohort before
the first due moulded outgoing actions and never replenishes it. A chaff stream
becomes a continuation candidate only when its zero-required-insert-count,
nonblocking QPACK request has a positive final size and the complete,
gap-free request-stream range `[0, final-size)` plus FIN is peer-acknowledged.
Retransmitted and acknowledged offsets are union-deduplicated. Before the first
incoming base allocation, the latched survivor gate requires a
peer-acknowledged nonblocking survivor count of at least the total number of
remaining receiver continuations plus one. Distinct deterministic pristine
reserves cover every remaining nonzero incoming component and remain reserved
across later positive outgoing components until their corresponding
continuation is allocated.

A continuation is eligible only after issued base events have been requested,
their request signals observed, and any application-batch gate has opened. It
is normally released after all base events have been issued. It may be released
earlier when a real reported ordinary nonreserved-capacity snapshot is below
one full cell, including zero; an unknown snapshot never enables early release.
Allocation then follows the same coalesced-tail-or-oldest-reserve rules below,
while the corresponding oldest reserve is discharged exactly once. This closes
the reserve-capacity deadlock while retaining base-first behaviour whenever at
least one ordinary full cell is available. The initial survivor gate still
applies before either early continuation or base allocation.

Every retry recomputes live unconsumed base debt. When exactly one
peer-acknowledged nonreserved header-phase chaff stream carries a positive debt
at or below the parser ceiling, an already advertised tail is extended in
place. If the same exact tail is awaiting its `MAX_STREAM_DATA` advertisement,
the continuation and oldest reserve are retained until that advertisement is
observed, after which the same stream is extended. Otherwise the whole cell is
released to the oldest retained peer-acknowledged pristine reserve regardless
of unrelated live base debt. Split or ledger-inconsistent tails are
ineligible, and each corresponding reserve is removed exactly once.

Ordinary base receive allocation exhausts application streams before
peer-acknowledged nonreserved controlled chaff streams; exact capacity precedes
bounded provisional framing claims. A reserve is excluded from ordinary
capacity until release. If a reserve is lost, allocation holds while the
horizon is deterministically reconstituted from an eligible peer-acknowledged
pristine member of the already provisioned cohort; it fails closed only when no
eligible replacement remains. No new request replenishes the cohort, and the
contract promises neither targetless request retransmission nor generic
post-loss liveness. Retryable unadvertised continuation rollback or requeue
restores the corresponding all-future reserve before further base allocation.

Manual receive retains an exact `STREAM_DATA_BLOCKED` report only while a
stream is pristine and wholly pre-header. The original small-floor path remains
available when the prepared body floor and requested, advertised, and known
limits agree below the absolute 1,000-byte framing target. A positive floor no
longer discards the proof merely because scheduled credit has already raised
the requested limit: that residual branch is permitted only when the
controller proves one live contiguous advertised scheduled range from the
effective initial receive offset through
`requested == advertised < 1000`, with known capacity beyond it. Either branch
appends only an ownerless, slotless parser lease through absolute offset 1,000,
bounded by the existing lifetime `max_stream_data_excess` budget. The residual
branch neither moves nor satisfies the scheduled range or its slot; only
consumption retires that debt, and any typed HTTP/3 progress invalidates the
retained transport proof. This bounded bootstrap permits one atomic HEADERS
frame to cross the residual scheduled prefix without changing a defence
schedule, parameter, slot-accounting rule, or capture-fidelity gate.

A separate terminal-tail bridge covers the corresponding post-DATA boundary
without changing scheduled ownership. Once incoming scheduling is complete,
with no queued assignment, continuation, or same-stream backing, a pristine
typed boundary may receive one ordinary 16-byte parser lease only when its
entire outstanding scheduled tail is already advertised, contiguous, and
between one and fifteen bytes; requested and advertised limits agree, known
exact capacity continues beyond them, and the full 16 bytes remain inside the
existing lifetime parser allowance. The lease is unowned and slotless. Its
grant or advertisement satisfies nothing: the original tail retains its slot
and only consuming those scheduled bytes can settle it. Gapped, partial,
post-cap, continuation-owned, or nonterminal states remain fail-closed.

FRONT alone opts into prearming its frozen packet targets. A future incoming
target remains private and ineligible before its exact not-before time; its
endpoint and deadline are frozen, with the strict 5 ms deadline unchanged.
Each drive reconciles every due fixed event and its incoming credit before
eligible output and ordinary input, using fresh monotonic time and absolute
wake instants. Release uses ceiling conversion and deadlines use floor
conversion, so prearming cannot transmit early or extend a deadline. Static
and non-FRONT dynamic schedules retain their existing activation behaviour.

Receive-control batches are globally and transactionally preflighted using
typed lifecycle outcomes. Exact current-batch identities and persistent
accepted-but-unencoded `MAX_STREAM_DATA` identities are validated together;
shared transitive closures are cancelled once, transport rollback is previewed
in LIFO order, and encoded or advertised credit is never revoked. A
lifecycle-invalid receive-limit increase or manual-receive configuration
becomes terminal or gone only when unavailability is proven; ledger, ordering,
identity, and rollback inconsistencies remain fatal. Resulting observations
and defence realizability are flushed before unrelated actions, while a fatal
case records both the raw action and typed error. This changes no seed,
defence parameter, schedule, fidelity threshold, or acceptance threshold.

The initial priority-aware selector binds a known-valid same-origin selected
source resource; its derived chaff projection is dependency-free and has exact
qualified body capacity. Campaign loading binds the prepared workload and
runtime rechecks endpoint-relative eligibility. Three independent response
qualifications use `max(5, required_chaff_streams)` parallel requests to bind
the response identity and body length. Three independent schema-2 prefix
qualifications prove every component's exact sender-framed targets, cumulative
application and one-shot chaff requests through FIN, peer acknowledgement of
every required chaff-request STREAM range and FIN, and zero targetless STREAM
bytes. These bytes are runtime-only falsification evidence and never enter
fitting.

Parser consumability and source-envelope bounds remain runtime fail-closed
preconditions. FRONT additionally avoids stranding a final partial receive
slot: for a `ChaffOnly` schedule whose incoming side is proven complete, the
last untouched whole slot prefers a peer-acknowledged pristine chaff stream
with a full cell of exact capacity. This changes no capture-clock acceptance
rule. FRONT and Tamaraw remain profile-generated and have no external fitted
files.

Reported Walkie-Talkie runtime padding cost and scheduled bytes include both
sender-framing and receiver-continuation cells. The base symmetric pairing
objective is unchanged, but the adapted runtime mould and cost are not the
historical schema-5 values. Neither qualification evidence nor the controlled
wire smoke establishes a general HTTP/3 property or defence effectiveness.

Only fields shown by the schema are accepted. Campaigns do not carry dataset,
classifier, monitored/unmonitored, open-world, split, projection, or runtime
header-policy settings, and command behaviour is not embedded inside the YAML.
A campaign with several defences must include exactly one
undefended baseline so response identity and overhead can be paired. A
single-defence campaign is valid for capture mechanics, but cannot produce a
paired comparison unless its prepared workload supplies the expected response
identity.

## Workload catalogue and research cohort

The workspace-level [`results.zip`](../results.zip), SHA-256
`103a82cb95eaa305e38b0084ba16744429b273146be80ab05c7653d52bf66b11`, is a
catalogue of 17 Chromium-observed request graphs from the retired discovery
workflow. It is not a lab result, fitting corpus, or accepted campaign input. Its historical
`header_policy` and replay records describe how candidates were observed; they
do not reintroduce runtime header policies into the consolidated lab.

`prepare` promotes a candidate only after origin filtering and three stable
undefended Neqo runs. Each run must resolve the exact 1200-byte UDP-payload
ceiling, produce valid runner packet evidence in both directions, and contain
no UDP payload above 1200 bytes, including handshake traffic. The frozen
preparation receipt records the packet-file SHA-256 plus incoming, outgoing,
and total packet counts, maxima, and oversized counts for every run. Research
validation requires that exact receipt; older manifests remain readable but
are not research inputs.

A case-insensitive Chromium-header merge correction made the earlier `-r1`
manifests ineligible for research because they contained duplicate header
names. The earlier catalogue cohort's `-r2` manifests then predated absolute
whole-run UDP qualification: their application traffic used a 1200-byte
configuration, but their receipts did not prove that every handshake and
application datagram respected that ceiling. Those two earlier generations
remain historical preparation evidence only; the separately prepared POC5
Hyper r2 replacement has a current whole-run UDP receipt.

The frozen research adaptation cohort was therefore prepared from the clean,
corrected image as six new `-r3` workloads. Each preparation passed three
stable undefended Neqo runs and recorded zero datagrams above 1200 bytes over
the complete packet ledger:

| Workload | Resources | Prepared-manifest SHA-256 |
|---|---:|---|
| `getbootstrap-home-r3` | 9 | `863638bb6bf7a27c2a4e9184dcb9c3db8d748af1e0da1b875d24a21233b92ca2` |
| `bootstrap-introduction-r3` | 9 | `e228029e7c987c63f8218e5471375e62e6d4557825bc6c4c0cb4bbfa0be6c16b` |
| `apache-traffic-server-docs-r3` | 18 | `8f4fa9b10c4488ff99d30e7ac8b2b784867416c84635afe96b9c4ef45ab71ecd` |
| `nginx-quic-r3` | 11 | `56ddd2eee52affc59d0062c83b49e2fd435d0fe9ca40f4f0b30e65c156e7ef09` |
| `cloudflare-quiche-r3` | 1 | `e608366c95d6902234b4a705043435b3868f9572bcb8e103feb71db3110cbacc` |
| `nghttp2-ngtcp2-r3` | 8 | `a871e1d783b52a79fb1f72761ea2771fced38ba408fbed0896a3c280d20927f1` |

The final preparation pass rejected these candidates without weakening the
qualification gates:

| Candidate | Rejection |
|---|---|
| Behance | Whole-capture UDP payload maximum was 1452 bytes. |
| Chromium project pages | A pre-handshake Initial datagram was 1280 bytes. |
| aioquic | The endpoint refused the preparation connection. |
| Guardian | Whole-capture UDP payload maximum was 1280 bytes. |
| R10 | Exact response identity was unstable across the three runs. |
| TeamViewer | The retained assets were orphaned from the source/final navigation root. |

NGINX QUIC and Bootstrap Introduction passed after those rejections and were
promoted. The cohort contains six unique request graphs over five distinct
origins: the two Bootstrap graphs share an origin and many static assets. That
correlation can make their fitted distance or mould-padding cost smaller than
for independent sites, so this is explicitly a reproducible QCSD adaptation
cohort, not six independent websites or a representative sample of the
rejected population. Fitting and later evaluation reference the same frozen
files and hashes but execute independent network visits; fitting traces are
never reused for evaluation.

## Execution order and concurrency

Expansion is deterministic:

```text
workload declaration order
  -> request-policy list order
    -> visit 0..N-1
      -> seeded shuffle of the configured defences
```

The sample count is:

```text
sum(workload visit counts) * number of request policies * number of defences
```

Samples are executed one at a time. A sample is one Neqo page-load process and
one PCAP. Inside that sample, Neqo owns one connection per distinct origin;
connections and ready request streams can progress simultaneously. The
orchestrator does not merge those origins into separate samples and does not
run two samples concurrently. Per-origin cooldowns are applied between samples
and conservatively restarted for previously attempted origins after `resume`.

The seed freezes defence order and per-sample defence randomness. It does not
make independent live network responses identical. Eligibility instead checks
that delivered response identity matches the undefended member of the same
workload, policy, and visit.

## Result contract

This working copy's `results/` directory may also contain two explicitly
documented historical snapshots from the retired workflows. See
`results/README.md`; they are preserved data, not supported result formats, and
no active command writes them.

```text
results/<campaign>/<run-id>/
  experiment.json
  evidence.sha256
  inputs/
    campaign.yml
    source.json
    workloads/
      <workload>.json
    runtime-workloads/
      <selected-workload>.json
    chaff-prefix-specs/
      <workload>.json
    chaff-qualifications/
      <workload>.json
    chaff-manifests/
      <workload>.json
    defense-parameters/
      <defence>/
        schedule.csv | parameters.json
        provenance.json
  samples/
    <workload>/<policy>/visit-000/<defence>/
      capture.pcapng
      neqo/
        run.json
        packets.csv
        events.csv
        schedule.csv
  failures/
    <sample-id>/attempt-001/
      ... diagnostic working evidence ...
  derived/
    summary.csv
    plots/
      aggregate-latency.svg
      aggregate-overhead.svg
      <workload>/<policy>/visit-000/trace-comparison*.svg
    report.html
```

Every remaining file has one job:

- `experiment.json` is the sole experiment receipt and state machine. It owns
  provenance, frozen configuration, exact execution order, sample identity,
  attempts, state, eligibility, failures, diagnostics, accepted artifact
  hashes, and totals.
- `evidence.sha256` is the terminal SHA-256 index. SHA-256 is a content
  fingerprint: changing one covered byte changes the expected digest. The
  index exactly covers `experiment.json`, `inputs/`, `samples/`, and
  `failures/`; it deliberately does not cover itself or `derived/`.
- `inputs/campaign.yml` is the exact campaign submitted to the run.
- `inputs/source.json` records the exact collection-image ID, lab and Neqo
  commits, and dirty/patch provenance used by resume.
- `inputs/workloads/*.json` are the exact prepared graphs supplied to the
  campaign. They are kept once, rather than copied beside every sample.
- `inputs/runtime-workloads/*.json` are the exact stripped runnable graphs for
  the campaign-selected workloads.
- `inputs/chaff-prefix-specs/*.json`, `inputs/chaff-qualifications/*.json`, and
  `inputs/chaff-manifests/*.json` freeze the exact schema-6 Walkie-Talkie
  qualification cohort and its derived runtime projections.
- `inputs/defense-parameters/**` contains the exact external schedule or
  parameter/provenance pair selected by the campaign. Directly configured
  defences create no directory here.
- `capture.pcapng` is the direct Ethernet evidence, filtered after collection
  to the exact bidirectional endpoint tuples reported by Neqo.
- `neqo/run.json` is the runner receipt: resolved configuration, endpoints,
  response identity, completion, timing, and defence diagnostics.
- `neqo/packets.csv` is Neqo's transport-datagram record used to reconcile the
  runner with the independently captured PCAP.
- `neqo/events.csv` records ordered runner, application, and controller events
  needed to interpret completion and defence behaviour.
- `neqo/schedule.csv` records one terminal row per scheduled slot and its
  observed realisation. `target_time_us` is the defence's requested time;
  `action_time_us` is the first adapter action issued for that slot, including
  an owned parser-liveness lease. Current terminal rows use outcome schema 3;
  the appended nullable `terminal_defense_elapsed_us` is the controller's
  exact terminal-resolution offset from defence start, floored to
  microseconds. It is populated only in `schedule.csv` and remains blank in
  `events.csv` and `packets.csv`. Ordinary terminal resolutions cannot predate
  their targets; a typed failed-attempt cancellation may resolve a future slot
  early, but such a missed row cannot enter accepted candidate evidence. For
  current incoming fixed opportunities,
  `credit_advertised_at_us` is the complete local on-wire `MAX_STREAM_DATA`
  boundary that rearms cadence, while `credit_consumed_at_us` is the distinct
  later process-clock peer stream-offset-consumption boundary that terminalises
  the slot; both delay columns are measured from `action_time_us`. The handoff
  translates this process clock through the receipted defence-start anchor
  before reconciling it with the defence-relative terminal time. None of these
  fields claims scheduled server-datagram timing or size. The same versioned
  nullable suffix is present in `packets.csv` and `events.csv`. These records
  provide plot overlays and fidelity metrics.

  For schema-4 CS-BuFLO stop/drain evidence, schedule reconstruction reports
  terminal counts strictly before, exactly at, and at or before the stop
  timestamp. The Rust snapshot must fall between the strict and inclusive
  counts: controller observations sharing a timestamp have a stable production
  order that cannot be inferred from timestamp comparison alone.
- `failures/<sample-id>/attempt-NNN/` retains logs, partial captures, runner
  output, and other diagnostics produced by a completed failed attempt. The
  exact contents depend on the failure stage; the structured current failure
  is in `experiment.json`.
- `derived/summary.csv` is the reproducible metrics table.
- `derived/plots/**/*.svg` are reproducible vector figures.
- `derived/report.html` is the reproducible, self-contained report and links
  back to authoritative sample files.

An accepted sample contains exactly the five listed files. There is no
`sample.json`, fidelity sidecar, JSONL index, resolved-workload duplicate,
normalized-trace copy, PDF, secondary index, or qlog.

## Capture, acceptance, and recovery

For every attempt the collector follows this boundary:

```text
start dumpcap -> start Neqo -> application completes -> defence tail
  -> settle interval -> stop dumpcap -> filter to Neqo endpoint tuples
```

The collection image is Linux-native and explicitly requests dumpcap's
`host` timestamp type on its container `eth0`. Packet evidence is compared
only with the Rust runner's Linux monotonic timeline. Windows QPC, W32Time,
PowerShell, WSL status flags, and any other outer-host clock are not capture
inputs or admission requirements. The timing contract applies on native Linux
and Linux container hosts. The current image and pinned browser/toolchain
receipts are AArch64-only and reject another target architecture. Supporting a
different architecture requires a new, explicitly pinned image contract,
architecture-specific binary receipts, validation, and cohort; it is not a
transparent rebuild of the present image.

An attempt is promoted only after direct-capture validation, endpoint-count
validation, response completion, interface GRO/GSO/TSO/USO evidence,
profile-wide UDP-payload-ceiling checks, and bounded runner/PCAP reconciliation.
That reconciliation must have one constant-offset segment, zero clock steps,
packet residuals no larger than 10 ms, and a bracket-uncertainty-aware Linux
realtime/monotonic elapsed difference no larger than 10 ms. The paired visit
then adds response-identity and defence-realisation checks.

When a prepared workload freezes `expected_responses`, every otherwise
successful attempt must also match the exact prepared response signature:
resource ID, HTTP status, delivered byte count, body SHA-256, and successful
outcome. This gate runs before promotion. Drift is retained as the retryable
fidelity failure `StrictPreparedResponseIdentityFailure`, not promoted as an
accepted-but-ineligible sample. Crash recovery applies the same gate to a
successful terminal attempt before completing an interrupted promotion, so a
restart cannot bypass it. Failed attempts stay under `failures/`; a successful
attempt is moved once to the canonical sample path and is not duplicated.

`experiment.json` is checkpointed atomically. Accepted files are independently
bound by hashes before the terminal seal is written. A successful attempt's
diagnostics and prospective artifact hashes are checkpointed before its exact
five-file directory is atomically installed. Resume can therefore finish an
interrupted promotion without recollection. Verified accepted work is reused;
only a genuinely partial, unpromoted working attempt may be discarded.

See [METHODOLOGY.md](METHODOLOGY.md) for the scientific interpretation of the
observer, pairing, fidelity, and derived metrics.

## Research readiness and five-class classifier proof of concept

The post-fit 14-sample evaluation and 120-sample fitting campaign definitions
are checked in, and their completed results are sealed locally. The six-workload
fitting cohort is frozen. The later classifier study is a separately authorized
five-origin, three-condition closed-world proof of concept. The relevant exact
expansions below are a retained historical ledger; they do not define the
current 100-class, 900-certification-cell, 16,000-capture endpoint:

- fitting: six workloads × ten visits × two request policies × undefended =
  120 samples;
- post-fit smoke: two workloads × one visit × one request policy × seven modes
  = 14 samples;
- deferred six-class classifier pilot: seven independently sealed blocks ×
  six workloads × one visit × one request policy × seven modes = 42 samples
  per block and 294 samples in the complete pilot;
- immediate three-class classifier pilot: seven independently sealed blocks ×
  three workloads × one visit × one request policy × seven modes = 21 samples
  per block and 147 samples in the complete, now-superseded pipeline pilot;
- POC5 rehearsal: five workloads × two visits × one request policy ×
  undefended/FRONT/Tamaraw = 30 samples, all excluded from the formal corpus;
- POC5 formal corpus: ten temporal blocks × five workloads ×
  (30 undefended + 10 FRONT + 10 Tamaraw visits) = 2,500 samples;
- superseded pre-final rehearsal: six workloads × one visit × one request
  policy × seven modes = 42 samples;
- superseded seven-mode final: six workloads × three visits × one request
  policy × seven modes = 126 samples.

The retained legacy POC5 workload/class bindings were exactly
`getbootstrap-home-r3`/`getbootstrap.com`,
`cloudflare-quiche-r3`/`cloudflare-quic.com`,
`hyper-basic-client-r2`/`hyper.rs`, `serde-home-r1`/`serde.rs`, and
`rfc9114-text-r1`/`www.rfc-editor.org`. The prepared Haxx workload
`http3-explained-en-r1` is not used by the rehearsal, formal campaigns, or
handoff. FRONT and Tamaraw use their fixed research-profile algorithms and
seeds; the POC neither consumes nor refits the Traffic-Morphing, WTF-PAD, or
Walkie-Talkie artifacts. The legacy POC5 recovery contract requires five
response-store v2 sidecars (schema 2) deriving schema-4 runtime manifests,
with no prefix-pack or fitted-data dependency. All previous v2 transactions
are superseded, and canonical legacy `v2` contains only the POC5 Q6/F3 cohort
published by P6. The historical Q5 image, incorporating Linux-local capture
integrity commit
`47c91bb36dcddd3943253ee16141febbaf9041e8`, passed all 731 local prerequisite
tests before its atomic
qualification, and the P5 final images then passed their image and campaign
preflights; the excluded rehearsal nevertheless rejected the stale Hyper r1
identity as recorded above. The completed Q6/F3 qualification remains
published by P6 as legacy POC5 compatibility evidence; it is not qualification
or image provenance for `classifier-multiorigin5-v2`.
Historical v1/schema-3 evidence remains readable only for its frozen
compatibility role.

Each temporal block has two campaign files:
`classifier-poc5-baseline-NN.yml` contributes 20 undefended visits per class,
and `classifier-poc5-paired-NN.yml` contributes ten visits per class under each
of undefended, FRONT, and Tamaraw. Thus every block contributes 30/10/10 per
class without extending the campaign schema. The workload order rotates so
every class occupies every workload position exactly twice across ten blocks.
The paired seeds were selected prospectively from deterministic plan expansion;
each class/condition occupies each of the three within-visit positions 32--35
times across its 100 visits.
Blocks 01--08, 09, and 10 supply the undefended 240/30/30
train/validation/test split per class. All 100 FRONT and all 100 Tamaraw rows
per class are inference-only. Run baseline before paired in odd-numbered
blocks and paired before baseline in even-numbered blocks, verify both results
immediately, and retain the shared temporal block in the handoff. The exporter
accepts the twenty result arguments in canonical
`baseline-01, paired-01, ..., baseline-10, paired-10` order, checks sealed
timestamps for the odd/even capture chronology, and requires each pair to
finish before the next block starts.

```shell
./qcsd-lab verify config/campaigns/classifier-poc5-rehearsal.yml
./qcsd-lab run config/campaigns/classifier-poc5-rehearsal.yml
./qcsd-lab verify results/research-classifier-poc5-rehearsal-1200/<run-id>
./classifier-pilot export classifier-poc5-rehearsal-v2 \
  results/research-classifier-poc5-rehearsal-1200/<run-id> \
  --splits interface
./classifier-pilot verify classifier-poc5-rehearsal-v2
# Proceed only if all 30 rehearsal samples are accepted and eligible and the
# handoff is ingestible. The rehearsal is never reused in classifier training
# or evaluation. Then run and verify both campaigns in blocks 01 through 10.
```

For odd block `NN`, run the baseline campaign before the paired campaign; for
even `NN`, reverse those two operations. In either case each operation is:

```shell
./qcsd-lab verify config/campaigns/classifier-poc5-<kind>-NN.yml
./qcsd-lab run config/campaigns/classifier-poc5-<kind>-NN.yml
./qcsd-lab verify \
  results/research-classifier-poc5-<kind>-NN-1200/<run-id>
```

Do not start block `NN+1` until both block-`NN` results verify as complete,
with every planned sample accepted and eligible. A failed formal result is
retained and diagnosed; it is never replaced with an ad-hoc campaign or a
different seed. All twenty formal results must bind one identical clean Lab
commit, Neqo commit, and collection-image source receipt. The rehearsal
authorizes only the exact image, workloads, and campaign commit that it ran;
any rebuild, source or workload repair, parameter change, or class replacement
requires a new excluded 30-sample rehearsal before formal acquisition.

### Fresh approved-origin multi-origin v2 cohort

`classifier-multiorigin5-v2` is a wholly fresh 2,500-capture lineage. It does
not reuse any POC5 or `classifier-multiorigin5-v1` capture, seed, sample ID,
response sidecar, campaign namespace, analysis, or handoff row. It measures a
fixed approved-origin HTTPS `GET` graph. This is a page-like replay of every
resource admitted to that frozen graph, including approved cross-origin
resources; it is not a full browser page load, render, cache model, or record
of every third-party request on the public site. The five class labels remain
the primary page domains. Secondary origins contribute encrypted traffic to
that class and are never separate labels.

The frozen workload graphs are:

| workload | class label | approved origins | resources |
| --- | --- | ---: | ---: |
| `getbootstrap-home-r4` | `getbootstrap.com` | 1 | 9 |
| `cloudflare-quiche-r4` | `cloudflare-quic.com` | 3 | 6 |
| `hyper-basic-client-r3` | `hyper.rs` | 2 | 7 |
| `serde-home-r2` | `serde.rs` | 1 | 20 |
| `rfc9114-text-r2` | `www.rfc-editor.org` | 1 | 2 |

Cloudflare uses `cloudflare-quic.com`,
`blog-cloudflare-com-assets.storage.googleapis.com`, and
`blog.cloudflare.com`; Hyper additionally uses `cdn.jsdelivr.net`. Chromium
discovers and admission-filters the graph during preparation only. Collection
replays it with Neqo: one QUIC/H3 connection per approved origin and one
request stream per resource when its dependencies are ready. Multiple resource
streams on the same origin share that origin's connection; streams and origin
connections can progress concurrently in the same sample event loop. Their
exact endpoint-tuple union is retained in one PCAP.

The five-file response qualification set
`config/chaff-response-qualification-store/sets/classifier-multiorigin5-v2/`
has been published as a create-only transaction. Defended campaigns bind
`chaff_qualification_set: classifier-multiorigin5-v2`; baseline campaigns
intentionally omit the set because they contain no response-only defence. Run
the excluded rehearsal first with the exact final collection image:

```shell
QCSD_LAB_COLLECTION_IMAGE=sha256:<exact-final-image> \
  ./qcsd-lab verify \
  config/campaigns/classifier-multiorigin5-v2-rehearsal.yml
QCSD_LAB_COLLECTION_IMAGE=sha256:<exact-final-image> \
  ./qcsd-lab run \
  config/campaigns/classifier-multiorigin5-v2-rehearsal.yml
QCSD_LAB_COLLECTION_IMAGE=sha256:<exact-final-image> \
  ./qcsd-lab verify \
  results/research-classifier-multiorigin5-v2-rehearsal-1200/<run-id>
QCSD_LAB_COLLECTION_IMAGE=sha256:<exact-final-image> \
  ./qcsd-lab analyze \
  results/research-classifier-multiorigin5-v2-rehearsal-1200/<run-id>
./classifier-pilot export classifier-multiorigin5-v2-rehearsal \
  results/research-classifier-multiorigin5-v2-rehearsal-1200/<run-id> \
  --splits interface
./classifier-pilot verify classifier-multiorigin5-v2-rehearsal
```

The rehearsal is five workloads times two visits times three conditions: 30
captures, permanently excluded from training and evaluation. Proceed only
after all 30 are accepted, eligible, sealed, verified, analyzed, independently
checked for multi-endpoint capture, responses, clocks, schedules, credits,
offloads, and the 1200-byte UDP ceiling, and exported to the verified
interface-only handoff `handoffs/classifier-multiorigin5-v2-rehearsal/`. Any
subsequent source, image, workload, qualification, campaign, or defence change
invalidates it.

The formal files are
`classifier-multiorigin5-v2-{baseline,paired}-NN.yml`. Each of ten temporal
blocks contributes 100 baseline captures and 150 paired captures, for 500
captures per class and 2,500 total. The exact totals are 1,500 undefended, 500
FRONT, and 500 Tamaraw. The exact acquisition chronology is:

```text
B01, P01, P02, B02, B03, P03, P04, B04, B05, P05,
P06, B06, B07, P07, P08, B08, B09, P09, P10, B10
```

That is baseline then paired in odd blocks and paired then baseline in even
blocks. Never begin the next block until both current results are complete,
sealed, verified, and analyzed. Pass roots to the exporter later in canonical
baseline-01, paired-01, ..., baseline-10, paired-10 argument order; their
sealed timestamps must prove the acquisition chronology above.

After each sealed campaign, including the rehearsal and every formal result,
run `./qcsd-lab verify` and then `./qcsd-lab analyze
results/<campaign>/<run-id>` before continuing. Analysis generates
`summary.csv`, `report.html`, paired trace SVGs, and aggregate latency/overhead
SVGs. After all twenty formal results pass, export the separate create-only
handoff `classifier-multiorigin5-v2` and verify it; the destination is
`handoffs/classifier-multiorigin5-v2/`. Josh should normally train from
`traces/` or `stripped/`; `raw/` PCAPNG, classic PCAP, and run receipts are
restricted audit inputs because they retain real endpoint, timing, QUIC
Initial, URL, and request metadata. Use only undefended blocks 01--08 for
training, block 09 for validation, and block 10 for the clean test. FRONT and
Tamaraw remain inference-only.

Status: the excluded v2 rehearsal completed 30/30 accepted and eligible, its
interface handoff is sealed, and all twenty formal result roots completed,
verified, and produced their per-campaign analyses. The create-only formal
handoff at `handoffs/classifier-multiorigin5-v2/` contains all 2,500 samples:
1,500 undefended, 500 FRONT, and 500 Tamaraw. Its `SHA256SUMS`, `dataset.json`,
and `samples.jsonl` SHA-256 values are respectively
`85bfd88be6c2105201ec7ff3eb87a743e378bd748a9c2097db2fb227875ec2d7`,
`46289f368912ee6e90314578814b821eb0dfeadcd794d3422c1af3599623317b`,
and `5974ab9c582793501c558ec294bea4e3afb01bf57039f990fceba33fb0b1e15f`.
On 1 September 2026, the offline launcher was corrected to invoke the pinned
`/opt/qcsd-venv/bin/python3` installed by the collection image rather than its
package-empty system interpreter. The repaired deep verifier rehashed and
validated all 12,503 governed files and all 2,500 sample relationships with
the same `SHA256SUMS` digest; no handoff byte was changed.
This artifact is a five-class classifier-*pipeline* pilot, not evidence of
classifier or defence efficacy: only undefended blocks supply the
train/validation/test observations, while every FRONT and Tamaraw sample is
inference-only. It neither evaluates an attacker retrained within each defence
nor supplies validation evidence for the later BuFLO or CS-BuFLO candidates.

The entire `classifier-multiorigin5-v1` acquisition lineage is retained only
as superseded diagnostic evidence. Its excluded rehearsal, B01, P01, and P02
must never be mixed into v2. P02 exposed live Cloudflare response-identity
drift, was stopped at a sample boundary, and remains deliberately unsealed;
none of its accepted files is a v2 sample or handoff row.

The superseded clean source receipt—Lab
`d5543406359528b1382222d8ef3d3cffd67b7d4d`, Neqo
`867246557ec719fc34552b60abf624895be2706c`, and collection image
`sha256:5d56c63fdd182ba311392602bad77e8f4c3198c6bd08958a691cac197f74f05e`—
passed the excluded rehearsal at
`results/research-classifier-poc5-rehearsal-1200/20260815T132537.356504Z`
with 30/30 accepted and eligible samples. Its sealed evidence-index and
experiment hashes are
`350e015f97d49fa8c14f7e5d82489b05f2fbdd5d0cb9a0345b54abba32d9b560`
and `f3028b05a7908826b003fafb8e07bdd0d0a709a183be0513fa7cc5efb7eb2703`;
the verified interface handoff's `SHA256SUMS` hash is
`392d897369de9e38bbdae116b79c1559a9f5d00a65f33c4b8eccbb887053e02c`.
It then completed baseline-01 at
`results/research-classifier-poc5-baseline-01-1200/20260815T134617.090622Z`
with 100/100 accepted and eligible samples, all on their first attempt. Its
sealed evidence-index and experiment hashes are
`65a858a25a714a534dff1afb7ec57d510fd2ac8ea6b1995b9aad34fd94136bc9`
and `5ae8cded5a7dc117ec21ce302a9a1b12051acc8690939a75fbbe004f76fd593b`.
Paired-01 at
`results/research-classifier-poc5-paired-01-1200/20260815T144004.646818Z`
is sealed and valid but incomplete: 146/150 samples were accepted and eligible
across 166 attempts, split U/F/T as 50/46/50, with four terminal FRONT
failures—Hyper visits 002, 004, and 009, and RFC visit 003. Its sealed
evidence-index and experiment hashes are
`dc1b656a8745d589ff43224862647d46aed67d8cf3687d1d7cd78e7e84ffb2af`
and `767d0237d3172b506d951bdb9a9c1c4b37df6aee3e166d90b9193c3d7c9ab7d2`.
Hyper 002 and RFC 003 exhausted their retries on strict schedule misses. Hyper
004 stalled with
310–325 scheduled response bytes still unconsumed below the atomic HEADERS
boundary. Hyper 009 combined strict misses with a typed transport
`InvalidInput` on one attempt. These observations motivated, prospectively,
the residual scheduled-prefix bootstrap, FRONT-only prearming, and
transactional typed receive-action preflight described above; no seed,
schedule, fidelity gate, or acceptance threshold was changed.

P2 then produced a fresh excluded rehearsal at
`results/research-classifier-poc5-rehearsal-1200/20260815T201524.981071Z`
from clean Lab P2 `8a8d605166bfc27c6a7b8907162119e055ca7ca2`, F2
`a8378520b9740be782bfe526cdb3eb05e6665571`, and collection image
`sha256:a971810d2d26f7b87d380c96ae3516890b0715267a717879a4f93316caa96122`.
It is sealed incomplete and permanently excluded: 29/30 samples were accepted
and eligible, while Hyper visit 000 FRONT failed deterministically across all
three attempts. The sealed evidence-index and experiment hashes are
`3d9baba02bb87e3e884992c1a215dcb549b8f1628b732826a5b502669e496df7`
and `c9544d06a4349f5160388fb93f7ea8b9be7c5f80435668ef0dd66360379978ff`.
Each failed attempt opened every application request stream, and every
application request's bytes and FIN were acknowledged, but all five response
resources remained incomplete; 1,333,200 scheduled incoming bytes were
requested, zero were consumed, and all were retired at timeout. Retained
capture evidence shows that response datagrams reached the host.

The failure was a two-layer F2 liveness defect. FRONT's fixed-schedule
`reconcile_due_fixed` processed due incoming work at the exact elapsed instant
but did not advance the incoming boundary used by `next_deadline`; when that
work could not yet allocate, its retry deadline remained in the past. The
single-thread runner treated the past deadline with an await-free `continue`,
so it hot-looped without polling socket readiness and starved the already
arriving response. F3 advances only that fixed-schedule retry watermark while
retaining exact elapsed processing, private future events, and global order;
the runner now performs a readiness-aware await with a one-microsecond retry
timer for an already-due target while leaving future absolute wake arithmetic
unchanged. No schedule event is dropped, reordered, or artificially satisfied.

All five result roots above remain immutable diagnostic evidence. The earlier
passing rehearsal no longer authorizes a replacement image, baseline-01
contributes no sample to the replacement corpus, and no accepted row from
either incomplete result may be reused. No formal campaign and no classifier
export was run from P2. Q3 completed the atomic exact-five F3 qualification,
and P3 `507cb04c38babcdc0050ddb064007a962efee0a2` published that historical
cohort and built the clean final images recorded above. No P3 rehearsal,
interface handoff, formal capture, or classifier export was launched. The
replacement Lab capture-integrity implementation at
`47c91bb36dcddd3943253ee16141febbaf9041e8` makes those historically valid
sidecars ineligible under the current-implementation contract. Q4 kept
canonical v2 absent and launched no public qualification after its local live
fixture failed. Q5 passed its repaired live prerequisite, completed the new
atomic exact-five Q5/F3 qualification, and P5 published that now-historical
cohort. Its `20260817T181058.212792Z` rehearsal sealed incomplete because the
frozen Hyper r1 response had drifted, even though every retained attempt
passed the Linux-local capture-integrity gate. Q6 changed the then-active POC5 binding
to the independently prepared Hyper r2 graph and removed the prior canonical
v2 cohort at its acquisition boundary. Its completed exact-five Q6/F3
qualification remains published by P6 as legacy evidence. At that boundary,
clean P6/F3 final images were required to pass a wholly new excluded 30/30
rehearsal and verified interface handoff before formal acquisition could
restart from baseline-01 under one homogeneous source receipt.
The earlier `20260815T103924.969402Z`,
`20260814T150747.615059Z`, and `20260814T110741.344914Z` rehearsals and all
their retries remain permanently excluded as well.

The incomplete six-class diagnostic at
`results/research-classifier-pilot-01-1200/20260814T064655.275845Z` is excluded
from the POC5 corpus and classifier export. None of its individually accepted
samples is reused. Its Apache response drift and FRONT/Tamaraw fidelity
failures show that the strict gates rejected that particular run; they do not,
by themselves, establish a general defect in Neqo. The replacement cohort was
therefore required to pass a fresh Linux-local capture-integrity rehearsal with
exactly 30/30 accepted and eligible samples and a verified interface handoff
before any formal block; v2 satisfied that prerequisite.
Never weaken fidelity to force a pass. Refresh, repair, or prospectively
replace a failing class under a new frozen contract instead.
The fitting corpus, qualification runs, smoke result, failed attempts, and
qualification diagnostics are likewise never POC5 classifier samples.

These POC5 campaign files, the offline exporter, tests, and documentation are
outside the qualification implementation-file inventory, but the clean Lab
commit remains part of source provenance. Canonical legacy response-store
`v2` retains only the POC5 Q6/F3 cohort published by P6 after the P5 rehearsal
exposed stale Hyper r1 response identity. At that POC5 boundary, formal
acquisition and classifier export required a clean P6/F3 final collection
image, a fresh excluded rehearsal with exactly 30/30 accepted and eligible
samples, and a verified interface handoff before restarting from baseline-01.
Keep the historical response-store v1/schema-3 evidence
frozen-compatible; do not regenerate the separate historical full-v2
sidecars, prefix specs, fitting result, or sealed `research-1200` bundle.

The implementation goal established the profiles, preparation policy,
fitters, runtime realisation, campaign contracts, and evidence boundaries.
The completed sequence was:

```shell
./qcsd-lab test live
./qcsd-lab run config/campaigns/fitting.yml
./qcsd-lab verify results/research-fitting-1200/20260812T130241.322364Z
./qcsd-lab verify artifacts/research-1200-superseded-schema5-0a141768
./qcsd-lab derive-chaff-prefix-specs
# Commit the final qualification code, Neqo gitlink, and six specs as clean Q.
./qcsd-lab build
./qcsd-lab qualify-chaff
# Commit the exact six v2 qualification sidecars.
./qcsd-lab fit results/research-fitting-1200/20260812T130241.322364Z
./qcsd-lab verify artifacts/research-1200
# Rebuild from the sidecar commit before evaluation capture.
./qcsd-lab build
./qcsd-lab verify config/campaigns/smoke.yml
./qcsd-lab run config/campaigns/smoke.yml
./qcsd-lab verify results/research-smoke-1200/20260814T023209.708923Z
./qcsd-lab analyze results/research-smoke-1200/20260814T023209.708923Z
```

`test live` is a bounded baseline/direct-wire mechanics gate, not a substitute
for the exact-six qualification transaction. The sealed fitting result contains
120 accepted and eligible samples. The current schema-6 bundle verifies, and
the checked-in smoke evaluated the fitted defenses on new Internet visits:
`20260814T023209.708923Z` is verified and analyzed with 14/14 accepted and
eligible, zero failures, and every sample accepted on its first attempt.

The superseded runtime-falsification evidence is locally preserved and
manifest-sealed at
`results/chaff-qualification-diagnostics/q7-b19cb04-7ebcdb0-schema6-203eee42-runtime-falsification/`.
Its outer manifest SHA-256 is
`4ee68a930a344dc0e5874279e09069f92935a2f4f42bc7bb7e88077153b85aa9`;
its manifest is bound by the v2 receipts, while its bytes are not positive
qualification or fitting input. The POC5 campaigns do not define or execute
the separately named historical 42-sample pre-final rehearsal or 126-sample
engineering campaign. Both remain explicitly on hold and require later
authorization.
