# Resource-domain study

## Prospective fixed-class-IP protocol: live validation pending

The approved study is **50 exact resource hostnames × five traffic modes ×
400 accepted connections = 100,000 sessions**. Each counted connection must
fetch all **20 distinct, fixed resource URLs** assigned to its hostname.
The five modes are ordinary traffic (`undefended`), FRONT, Tamaraw, BuFLO and
CS-BuFLO. Each mode contributes 20,000 sessions.

New plans freeze deterministic per-class addresses and an explicit tuple scope.
This prospective implementation needs matching live pilots under its exact
runtime and plan before formal credit. It does not import older sessions into
the corrected protocol. Historical plans and receipts remain readable under
their original acceptance contract.

The published handoff checkpoint recorded **three live-enrolled classes and 21
independently verified formal sessions:** ordinary 14, FRONT 2, Tamaraw 4,
CS-BuFLO 1 and BuFLO 0. `formal-batch-000002.json` exports all 21.
`verify --recover --all` passed with no errors, pending or interrupted attempts,
deleted files or running containers. The original four-session export and
the real **4 → 8 → 12** SIGTERM stop/resume evidence remain unchanged.
The 100,000-session target is incomplete; 50 structurally eligible input hosts
are not 50 live admissions.

Shopify CDN and Dictionary CDN have all five admission readiness flags; Fonts
is ordinary-only after chaff qualification failed. Zero-credit pilots passed
for four modes: ordinary on Fonts and Shopify, FRONT and Tamaraw on Shopify,
and CS-BuFLO on Dictionary. BuFLO remains blocked: three actual pilots failed
with WSL clock shifts of 22.9–30.8 ms. These failures receive no credit; no Native change was made. Missing mode pilots and transient Shopify FRONT/CS-BuFLO
Native deadlines paused affected cells while healthy cells continued.
SDK005 was installed and verified at that checkpoint. These historical results
do not establish Mac behavior or a pass for the prospective network protocol.

The earlier website study's **392 accepted ordinary recordings** remain
historical evidence under their original contracts. They do not count toward
these 100,000 sessions. See [PROJECT.md](../PROJECT.md) for the status boundary
and [the historical rapid path](RAPID-CAPTURE-PATH.md) for that earlier design.

## What a class and a session mean

A class is the **exact resource hostname**, such as `cdn.example.org`.
It is not the website that referred to a resource, a registrable domain, or
a whole browser page. Different hostnames remain different classes even when
they share a server IP address. The new design deliberately prepares its own
single-origin resource manifests; it does not prune or relabel old page graphs.

Each class has a frozen list of 20 different URLs on its one HTTPS origin.
Keep URL queries intact, including Bing `th` identifiers and other resource
identifiers. Twenty requests for one URL do not satisfy the 20-resource rule.
The importer preserves the supplied choices and records their provenance.
If a primary candidate cannot meet the live contract, the declared reserve
order is **`cdn.myanimelist.net`, then `ahrefs.com`**. Replacing a class is a
prospective recorded decision, not permission to alter an earlier attempt.
No ready URL inventory for either reserve was found in the bounded current-source
lookup. Discover and authenticate their inventories before live preparation;
the declared names alone do not establish eligibility or admission.

One visit starts a fresh Native client process and one QUIC connection to
that origin. Its 20 resource requests use ordinary HTTP/3 request streams on
the same connection. Streams may overlap when the request dependencies and
stream limits allow it; this does not mean 20 simultaneous connections.
Protocol control streams and defense chaff are additional traffic and do
not replace any of the 20 application requests.

The sampling unit is the **accepted connection session**, not a request
stream, a browser navigation or a packet. The collector must verify the
actual connection inventory, handshake, all 20 completed full GET responses,
and the mode's declared timing and completion conditions before crediting it.
Each class/mode cell needs 400 accepted sessions with distinct recorded
five-tuples. Attempts, retries and practice sessions do not fill that count.

## Packet evidence and tuple identity

Capture on the measured client's **`eth0` before Docker NAT**. The five-tuple
is client IP, client UDP port, server IP, server UDP port and UDP protocol.
Preserve its orientation and the capture interface in the receipt. This is
the observed container-side tuple; it is not a claim that the Internet-facing
NAT tuple is the same.

Use persistent per-class container IP assignments on a collision-checked
bridge, together with a tuple ledger. A fresh process requests a fresh socket,
but the operating system can reuse a UDP port. A duplicate tuple within the
declared uniqueness scope is an uncredited attempt, not a second session.
State that scope in the frozen study plan and enforce it during capture and
verification. Connection migration or a tuple change cannot count one QUIC
connection twice.

For new plans, `class_network` freezes all 50 selected exact hostnames, sorted
lexically, onto the first 50 disjoint `/29` subnets of a private `/23` pool
(default `10.232.0.0/23`). Each subnet reserves `.1` for the Docker bridge,
`.2` for its router, and `.3` for its measured client. The address remains the
same across worker lanes, modes and finite flights. A flight creates only its
selected enrolled class networks and routers, after checking the entire frozen
map against existing Docker IPAM and nondefault Linux host routes. Each client
uses its class router as its sole default route for every mode.

The frozen `tuple_uniqueness_scope` is `hostname-mode-study-root`: the SQLite
ledger rejects a repeated observed five-tuple in the same hostname/mode cell
within that study root. It does not assert global uniqueness across modes or
historical study roots. Independent verification joins the observed Native
endpoint and primary PCAP source IP to the frozen class address, plus the
actual worker endpoint, measured scheduler container, class router and observer.
Plan, mapping and scope hashes remain bound in receipts, ledger metadata and
exports. BuFLO retains its additional raw kernel TX and post-veth gates.

The map has exactly 50 classes. A reserve hostname outside it cannot silently
become a 51st mapping. Authenticate its resource inventory, record the changed
selection in a prospective plan/epoch, and run matching pilots for every
affected class/mode. A full map/protocol change affects every cell and starts
with zero credit in its new root; original receipts stay under their old plan.

Retain the original packet capture and its hash. Join it to the frozen URL
manifest, Native endpoint tuple, handshake/protocol evidence, request events
and completed response records. Encrypted packets alone do not prove which
20 URLs completed. Exports must retain those joins and the connection's tail;
they must not select only favorable packets or omit failed attempts from the
attempt inventory.

## Progress, recovery and independent modes

The study has **250 cells**: 50 classes under five modes. Each cell has its
own accepted-session count, immutable receipts and attempt history. A failed
defense must not stop a different ready mode from making valid progress.

For this new study, the transactional **SQLite ledger plus immutable,
hash-bound receipts** is the progress authority. Status and export use that
ledger; verification reopens the receipts and their raw dependencies.
SQLite is not authority to accept a session whose evidence fails validation.
An incremental batch adds new verified sessions without rewriting previous
receipts or importing the old website target's historical proof chains.

Keep failed and interrupted attempts. Resume an unchanged attempt only under
its original bound inputs and runtime. A changed traffic parameter, acceptance
rule, resource list or relevant implementation starts a prospective affected
cell/mode epoch. Preserve valid unaffected modes and their counts. A verifier
or provenance repair must record exactly what changed and reverify affected
evidence; it does not automatically erase the whole corpus or promote a failed
receipt. Historical `experiment.json` campaigns retain their original resume
and authority rules.

The new route does not inherit the old 110-vector browser sequence, three
browser stability windows, or a requirement to qualify all five modes before
one independently ready mode can start. It still requires a frozen manifest,
truthful source/runtime bindings, live resource and chaff checks where needed,
and complete evidence for every accepted session.

## Public command interface

The public interface is `./qcsd-lab resource-study`, backed by
`tools/resource_study.py`. Bind the exact study root and canonical runtime:

| Action | Purpose |
|---|---|
| `prepare` | Import the 50-row candidate list, freeze 20 URLs per hostname and record live admission separately |
| `capture` | Run fresh connection attempts for selected ready cells, preserving all attempt evidence |
| `status` | Report accepted counts, pending cells, failures and active attempts from the ledger |
| `verify` | Check the ledger, immutable receipts, raw dependencies and tuple uniqueness |
| `export` | Export verified sessions and labels with source, mode, tuple and manifest provenance |

```sh
./qcsd-lab resource-study prepare --root /absolute/fresh/study --source /absolute/frozen/resources.json --storage-reserve-bytes 64424509440 --class-network-pool 10.232.0.0/23
./qcsd-lab resource-study prepare --root /absolute/fresh/study --runtime /absolute/runtime/canonical-runtime.json --enroll --hostname RESOURCE_HOSTNAME
./qcsd-lab resource-study capture --root /absolute/fresh/study --runtime /absolute/runtime/canonical-runtime.json --hostname RESOURCE_HOSTNAME --workers 2 --pilot --chunk 1 --attempts 5
./qcsd-lab resource-study capture --root /absolute/fresh/study --runtime /absolute/runtime/canonical-runtime.json --hostname RESOURCE_HOSTNAME --workers 2 --mode undefended --chunk 1 --attempts 2
./qcsd-lab resource-study verify --root /absolute/fresh/study --all
./qcsd-lab resource-study status --root /absolute/fresh/study
./qcsd-lab resource-study export --root /absolute/fresh/study --output /absolute/fresh/export.json
```

The storage reserve and class pool are creation parameters. They become frozen
in `study.json`; repeating `prepare` with different values refuses the change.
The default live storage reserve is 60 GiB. Use the supported preparation flags
instead of editing the frozen plan.

For this protocol, a pilot authorizes only its exact hostname, 20-resource
workload, mode settings/policies and complete capture runtime. A single class
pilot cannot qualify the other 49 mapped classes. Run zero-credit pilots for
the selected class/modes, then start finite formal attempts for independently
ready cells. Missing pilots and failed modes pause only the affected cells.
No historical 9–10-hour qualification chain is required.

Only historical pre-v2 plans let initial unchanged cells use the approved
one-domain pilot for their mode. Every new v2 plan requires per-cell pilots.
Changed scientific epochs require an exact-host, frozen-resource pilot for
each affected cell. Omitting `--mode` selects all five modes; use explicit
ordinary selection first. Use
`verify --recover --all` only after workers stop. It cannot promote an orphan
folder or failed receipt. Confirm installed help before launching.

Packet-clock integrity remains strict at **10 ms**. BuFLO's observed
22.9–30.8 ms WSL shifts were refused; bounded retries retain failed attempts
without widening the limit. Host observer/provenance fixes have separately recorded code identity.
They do not relabel the installed SDK or old evidence. Cell-epoch integration
and clock controls passed 36 focused checks. A new scientific epoch still needs
an explicit admission selecting affected cells and their own matching pilots;
this checkpoint issues no such admission and preserves unaffected receipts.

## Runtime and machine requirements

Reuse the verified Native D2 implementation and cached client through the
public runtime producer. Lab-only collector changes do not require a new
Rust compilation. They do require the new Lab SDK to be installed and bound
to the actual client and image receipts; an old image does not acquire new
Python behavior because an external checkout changed.

The initial operating budget is **two workers, six available CPU IDs and
16 GB RAM**. The measured scheduling contract needs two CPU IDs per worker
plus a residual sidecar CPU: **`2N + 1` for N workers**. Four workers therefore
require at least nine actual available CPU IDs and successful capability and
timing checks. More CPUs are not evidence that additional workers are already
supported or that timing remains valid. Measure a pilot before scaling.

The D-backed ext4 volume has a **512 GiB logical limit**. Its backing drive
previously had about **362 GiB physically free**; the sparse volume does not
create more physical storage. No measurement yet establishes that the full
100,000-session corpus fits. Measure complete pilot folders, including PCAPs,
logs, failures, tails, receipts and exports, and keep space for recovery.
Ordinary pilot folders retained 302,472 bytes for Fonts and 6,582,996 bytes for
Shopify. At Shopify's size alone, 100,000 folders would exceed 610 GiB; the full
cohort and defended-mode averages remain unmeasured. Four-worker rates are unverified.

## Timing and optional future modes

For illustration only, assume an effective **20 seconds per accepted session
per worker**, including the cost of retries and verification:

| Workers | Calculation | Continuous time for 100,000 sessions |
|---|---|---|
| 2 | `100000 × 20 / 2` seconds | 11.6 days |
| 4 | `100000 × 20 / 4` seconds | 5.8 days |

These are arithmetic scenarios, **not measured new-study rates**. Four-worker
scaling is conditional. Defended traffic can be slower; BuFLO's declared
640-second cadence budget is a maximum allowance, not an observed average.
Storage, interruptions, admission, preparation and final export can add time.

Traffic Morphing, WTF-PAD and Walkie-Talkie are optional later modes, each
adding 20,000 accepted sessions. Their fitting needs a separately declared
training baseline and new cohort provenance. Keep fitting data separate from
held-out evaluation sessions. Static is a possible additional control; it
would also add 20,000. The three fitted modes would raise the total to 160,000;
including Static would raise it to 180,000. They are not prerequisites for
the approved five-mode study.

Training/evaluation splits for this new session unit must be declared and
implemented before reporting classification results. Split by connection
session, keeping all packets and resource streams from one session together.
Exclude client/server addresses, ports, hostnames and URLs from model features;
persistent class IP assignments would otherwise reveal labels. Retain them as
verification metadata. Declare time/grouping splits to account for correlated
sessions with repeated URLs and nearby collection times.
Do not describe the historical 64-visit evaluation adapter as the new study's
already validated evaluation procedure.

## Proposed cleanup and Mac transfer

**Cleanup and migration have not been completed.** Finish implementation and
local checks first, then have the owner review the cleanup inventory. Keep
unfinished authoring changes, all captures and receipts, and any historical
checkout still required to reopen a bound proof. A clean Git status alone
does not establish that an old execution root is disposable. Remove a linked
worktree through its owning Git repository only after that review; do not
delete its directory and leave the worktree registry inconsistent.

The source-only transfer contains committed Lab source, its exact Native
Gitlink source, dependency locks, this guide and the frozen original resource
JSON. Its tar is not a Git checkout: restore the published commits as instructed
by the package. A stopped ledger and all raw evidence require a separate
owner-reviewed transfer if continuing recorded work. The source package alone
carries zero session credit. Do not copy diagnostic clones, Python environments
or machine build caches into it. Final package paths, manifest and Lab commit
remain owner-filled after publication; no Mac transfer is claimed complete.

For an Apple Silicon Mac, the current cached Linux x86-64 client is not an
ARM64 runtime. Reuse the same source commit, but build and qualify an actual
Linux ARM64 client and matching SDK/images in a suitable Linux environment.
The stock launcher has Linux scheduler, kernel, cgroup and user-systemd
requirements; a macOS shell is not a drop-in substitute. Verify the guest's
system counter access, ETF/CLOCK_TAI/SO_TXTIME and timing capabilities with a
complete small pilot. Docker CPU allocation does not prove host scheduling
isolation. Record the platform/runtime change as a prospective epoch, without
relabeling earlier captures. The Mac model, available CPUs, RAM and storage
must be established before choosing worker count; no Mac speedup or migration
completion is claimed here.

For the source-only handoff tool, exact Git restoration, Linux ARM64 runtime
and staged zero-credit pilot, follow [the Mac migration guide](MAC-MIGRATION.md).
