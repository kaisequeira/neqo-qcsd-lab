# QCSD Lab agent and harness rules

These repository-local rules apply throughout `neqo-qcsd-lab/`.

## Research and scope boundary

- The current approved study is the prospective resource-domain design in
  [docs/RESOURCE-DOMAIN-STUDY.md](docs/RESOURCE-DOMAIN-STUDY.md): 50 exact
  resource hostnames, 20 distinct frozen URLs completed per accepted fresh
  connection, five modes and 400 distinct recorded five-tuples per class/mode
  cell, for 100,000 accepted sessions. The current checkpoint is two live
  enrollments and twelve verified ordinary sessions; inspect current receipts
  before changing that count. Pilots carry zero formal credit.
  Importer eligibility is not live admission. Preserve queries and resource
  identifiers; use declared reserve order rather than silently substituting
  classes. Check current receipts before advancing any count.
- The authorised wording is **five validated defences plus two candidates /
  nine selectable modes** until a final validation attestation verifies.
- BuFLO and CS-BuFLO are client-only QUIC adaptations. Keep servers ordinary
  HTTP/3 endpoints; do not add bilateral or symmetric defence behaviour.
- Preserve multi-origin workload graphs. Never remove an origin or resource to
  make a defence, fitting stage, or capture pass.
- **Prospective resource-domain exception:** preparing a new single-origin,
  20-URL class is explicitly authorised for the new study. This is a new
  sampling design, not pruning an old admitted page graph. Preserve every
  historical graph, receipt, label and count unchanged. The old whole-page
  browser gate and whole-cohort launch sequence are not prerequisites for this
  new role. Keep ordinary HTTP/3 servers and all current mode-specific gates.
- Report accepted scientific counters only from final deep-verified receipts.
  Historical passing prefixes and non-evidentiary probes advance no numerator.
- Do not carry checkpoint figures forward from these instructions or memory.
  Read [PROJECT.md](PROJECT.md), the latest immutable receipts, and live
  checkpoint state. Separate a completed historical browser gate from authority
  for changed source. Preserve all old cohorts and use the allocator's next
  unused version after source freeze.

## Live source-bound operations

- For the historical class-study launcher, keep its exact clean Lab checkout,
  pinned Rust Gitlink, allocator authority, and create-only destinations. A
  prospective study may reuse a previously verified immutable image with a
  matching clean execution checkout and a separately versioned, hash-bound
  study plan; it need not run a fresh no-cache build solely because the study
  plan or external verifier changed. Record both identities without claiming
  that new authoring code was installed in the old image.
- Keep jobs that share mutable image tags, lifecycle locks, or evidence roots
  serial. Independent inspection, documentation, tests, and authoring in a
  separate checkout may continue while a source-bound Docker job runs. Keep
  the execution checkout and its pinned Gitlink unchanged until that job exits.
- If the user changes the study scope during a long job, stop the obsolete job,
  preserve its attempted evidence and lifecycle records, and recover its locks
  before starting a replacement. Keep the user informed during long jobs.
- Keep the execution checkout pinned throughout its campaign. Publish research
  progress from a separate authoring clone between live operations; a
  documentation commit must not move the running checkout's source identity.

## Evidence and cohort discipline

- For the new resource-domain study, SQLite and immutable hash-bound receipts
  are the progress authority. Track 250 independent class/mode cells, accepted
  tuple uniqueness, raw capture/request/completion joins and all attempts.
  Verification must refuse ledger credit without valid evidence. Never count
  streams or migrating tuples as extra connection sessions. Historical
  `experiment.json` and acquisition checkpoints retain their original rules.
- `experiment.json` is the authoritative capture-campaign checkpoint for
  interruption, resume, attempt order, and completion state. Acquisition uses
  its `checkpoint.json` and bound `provenance.json`.
- Cohort versions and evidence destinations are create-only. Receipt absence
  does not make a claimed or attempted version reusable.
- Resume only an unchanged-source, unchanged-input checkpoint using the exact
  original arguments. A source, parameter, workload, image, or acceptance-rule
  change requires the next unused cohort and complete downstream reproof.
- For the prospective resource-domain role, that reproof is scoped to the
  affected class/mode epoch and relevant dependencies. Preserve validated
  unaffected cells and modes; one failed defense must not block another ready
  defense. A provenance or verifier correction gets truthful new source and
  receipt bindings plus affected revalidation, not an automatic whole-study
  reset. A changed traffic condition applies prospectively and cannot promote
  a failed old receipt. This exception does not reinterpret historical resume
  authority or permit changed inputs inside an existing attempt.
- For an affected scientific epoch, bind its new mode pilot to the exact
  hostname, frozen 20-resource manifest, enrollment, settings and runtime.
  A pilot from another hostname cannot qualify that changed cell. Initial
  unchanged cells use the approved one-domain pilot for their mode. Epoch
  admission and parent recovery require their own reviewed implementation and
  actual gates; a design description is not an issued admission.
- Keep the primary packet-clock limit at its declared 10 ms. Record and refuse
  disturbances outside that limit, including on a VM; bounded retries preserve
  failed evidence and do not silently widen scientific acceptance.
- Preserve failed attempts, logs, captures, checkpoints, and receipts. Never
  delete, overwrite, substitute, relabel, or post-hoc promote evidence.
- Under the historical 100-site and 20-site contracts, acquisition-only
  authority cannot replace the full defence foundation for a capture role.
  A new prospective study may define smaller, focused launch checks, with its
  own versioned profile, source and runtime bindings, independently verified
  complete traces, and explicit limits on the scientific claim.
- Complete acquisition under its bound study profile: the registered 100-site
  contract requires the first 24 eligible candidates per stratum and every
  earlier candidate to have scientific terminal evidence; the prospective
  20-site contract requires its declared round-robin order through 30 eligible
  pilots, with every earlier candidate accounted for. Preserve unused tails as
  unassessed. Infrastructure errors and missed stability windows are blockers,
  not selective site rejections. No active/recovery work may be hidden by a
  complete prefix, and no old cohort gains the new profile's authority.
- Do not edit or regenerate `config/`, `artifacts/`, `results/`, or `handoffs/`
  unless the user's scoped task and the authoritative workflow explicitly
  require that mutation.
- Never index artifacts, results, qualification evidence, captures, logs,
  handoffs, caches, or fuzz corpora in the code graph.

## Source discovery and editing

- At the start of work, call `list_projects`. Select the Lab graph project whose
  reported repository root equals this repository's resolved root, and select
  the Rust project whose root equals the resolved `neqo-qcsd/` submodule root.
  Never hardcode a machine-derived project identifier or home-directory path.
- Call `index_status` for the selected project. For structural discovery use
  `search_graph` (limit at most eight), then `trace_path` at depth one or two
  and `get_code_snippet`; confirm against direct source with `rg`.
- Before negative or exhaustive claims, call `check_index_coverage` and inspect
  exact source. After edits, use `detect_changes(base_branch="HEAD")` for the
  blast radius.
- Use `apply_patch` for file edits. Preserve unrelated user changes in the
  shared worktree, and do not commit or tag unless the user or coordinating
  agent authorises it.
- For local documentation and agent guidance, link only to repository-relative,
  tracked files. [PROJECT.md](PROJECT.md) is the current ledger,
  [docs/CLASS-STUDY.md](docs/CLASS-STUDY.md) is the continuation runbook, and
  [docs/PROJECT-HISTORY.md](docs/PROJECT-HISTORY.md) preserves thesis progression.
  Keep README.md an operator guide. Do not depend on private parent-workspace
  notes or archived READMEs. Describe unavailable evidence with relative code
  paths through [docs/EVIDENCE-INDEX.md](docs/EVIDENCE-INDEX.md).
- If a client/Lab/defence defect appears during the campaign, diagnose and fix
  it within client-only scope, preserve the failed cohort, validate the fix,
  and restart under a fresh cohort. Do not weaken a gate to conceal a failed
  attempt. An explicitly authorised study redesign must be prospective,
  versioned, tested and bound to new source and evidence; old receipts remain
  verifiable on their historical contract and gain no new authority.
- Use the new `resource-study` route for the new sampling design as it becomes
  available. Do not impose the historical 110-vector browser sequence, three
  stability windows or all-five qualification chain as undeclared launch
  dependencies. Reuse the verified cached Native D2 client for Lab-only
  changes through the public runtime producer with exact SDK, client and image
  bindings; do not claim that an old installed SDK contains new collector code.

## Validation and claims

- Validate changes in proportion to risk. At minimum run relevant focused
  tests, schema/receipt compatibility checks where applicable, link checks for
  documentation, and `git diff --check`.
- Reconfirm source heads, cleanliness, and Gitlink before launching or making
  an evidence-authority claim.
- A launched attempt, locally passing test, image, or partial vector sequence is
  engineering progress only. Claim a gate pass only after its required final
  receipt and closed inventory independently verify.
- Use current status in [PROJECT.md](PROJECT.md), checked-in specifications such
  as [config/class-study/v1/study.json](config/class-study/v1/study.json), the
  latest immutable receipts, and `./qcsd-lab class-study --help`. External or
  untracked workspace notes are not repository authority.
