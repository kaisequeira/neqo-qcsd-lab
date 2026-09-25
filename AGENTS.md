# QCSD Lab agent and harness rules

These repository-local rules apply throughout `neqo-qcsd-lab/`.

## Research and scope boundary

- The authorised wording is **five validated defences plus two candidates /
  nine selectable modes** until a final validation attestation verifies.
- BuFLO and CS-BuFLO are client-only QUIC adaptations. Keep servers ordinary
  HTTP/3 endpoints; do not add bilateral or symmetric defence behaviour.
- Preserve multi-origin workload graphs. Never remove an origin or resource to
  make a defence, fitting stage, or capture pass.
- Report accepted scientific counters only from final deep-verified receipts.
  Historical passing prefixes and non-evidentiary probes advance no numerator.
- Do not carry checkpoint figures forward from these instructions or memory.
  Read [PROJECT.md](PROJECT.md), the latest immutable receipts, and live
  checkpoint state. Separate a completed historical gate from authority for
  changed source: v89's verified 110-vector browser gate cannot authorise the
  subsequent consumer fixes. Preserve all old cohorts and use the allocator's
  next unused version after source freeze.

## Live source-bound operations

- Before launch, require the exact clean Lab checkout, clean pinned Rust
  submodule/Gitlink, allocator authority, and create-only destinations.
- Run source-bound Docker campaigns serially. This includes builds, pinned-CDP,
  browser-egress, reference, timing, regression, code, controlled, and class
  capture stages.
- While such a process is live, every agent must perform **only polling of that
  existing process/session**. Do not read or edit repository files, run Git or
  graph commands, start parallel agents, launch tests, or issue unrelated
  Docker commands. Resume ordinary work only after the process exits.
- Keep the user informed during long operations without disturbing the live
  source boundary.
- Keep the execution checkout pinned throughout its campaign. Publish research
  progress from a separate authoring clone between live operations; a
  documentation commit must not move the running checkout's source identity.

## Evidence and cohort discipline

- `experiment.json` is the authoritative capture-campaign checkpoint for
  interruption, resume, attempt order, and completion state. Acquisition uses
  its `checkpoint.json` and bound `provenance.json`.
- Cohort versions and evidence destinations are create-only. Receipt absence
  does not make a claimed or attempted version reusable.
- Resume only an unchanged-source, unchanged-input checkpoint using the exact
  original arguments. A source, parameter, workload, image, or acceptance-rule
  change requires the next unused cohort and complete downstream reproof.
- Preserve failed attempts, logs, captures, checkpoints, and receipts. Never
  delete, overwrite, substitute, relabel, or post-hoc promote evidence.
- Acquisition-only authority cannot replace the full defence foundation for
  any capture role, including fitting. The later foundation must bind the same
  source, build, acquisition contract, pinned-CDP and browser-egress evidence.
- Complete acquisition only after the first 24 eligible candidates per stratum
  and every earlier candidate have scientific terminal evidence. Preserve the
  unused tail as unassessed. Infrastructure errors and missed stability windows
  are blockers, not selective site rejections. No active/recovery work may be
  hidden by a complete prefix.
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
  and restart under a fresh cohort. Do not weaken an acceptance gate.

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
