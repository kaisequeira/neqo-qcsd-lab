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
- At this checkpoint, use **browser-egress 0/110, certification 0/900, formal
  capture 0/16,000**. V86's build/completion and pinned-CDP receipts verify.
  Its checkpoint preserves 97 passing vectors and a vector-98 operational
  failure caused by requesting a default-profile tab without an existing
  window. The window-creation and cleanup fix passes 630 selected host tests
  and 13 real-Chromium integration tests. These regression checks do not
  authorise old-cohort resume or a qualification pass. Preserve v86; v87 is
  the next planned fresh cohort at 13 September 2026. Re-read
  [README.md](README.md), the latest immutable receipts, and live checkpoint
  state before any later update rather than carrying these figures forward
  from memory.

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

## Evidence and cohort discipline

- `experiment.json` is the authoritative checkpoint for interruption, resume,
  attempt order, and completion state.
- Cohort versions and evidence destinations are create-only. Receipt absence
  does not make a claimed or attempted version reusable.
- Resume only an unchanged-source, unchanged-input checkpoint using the exact
  original arguments. A source, parameter, workload, image, or acceptance-rule
  change requires the next unused cohort and complete downstream reproof.
- Preserve failed attempts, logs, captures, checkpoints, and receipts. Never
  delete, overwrite, substitute, relabel, or post-hoc promote evidence.
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
- Use current status in [README.md](README.md), checked-in specifications such
  as [config/class-study/v1/study.json](config/class-study/v1/study.json), the
  latest immutable receipts, and `./qcsd-lab class-study --help`. External or
  untracked workspace notes are not repository authority.
