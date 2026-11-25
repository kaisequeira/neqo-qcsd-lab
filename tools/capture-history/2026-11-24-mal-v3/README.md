# MAL v3 capture drivers, 24–25 November 2026

This directory preserves the exact Python driver versions reported by the
selected `cdn.myanimelist.net` replacement captures in the final six-condition
study. These are historical source snapshots, not a supported entry point for
new captures. Several scripts assume the original Linux environment, external
configuration, and capture infrastructure; their embedded paths and commands
describe that environment and are not portable setup instructions.

`driver-index.csv` maps each defense, original filename, source SHA-256 and
selected-session count to the corresponding file in `drivers/`. Filenames are
the SHA-256 of the exact preserved bytes. Multiple versions are retained when
final selected sessions report different driver identities; they must not be
treated as interchangeable or merged into one inferred historical version.

The index was assembled by joining the final replacement staging receipts to
their selected per-session `FINAL.json` records. For BuFLO, the final timing
map supplied the selected attempt IDs. All 400 selected records per condition
matched their slot and reported success; for the other five conditions each
record also matched the SHA-256 in its staging receipt. The complete
session-level mapping and its supporting records are preserved separately in
the private study reference library. These joins establish recorded source
identities, not a fresh execution, defense-fidelity validation, or independent
assessment of scientific eligibility.

The final MAL BuFLO cohort contains both 5 ms and 20 ms outgoing-window
variants. The timing map, not this source index, determines the variant used
for a particular session. The 20 ms window is a study-specific relaxation;
do not describe it as paper-equivalent.
