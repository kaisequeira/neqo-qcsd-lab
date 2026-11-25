# Seven replacement-host capture drivers, 23–24 November 2026

This directory preserves capture-driver Python sources identified in selected
replacement captures for seven resource-domain hosts and five defenses. These
are historical source snapshots, not a supported entry point for new captures.
The scripts assume the original Linux environment, external configuration, and
capture infrastructure; embedded paths and commands document that environment
and are not portable setup instructions.

`driver-index.csv` maps each host, defense, source SHA-256 and selected-session
count to its matching file in `drivers/`. A filename is the SHA-256 of the
exact source bytes. Multiple versions are retained where selected sessions
report different driver identities; those versions must not be treated as one
interchangeable historical implementation.

The index joins the 14,000 selected sessions (seven hosts × five conditions ×
400) from the final replacement staging receipts to their `FINAL.json` records.
Each record matched the receipt SHA-256, slot and reported success. The complete
session-level mapping and supporting records are kept separately in the private
study reference library. The join establishes recorded driver identities, not
a fresh execution, defense-fidelity validation, or independent assessment of
scientific eligibility.

Two source files have not yet been located, affecting seven `www.flashscore.com.mx`
BuFLO sessions. Their entries in `driver-index.csv` have blank `source_file` and
`original_filename` fields: slot 1 reports SHA-256
`5eba9b07bd6751d54737f3855ff667f8d2e80a8fa12ff65570dfe90d2583fe7f`, and
slots 2–7 report
`c31c7e563ae785f7ee9741e0a040a367a8141a27df8363c3eaa29efacb0cb9a0`.
The source bytes cannot be reconstructed from those hashes alone.
