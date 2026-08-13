# Research defense artifacts

`./qcsd-lab fit <sealed-fitting-result>` creates one fixed, sealed runtime
bundle at `artifacts/research-1200/` containing exactly:

- `traffic-morphing.json`
- `wtf-pad.json`
- `walkie-talkie.json`
- `provenance.json`

Generated bundle contents are intentionally ignored by Git and excluded from
the Docker build context. The production research bundle has been fitted and
verified locally; its generated contents are deliberately not checked in.
