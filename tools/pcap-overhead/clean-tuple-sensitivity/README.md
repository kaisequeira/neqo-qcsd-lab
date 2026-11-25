# Clean candidate-flow capture sensitivity

This secondary analysis asks how cohort estimates change when each condition is restricted to whole captures with valid IP parsing and one bidirectional UDP/443 candidate accounting for all observed IP bytes. It uses the same per-metric eligibility as the primary aggregator, then applies that selection separately to each condition. It does not remove other traffic from a capture, establish the intended connection, correct confounding, or imply causation. The span remains first-to-last observed packet, not application completion. Selection can change the population and introduce bias.

The input is the final capture manifest and the PCAP-derived metrics SQLite database produced by the toolkit. The script loads `aggregate.py` from its parent toolkit directory, independently of the working directory. No capture contents or historical measurements are required at this stage. The command checks the manifest's balanced six-condition, 50-domain, 400-session design, verifies all 120,000 identities, digests and sizes against stored extractor records, and requires zero extractor errors before creating the output directory. This checks recorded values; it does not independently reread the PCAPs.

```sh
python3 clean-tuple-sensitivity/clean_tuple_sensitivity.py --manifest session-manifest.csv --database full-metrics.sqlite3 --output clean-tuple-results
```

Run the command from the parent toolkit directory, or provide an absolute path to the script. Python 3.11+ and the toolkit's NumPy dependency are required. The output directory must not exist. Outputs:

* `domain-clean-tuple-sensitivity.csv`: each defense/domain/metric, primary and clean sample counts and means, independent-cohort percent overheads, primary exclusions, mutually exclusive clean-filter reasons, and the clean-minus-primary difference in percentage points.
* `overall-clean-tuple-sensitivity.csv`: equal-domain mean of per-domain overhead percentages and ratio of sums of per-domain means. Available-domain summaries use their own eligible domain sets. Differences are calculated only across domains eligible under both selections; the common-domain count and coverage flag make any restricted scope explicit. `full_available` reproduces the primary point estimand when all expected domains are eligible.
* `clean-tuple-quality.json`: manifest, metrics snapshot, and script hashes, selection, scope and limitations.

No confidence intervals are estimated for the difference. Session IDs are not paired across conditions. Directional ambiguity categories indicate the first failed criterion, not the cause of the other traffic. Comparisons are not evidence of application latency or classification effectiveness.

Run `python3 -m unittest discover -s clean-tuple-sensitivity -p 'test_*.py' -v` from the toolkit directory to check synthetic estimands, eligibility, coverage, zero-baseline handling and the incomplete-census gate against a synthetic balanced manifest and empty database.
