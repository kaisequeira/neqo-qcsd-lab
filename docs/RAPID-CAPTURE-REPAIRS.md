# Targeted repairs before the rapid capture study

The target remains **50 sites × five conditions × 64 visits = 16,000 accepted
formal traces**. This document explains the repairs prompted by the first
five-condition diagnostic on Poki. The original failed attempts remain failed;
new source needs new captures. See the [capture path](RAPID-CAPTURE-PATH.md) and
[evidence index](EVIDENCE-INDEX.md) for the recorded operations.

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
4. Capture one baseline and the failing settings on the complete graph. Stop
   and diagnose a failing condition immediately, retaining every attempt.
5. Deep-verify and independently reopen the fresh results. Only then proceed
   to the ten-site, five-condition study shakedown.

Focused unit and regression tests establish engineering behavior. Installed
byte checks, synthetic 16,000-slot fixtures and additional diagnostic captures
do not count toward the study's **50 shakedown or 16,000 formal traces**.

## Source

- [Capture policy validation](../src/qcsd_lab/capture_acceptance_policy.py)
- [Endpoint extraction](../src/qcsd_lab/capture.py)
- [Timing and reconciliation](../src/qcsd_lab/fidelity.py)
- [Independent deep verification](../src/qcsd_lab/verification.py)
- [Policy and boundary regressions](../tests/test_capture_acceptance_policy.py)
- [Endpoint tail regressions](../tests/test_endpoint_receive_tail.py)
- [PCAP replay and portable transport regressions](../tests/test_endpoint_capture_replay.py)
- [Collector runtime repair epochs](RAPID-RUNTIME-REPAIR.md)
