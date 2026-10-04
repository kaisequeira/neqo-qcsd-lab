# FRONT V4: leave time to finish preparing a padding packet

The study remains **50 classes × 5 modes × 64 visits = 16,000 formal traces**.
This prospective change addresses a FRONT send failure and keeps every enrolled
application resource and origin. It changes neither the selected classes nor
the other modes' traffic settings.

## Why the change is needed

In a four-seed FRONT V3 diagnostic, two attempts completed all 260 application
resources across four origins. The other two aborted before their socket calls:
packet preparation finished 3,765 ns and 8,419 ns after the padding deadlines.
The adapter had checked eligibility before construction, when the deadline had
not yet passed. Encryption and attribution then used the remaining time.

The unsuccessful V3 attempts stay unsuccessful. Their old traces do not retain
the rejected prepared datagrams, so their exact coalesced byte composition
cannot be reconstructed from nearby packets.

V4 stops beginning padding construction **1 ms earlier**, while preserving the
original physical send deadline:

| Time since the padding target | What happens |
| --- | --- |
| Before release | Padding remains ineligible. |
| From release to less than 9 ms | Padding construction may begin. |
| At or after 9 ms | An unbuilt padding target expires. Application and control work remain live. |
| Before 10 ms | A target already built may reach the socket. |
| At or after 10 ms | Sending the target remains a hard failure. |

Existing microsecond rounding remains. Each actual construction deadline is
exactly 1,000 microseconds earlier than its recorded socket deadline. The runner
takes a fresh monotonic sample before construction. A long scheduler pause can
still cause a failure; the reserve does not guarantee real-time execution.

## What the evidence must show

The exact prepared policy is:

`rapid-v5-front-bounded-outgoing-padding-omission-10pct-window-10000us-reserve-1000us-v4`

Its native marker has schema version 4 and declares the 9 ms construction
window, 1 ms reserve, unchanged 10 ms physical window and unchanged 10% combined
outgoing pure-padding omission limit. The marker requires the original
research1200 FRONT parameters and the existing authenticated application
preparation contract.

The Lab reopens the raw schedule, events and physical packets and checks:

- Every outgoing target has one original action and one explicit
  `front_padding_preparation_window` record.
- The transport action changes only the construction deadline by 1,000
  microseconds. Packet size, origin ownership, target identity, stream exclusion
  and the original socket deadline stay bound to the same target.
- Ordinary expiry has a matching native miss observation at or after the exact
  construction deadline. A target registered during its reserved tail instead
  has an explicit unbuilt omission, without transport mutation or socket success.
- An omitted target has no physical packet. A successful target has its actual
  nanosecond datagram observation matched to its physical packet and original
  half-open socket window.
- A `front_prepared_output_failure` record cannot earn omission or success
  credit. An overrun still fails and retains the built datagram hash, composition,
  timestamps and target identity for diagnosis.
- The 10% limit is calculated by exact multiplication. All incoming credit,
  incoming completion, outgoing size and complete application checks remain.

Expiry happens before frames are selected. It does not cancel or consume
application, retransmission, reviewed-chaff or mandatory control bytes. Real
application and control work can continue in an ordinary datagram. A built
packet containing such bytes cannot be relabelled as an accepted unbuilt omission.

Implementation: [policy markers](../src/qcsd_lab/capture_acceptance_policy.py),
[raw window and send evidence](../src/qcsd_lab/front_preparation_evidence.py),
and [capture fidelity](../src/qcsd_lab/fidelity.py).

## Declare fresh capture inputs

The [capture amendment](../src/qcsd_lab/rapid_front_capture_amendment.py) creates
fresh FRONT manifests from the original V1 enrolled manifests. It replaces one
quoted FRONT policy literal, preserves the complete resource records, and copies
all original application evidence with unchanged bytes and executable metadata.
It never overwrites an earlier manifest, evidence directory or declaration.

The V4 amendment receipt is
`qcsd-rapid-v6-front-capture-policy-amendment-v3`. Its amendment version differs
from the native marker version because the existing V2 and V3 capture policies
already have amendment versions 1 and 2. The new receipt explicitly binds the
construction, socket and reserve windows to the capture runtime, actual client,
image, enrollment and original application evidence. It grants zero formal
trace or qualification credit.

Use the existing [rolling capture CLI](../tools/rapid_rolling_capture.py) with an
explicit V4 policy and fresh destinations:

```bash
PYTHONPATH=src python3 tools/rapid_rolling_capture.py front-amendment \
  --enrollment "$FRONT_V4_ENROLLMENT" \
  --runtime-spec "$FRONT_V4_RUNTIME_SPEC" \
  --output "$FRONT_V4_AMENDMENT" \
  --capture-policy rapid-v5-front-bounded-outgoing-padding-omission-10pct-window-10000us-reserve-1000us-v4
```

Then use the existing qualification, fresh complete-graph canary, independent
deep verification, plan publication and recoverable lane launch steps with that
declaration. The declaration alone cannot satisfy those gates or transfer an old
canary to new source. Existing V1–V3 inputs and all attempted cohorts remain on
their original contracts. Other modes retain their existing source and traffic
requirements.

See [EVIDENCE-INDEX.md](EVIDENCE-INDEX.md) for operational milestones and accepted
counters. The [raw evidence tests](../tests/test_capture_front_reserve_policy.py)
and [amendment tests](../tests/test_rapid_front_reserve_amendment.py) exercise the
boundaries and rejection paths; local tests themselves advance no formal counter.
