# Complete current application delivery

The prospective capture policy `complete-current-application-delivery-v1`
accepts a complete current application response even when its wire size,
body hash or content encoding differs from the original preparation. The
original resource graph and preparation remain unchanged.

Declare the policy before capture in the campaign and portable flight setup:

```sh
python tools/rapid_class_mode_flight.py stage \
  --application-body-identity-policy complete-current-application-delivery-v1 \
  ...
```

The usual stage arguments bind an actual clean Source checkout, installed
runtime, client, enrolled class group and fresh output namespace. The optional
`--qualification-delivery-compatibility PATH` selects a separately authenticated
response-qualification witness. It permits reuse only of the exact original
qualified sidecars and base manifests by the declared current consumer. It
does not grant capture or canary success. Without a witness, qualification
retains the current Source and image equality rules.

## What a successful capture proves

Every declared resource occurrence, ID, URL, dependency, origin and request
header remains in the full graph. Each resource must have its exact declared
HTTP status and successful complete stream outcome. The existing response
policy continues to govern complete terminal HTTP error leaves, including
declared 404 responses. The primary Document retains its existing public HTML
requirements.

The current run must retain the complete unique HTTP/3 origin set, intact
Native terminal evidence, its declared observed response cap, and nonempty
bodies for resources whose preparation was nonempty. Genuine declared empty
bodies remain permitted. A present content length must equal observed bytes.
Each visit retains its actual size, SHA256 and response headers; encoding is
derived from those retained headers, with an absent encoding header denoting
identity. **Content equality across visits is unclaimed.**

Promotion, fidelity comparison, independent deep verification, canary
readiness and formal planning all use the same explicit policy. Raw delivery
is checked before the size/hash comparison projection. Chaff response identity,
named qualification, traffic parameters, capture limits, clocks, Source and
client guards retain their existing checks.

## Historical evidence and prospective flights

An absent field retains exact prepared-body comparisons. The explicit strict
enum is `exact-prepared-application-body-v1`; unknown, Boolean or null campaign
values are refused. Earlier accepted counters and failed canaries keep their
original meaning and bytes. The retained complete 20-response failure is used
only as a HOST contract for this prospective policy, with zero scientific
credit.

The policy currently authorizes serial lanes through their own successful
current canary and deep verification. Existing parallel capsules cannot select
it. A prospective parallel policy must explicitly bind these semantics before
those lanes can run. The corpus target remains 50 classes × 5 modes × 64 visits
= 16,000 traces.
