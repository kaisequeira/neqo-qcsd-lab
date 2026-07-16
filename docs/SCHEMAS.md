# Input and output schemas

## Workload manifest v2

A manifest contains `schema_version: 2`, a `header_policy`, and stable
resources. Each resource has an integer ID, absolute HTTPS URL, browser-style
type, optional observed lengths, chaff selection flags, validity, dependency
IDs, and ordered header pairs. Neqo rejects duplicate IDs, missing/self/cyclic
dependencies, non-HTTPS URLs, pseudo-headers, connection-specific fields,
stored credentials, and unsafe values.

The adjacent `.sha256` covers the exact canonical JSON bytes. Discovery
freezes request definitions; it does not cache response bodies. `probe`
preserves IDs, dependency edges, types, and headers while enriching lengths and
HTTP/3 validity.

## Campaign v1

Campaign YAML records:

- named workload manifest paths;
- named defense TOML paths or built-in presets;
- repetition count and master seed;
- response, timeout, capture duration/filesize, and inter-run bounds;
- interface, raw-capture retention, optional PCAP export, and plotting values.

Defense seeds and defense order are SHA-256-derived from the master seed,
workload name, repetition, and defense name. Adding a defense normally means
adding one TOML and one campaign entry.

## Sample outputs

`sample.json` is the orchestration envelope. It records state, seed, content
drift, comparison eligibility, commits, image ID, capture outcome, and
interface/offload state. `SHA256SUMS` covers retained sample files.

The Neqo output directory contains:

- `run.json` v2: atomic running/final state, nanosecond anchor, resolved
  workload/header policy/config, endpoints and UDP tuples, ALPN, response
  request/response headers, status, byte count, outcome, and body SHA-256;
- `packets.csv`: observed UDP payloads and immediate target matching;
- `events.csv`: controller observations/actions and failure reasons;
- `schedule.csv`: target time, direction, size, endpoint, action time,
  satisfaction, observed size, and miss reason;
- `qlog/`: one trace per connection.

`traffic.csv` is derived from the filtered PCAPNG and contains UNIX/relative
nanoseconds, direction, observer `frame.len`, signed frame length, and Neqo
connection ID.
