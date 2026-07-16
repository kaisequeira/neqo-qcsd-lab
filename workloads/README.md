# Frozen workloads

Workload manifests and their `.sha256` files belong in this directory. A
manifest freezes public request definitions; response bodies are never cached
for measured runs. Generate a new version rather than editing a manifest that
has already contributed samples.

`example-v1.json` is a schema example, not a claim that the endpoint currently
offers HTTP/3. Run `qcsd-lab probe` immediately before adding it to a campaign,
then use the enriched output with `known_valid` response resources.
