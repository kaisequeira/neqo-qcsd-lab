# Capture design

The canonical v1 observer is the isolated container's `eth0` interface. This
keeps unrelated host traffic out of the trace and observes encrypted QUIC
before host NAT. It is not a claim about a physical WAN vantage point; future
host-uplink or WireGuard backends can add that perspective without changing
the campaign or workload schemas.

The collection sequence is fixed:

1. Perform a direct Neqo HTTP/3 preflight without mutating the manifest.
2. Record interface features, disable GRO/GSO/TSO, and start bounded `dumpcap`.
3. Run one fresh live workload with one defense and an explicit derived seed.
4. stop capture with SIGINT, validate it using `capinfos`, and obtain endpoint
   tuples from Neqo's atomic `run.json`.
5. Apply an exact bidirectional five-tuple display filter with TShark.
6. Extract epoch time, `frame.len`, direction, and connection into
   `traffic.csv`; optionally export classic PCAP.
7. Compare status, byte count, outcome, and body SHA-256 with the block's
   baseline. Preserve drifted or failed samples but exclude them from strict
   paired comparison.

`traffic.pcapng` is the canonical capture. PCAPNG retains interface and timing
metadata more faithfully than legacy PCAP. No TLS key log is produced by the
launcher. Neqo qlog remains available for protocol-level inspection and qvis.

Docker's veth/NAT path is part of the v1 measurement environment and is
recorded through image, interface, and offload metadata. It adds a stable lab
vantage rather than trying to emulate a browser or an arbitrary physical NIC.
# ARM64 NSS linking

The collection image uses release-mode dynamic linking against the exact NSS
3.121 build, so the NSS ARM64 GCM assembly wrapper is already part of the
runtime library. Developer debug/static links can require the upstream
`nss-rs` workaround used by the Neqo submodule: locate
`libaarch64-gcm-wrap_c_lib.a` below the Cargo `nss-rs` build output and pass
its directory plus `-l static=aarch64-gcm-wrap_c_lib` to the final test or
binary link. Apply those flags with `cargo rustc -- <flags>`, not global
`RUSTFLAGS`, because global flags also try to link the archive into host build
scripts.
