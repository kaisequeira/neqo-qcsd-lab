# Move the resource-domain study to a Mac

## Status and what moves

The migration tool can prepare and verify a source handoff locally. **An actual
Mac runtime, capability pilot and accepted session have not been demonstrated.**
The Mac is described as powerful and connected by Ethernet; its model, available
CPU IDs, memory and free disk space remain unknown.

The approved target remains **50 exact resource hostnames × five modes ×
400 accepted connection sessions = 100,000**. Every accepted connection must
complete its own fixed 20 distinct URLs. The new accepted count is zero.
Earlier website captures remain historical evidence and do not enter this total.
See [the study guide](RESOURCE-DOMAIN-STUDY.md).

The handoff contains:

- `source.tar.gz`: committed Lab source and its exact Native Gitlink source;
- `supplied-resources.json`: the original supplied JSON bytes, including queries;
- `manifest.json`: both commits, portable origin URLs, artifact hashes, full
  file modes and the archive's member inventory;
- `SHA256SUMS` and `CHECKOUT.md`: integrity checks and exact Git restore commands.

It includes no working Python environment, Docker images, cached client, active
SQLite ledger or live capture corpus. This is a fresh-start source handoff.
Resuming recorded work needs a separate owner-reviewed transfer of the stopped
ledger, all raw evidence and original runtime dependencies; copying this package
does not transfer session credit.

**The source tar is not a Git checkout.** The runtime producer requires the
original clean commits, including the pinned Native submodule. Restore those
from published repositories using `CHECKOUT.md`. Do not run `git init` on the
tar and treat the resulting history as the recorded source. This package needs
network access to the published commits; it is not an offline Git backup.
An offline restoration would require separately authenticated Git bundles.

## 1. Package only after the source is committed

On the existing Linux machine, use the final clean checkout. Substitute the
owner's published commits and frozen JSON digest; the example does not invent
a future Lab commit. Keep the package destination outside the checkout and
choose a new, absent directory.

```sh
python3 tools/resource_study_migration.py create \
  --source /absolute/clean/checkout \
  --lab-commit LAB_COMMIT_40_HEX \
  --native-commit NATIVE_COMMIT_40_HEX \
  --resources /absolute/frozen/resources.json \
  --resources-sha256 FROZEN_JSON_SHA256 \
  --output /absolute/fresh/mac-handoff
```

Creation refuses dirty Lab or Native source, a different Gitlink, unarchived
nested submodules, mismatched input bytes and an existing destination. It
archives committed files rather than ignored build or capture directories.
An interrupted output remains claimed; use a fresh destination after diagnosis.
The tool performs no runtime build, Docker action, enrollment or capture.

Record the returned `manifest_sha256` separately from the package. After copying,
verify it using the trusted migration tool from the exact published source:

```sh
python3 tools/resource_study_migration.py verify \
  --package /absolute/copied/mac-handoff \
  --manifest-sha256 RECORDED_MANIFEST_SHA256
```

Verification reopens bytes, full file modes and archive members without extracting
them or invoking Git. Preserve permissions when transferring the package;
its files are read-only (`0444`). A checksum file carried beside its contents
alone does not provide an independent trusted digest. Package verification
establishes transfer integrity, not a working Mac runtime.

## 2. Use a Linux ARM64 guest on Apple Silicon

The current launcher is a **Linux host program**. On an Apple Silicon Mac,
prepare an Ubuntu ARM64 virtual machine and install **Docker Engine inside that
guest**, using native ARM64 images. Keep source and study files on a Linux
filesystem such as ext4, with case sensitivity, Unix permissions, locking and
durable writes. Do not place the active ledger on a macOS shared folder without
establishing those properties.

Docker publishes separate Apple Silicon and Intel Desktop installers, but that
does not make this study's host launcher a Darwin program.
[Docker's Mac installation documentation](https://docs.docker.com/desktop/setup/install/mac-install/)
describes Desktop; [Docker's Ubuntu Engine installation guide](https://docs.docker.com/engine/install/ubuntu/)
is the relevant Engine setup for this guest. Docker also documents that CPU
emulation can be slower than native execution; use a native ARM64 build rather
than interpreting an amd64 image as equivalent timing evidence.
[Docker multi-platform builds](https://docs.docker.com/build/building/multi-platform/)

Start with **two workers, six guest CPU IDs and 16 GB RAM** as an operating
budget. The scheduling contract requires at least `2N + 1` actual available
CPU IDs: five for two workers, nine for four. Those minima do not establish
performance or fidelity under virtualization. Give the guest sufficient memory
and physical storage, use Ethernet, and measure the two-worker pilot before
considering four. CPU pinning inside a VM does not prove exclusive scheduling
on the Mac's physical cores.

The guest must expose the actual Linux capabilities used by capture: cgroups,
the required process scheduling and network privileges, `CLOCK_TAI`, ETF,
`SO_TXTIME`/`SCM_TXTIME`, packet capture and the routed physical observer.
Native ARM64 also needs readable `CNTFRQ_EL0`/`CNTVCT_EL0` system counters.
A VM that boots or a successful image build does not prove these work.
Retain capability failures and stop the affected mode rather than weakening
its timing checks. The existing source paths are
[the runtime producer](../src/qcsd_lab/rapid_portable_runtime.py),
[the collector runtime](../src/qcsd_lab/resource_study_runtime.py) and
[the scheduling contract](../src/qcsd_lab/process_scheduler.py).

## 3. Restore clean Git source, then build an actual ARM64 runtime

Follow the package's exact `CHECKOUT.md` commands inside the guest. Confirm both
heads, the Native Gitlink and clean statuses. Keep the copied resource JSON,
runtime build directory and study directory **outside** the checkout. Install
the locked Lab dependencies using the repository's environment instructions.
For example, from the restored source:

```sh
uv sync --frozen --all-extras
```

The current cached Linux x86-64 client cannot be reused as an ARM64 client.
Reuse the same Native source commit, but perform a real native ARM64 build
once and record its new executable, image, SDK and platform bindings. An
architecture change alone does not require a fabricated new source commit.

The public producer's initial ARM64 route is a cold build; leave out
`--reuse-canonical` for an x86-64 prior runtime. The explicit prospective
resource-domain policy below skips the old broad Rust formatting, test and
Clippy gates. It still compiles the release client and checks the complete
source, installed SDK and exported bytes:

```sh
.venv/bin/python3 tools/rapid_portable_runtime.py stage \
  --checkout /absolute/restored/checkout \
  --lab-commit LAB_COMMIT_40_HEX \
  --native-commit NATIVE_COMMIT_40_HEX \
  --platform linux/arm64 \
  --cold-check-policy resource-domain-live-pilot-v1 \
  --build-root /absolute/fresh/arm64-runtime
.venv/bin/python3 tools/rapid_portable_runtime.py build \
  --build-root /absolute/fresh/arm64-runtime
.venv/bin/python3 tools/rapid_portable_runtime.py verify \
  --canonical /absolute/fresh/arm64-runtime/canonical-runtime.json \
  --canonical-sha256 RECORDED_CANONICAL_SHA256
```

Use the completed producer's actual canonical file and digest. A failed build
is not a verified runtime. Later Lab-only changes on the same architecture can
use the producer's authenticated client-reuse route; that is separate from
the first ARM64 compilation. The build closure alone grants no live admission,
mode readiness or scientific session credit.

The selected policy is bound into the build inputs and an installed receipt
that explicitly records that Rust gates were **not run**. Omitting the option
keeps the original `full` policy. This option applies only to a new cold build;
authenticated client reuse retains its original build authority. ARM64 runtime
behavior remains unverified until actual live pilots pass. Before formal
capture in each of the five modes, its pilot must complete all 20 resources
on the new architecture and satisfy the physical evidence checks below.

## 4. Prepare the input and run a small, zero-credit pilot

Use the restored public route's help to confirm current options:

```sh
./qcsd-lab resource-study prepare --help
./qcsd-lab resource-study capture --help
```

Import into a fresh study directory, then live-enroll a declared hostname from
the copied candidate list. Replace `RESOURCE_HOSTNAME` with its exact name;
this is not permission to substitute a page hostname or a different URL set.

```sh
./qcsd-lab resource-study prepare \
  --root /absolute/fresh/study \
  --source /absolute/copied/mac-handoff/supplied-resources.json
./qcsd-lab resource-study prepare \
  --root /absolute/fresh/study \
  --runtime /absolute/fresh/arm64-runtime/canonical-runtime.json \
  --enroll --hostname RESOURCE_HOSTNAME
./qcsd-lab resource-study capture \
  --root /absolute/fresh/study \
  --runtime /absolute/fresh/arm64-runtime/canonical-runtime.json \
  --hostname RESOURCE_HOSTNAME --workers 2 --pilot --chunk 1 --attempts 5
./qcsd-lab resource-study verify --root /absolute/fresh/study
./qcsd-lab resource-study status --root /absolute/fresh/study
```

Pilot receipts must independently join the actual connection tuple and handshake,
all 20 complete full GETs, PCAP, request trace, mode and runtime. Pilots carry
**zero formal credit**. Five attempts are a bounded first exercise, not a
promise that every mode passes. A failed mode remains independently blocked;
it must not stop another ready mode.

Only after ordinary traffic has its own passing pilot, start a small formal
ordinary batch. Do not omit `--mode undefended` and accidentally select all modes:

```sh
./qcsd-lab resource-study capture \
  --root /absolute/fresh/study \
  --runtime /absolute/fresh/arm64-runtime/canonical-runtime.json \
  --hostname RESOURCE_HOSTNAME --workers 2 --mode undefended \
  --chunk 1 --attempts 2
./qcsd-lab resource-study verify --root /absolute/fresh/study
./qcsd-lab resource-study status --root /absolute/fresh/study
```

Enable each defense's formal capture only after its own pilot verifies on this
runtime. Keep every failed attempt, tuple collision and interrupted receipt.
The fixed traffic parameters and acceptance rules stay declared; changing
hardware does not silently relax them or import old platform credit.

## 5. Measure capacity before committing to the full study

Measure complete accepted and failed pilot folders, not just filtered PCAPs.
Budget logs, full tails, immutable receipts, SQLite, recovery space and exports.
The existing D-backed sparse volume's 512 GiB logical capacity and previously
reported roughly 362 GiB physical free space do **not** establish enough room
for 100,000 sessions or describe the Mac's storage.

At an **unmeasured** effective 20 seconds per accepted session per worker,
100,000 sessions would take about 11.6 continuous days with two workers or
5.8 with four. These are planning arithmetic, not Mac benchmarks. BuFLO's
640-second nominal event budget can make individual sessions much slower;
retries and verification also matter. Establish rates and bytes separately
for each mode before projecting the whole five-mode study.

Workspace cleanup is a separate owner-reviewed operation after local checks.
This tool does not delete diagnostic clones, old evidence, image caches or
unfinished changes.
