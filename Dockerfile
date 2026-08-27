# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
ARG DOCKERFILE_FRONTEND=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
ARG RUST_IMAGE=docker.io/library/rust:1.90-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f
ARG DEBIAN_IMAGE=docker.io/library/debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.10.7@sha256:edd1fd89f3e5b005814cc8f777610445d7b7e3ed05361f9ddfae67bebfe8456a

# Copy the uv executable from an immutable multi-platform image.  Every
# Python environment below is synchronized directly from uv.lock.
FROM ${UV_IMAGE} AS uv-bin

# Inspect the local parent checkout and submodule. This stage is also the
# source of the immutable provenance copied into both runtime images.
FROM ${DEBIAN_IMAGE} AS source-metadata
ARG RUST_IMAGE
ARG DEBIAN_IMAGE
RUN apt-get update && apt-get install -y --no-install-recommends git python3 && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /source
COPY . .
RUN set -eu; \
    lab_commit="$(git rev-parse HEAD)"; \
    lab_status="$(git status --porcelain --untracked-files=all)"; \
    lab_dirty=false; \
    if [ -n "${lab_status}" ]; then lab_dirty=true; fi; \
    cp .git/index /tmp/lab-index; \
    GIT_INDEX_FILE=/tmp/lab-index git add -A; \
    lab_patch_sha256="$(GIT_INDEX_FILE=/tmp/lab-index git diff --cached --binary HEAD | sha256sum | cut -d ' ' -f 1)"; \
    neqo_mode="$(git ls-files --stage -- neqo-qcsd | awk '{print $1; exit}')"; \
    neqo_pinned_commit="$(git ls-files --stage -- neqo-qcsd | awk '{print $2; exit}')"; \
    test "${neqo_mode}" = 160000 && test -n "${neqo_pinned_commit}"; \
    neqo_commit="$(git -C neqo-qcsd rev-parse HEAD)"; \
    neqo_status="$(git -C neqo-qcsd status --porcelain --untracked-files=all)"; \
    neqo_dirty=false; \
    if [ -n "${neqo_status}" ]; then neqo_dirty=true; fi; \
    neqo_index="$(git -C neqo-qcsd rev-parse --git-path index)"; \
    cp "${neqo_index}" /tmp/neqo-index; \
    GIT_INDEX_FILE=/tmp/neqo-index git -C neqo-qcsd add -A; \
    neqo_patch_sha256="$(GIT_INDEX_FILE=/tmp/neqo-index git -C neqo-qcsd diff --cached --binary HEAD | sha256sum | cut -d ' ' -f 1)"; \
    printf '{"image_digest":null,"lab_commit":"%s","lab_dirty":%s,"lab_patch_sha256":"%s","neqo_commit":"%s","neqo_pinned_commit":"%s","neqo_dirty":%s,"neqo_patch_sha256":"%s"}\n' \
      "${lab_commit}" "${lab_dirty}" "${lab_patch_sha256}" \
      "${neqo_commit}" "${neqo_pinned_commit}" "${neqo_dirty}" "${neqo_patch_sha256}" \
      > /source-metadata.json; \
    uv_lock_sha256="$(sha256sum uv.lock | cut -d ' ' -f 1)"; \
    cargo_lock_sha256="$(sha256sum neqo-qcsd/Cargo.lock | cut -d ' ' -f 1)"; \
    printf '{"artifact_type":"qcsd-study-build-inputs","cargo_lock_sha256":"%s","debian_base_image":"%s","rust_base_image":"%s","schema_version":1,"uv_lock_sha256":"%s"}\n' \
      "${cargo_lock_sha256}" "${DEBIAN_IMAGE}" "${RUST_IMAGE}" "${uv_lock_sha256}" \
      > /study-build-inputs.json

# Hash the exact response-qualification execution surface.  BuFLO study,
# reference, evaluator, and native-tool sources are bound separately by the
# versioned study evidence rather than changing the sealed qualification
# receipt contract.  The final runtime stage adds hashes of the installed
# modules, generated entrypoint, and Neqo client executable.
RUN python3 - <<'PY'
import hashlib
import json
from pathlib import Path

root = Path("/source")
paths = [
    ".dockerignore",
    "Dockerfile",
    "docker/collection-entrypoint",
    "pyproject.toml",
    "qcsd-lab",
    "uv.lock",
]
paths += [
    "src/qcsd_lab/__init__.py",
    "src/qcsd_lab/analysis.py",
    "src/qcsd_lab/capture.py",
    "src/qcsd_lab/capture_session.py",
    "src/qcsd_lab/chaff_qualification.py",
    "src/qcsd_lab/cli.py",
    "src/qcsd_lab/defenses.py",
    "src/qcsd_lab/discover.py",
    "src/qcsd_lab/experiment.py",
    "src/qcsd_lab/fidelity.py",
    "src/qcsd_lab/fitting.py",
    "src/qcsd_lab/fitting_morphing.py",
    "src/qcsd_lab/fitting_trace.py",
    "src/qcsd_lab/fitting_walkie_talkie.py",
    "src/qcsd_lab/fitting_wtfpad.py",
    "src/qcsd_lab/manifest.py",
    "src/qcsd_lab/orchestrator.py",
    "src/qcsd_lab/parameters.py",
    "src/qcsd_lab/plotting.py",
    "src/qcsd_lab/prepare.py",
    "src/qcsd_lab/profiles.py",
    "src/qcsd_lab/report.py",
    "src/qcsd_lab/util.py",
    "src/qcsd_lab/verification.py",
]
files = {path: hashlib.sha256((root / path).read_bytes()).hexdigest() for path in paths}
Path("/qualification-source-files.json").write_text(
    json.dumps(files, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

FROM ${DEBIAN_IMAGE} AS osad-builder
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY tools/qcsd_osad.c ./qcsd_osad.c
RUN mkdir -p /out/usr/local/lib/qcsd && \
    cc -O3 -std=c11 -fPIC -shared -Wall -Wextra -Werror \
      qcsd_osad.c -o /out/usr/local/lib/qcsd/libqcsd_osad.so

# Fetch the exact Weka 3.7.5 VNG++ runtime declared by the pinned reference
# receipt.  Formal evaluation verifies these hashes again before execution.
FROM ${DEBIAN_IMAGE} AS weka-builder
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*
RUN mkdir -p /out/opt/qcsd/weka && \
    curl --fail --location --retry 3 \
      https://repo1.maven.org/maven2/nz/ac/waikato/cms/weka/weka-dev/3.7.5/weka-dev-3.7.5.jar \
      -o /out/opt/qcsd/weka/weka-dev-3.7.5.jar && \
    curl --fail --location --retry 3 \
      https://repo1.maven.org/maven2/org/pentaho/pentaho-commons/pentaho-package-manager/0.9.9/pentaho-package-manager-0.9.9.jar \
      -o /out/opt/qcsd/weka/pentaho-package-manager-0.9.9.jar && \
    curl --fail --location --retry 3 \
      https://repo1.maven.org/maven2/net/sf/squirrel-sql/thirdparty-non-maven/java-cup/0.11a/java-cup-0.11a.jar \
      -o /out/opt/qcsd/weka/java-cup-0.11a.jar && \
    printf '%s  %s\n' \
      4d20516c9d32e3433b402f8898a2430cb4b519734ba4877c39726878c18ec4ad \
      /out/opt/qcsd/weka/weka-dev-3.7.5.jar \
      a336161c0e868d8334449eb5d695bc16c961fc545a51bae60ac091af1e5722ca \
      /out/opt/qcsd/weka/pentaho-package-manager-0.9.9.jar \
      9afcfd0996dcc9a933e66749988428ad964d8c1b678107fe688a6fa55325e17e \
      /out/opt/qcsd/weka/java-cup-0.11a.jar | sha256sum -c -

# Build NSS once from Mozilla's checksum-pinned combined NSS/NSPR release.
# No Neqo repository is cloned in this image.
FROM ${RUST_IMAGE} AS neqo-toolchain
ARG TARGETARCH
ARG NSS_BUNDLE_URL=https://ftp.mozilla.org/pub/security/nss/releases/NSS_3_121_RTM/src/nss-3.121-with-nspr-4.38.2.tar.gz
ARG NSS_BUNDLE_SHA256=76b9a1364bc4522abc652c4d676498d5062f502f64e38b32e9e2c7a3fff530f1
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates clang cmake curl git gyp libclang-dev llvm-dev \
    ninja-build perl pkg-config python3 && \
    rm -rf /var/lib/apt/lists/*
RUN curl --fail --location --retry 3 "${NSS_BUNDLE_URL}" -o /tmp/nss.tar.gz && \
    echo "${NSS_BUNDLE_SHA256}  /tmp/nss.tar.gz" | sha256sum -c - && \
    mkdir -p /opt/mozilla && \
    tar -xzf /tmp/nss.tar.gz --strip-components=1 -C /opt/mozilla && \
    rm /tmp/nss.tar.gz
ENV NSS_DIR=/opt/mozilla/nss \
    NSPR_DIR=/opt/mozilla/nspr \
    NSS_PREBUILT=1 \
    LD_LIBRARY_PATH=/opt/mozilla/dist/Release/lib
RUN set -eux; \
    set -- -Ddisable_tests=1 -Ddisable_dbm=1 -Ddisable_libpkix=1 \
      -Ddisable_ckbi=1 -Ddisable_fips=1 --opt --static; \
    if [ "${TARGETARCH}" = arm64 ]; then set -- "$@" --target=arm64; fi; \
    cd "${NSS_DIR}"; \
    bash ./build.sh "$@"
RUN rustup component add --toolchain 1.90.0 rustfmt clippy

# Run every mandatory Rust gate against the same clean, gitlink-matched source
# snapshot from which the release executables are built.  A failing gate makes
# the collection target unbuildable.  Logs and their self-hashed receipt are
# copied into the final image as immutable build evidence.
FROM neqo-toolchain AS neqo-code-gate
ARG TARGETARCH
ARG RUST_IMAGE
ARG UV_IMAGE
ARG DOCKERFILE_FRONTEND
ENV CARGO_TERM_COLOR=never
WORKDIR /src
COPY neqo-qcsd/ ./
COPY --from=source-metadata /source-metadata.json /tmp/source-metadata.json
COPY --from=source-metadata /study-build-inputs.json /tmp/study-build-inputs.json
RUN RUST_IMAGE="${RUST_IMAGE}" python3 - <<'PY'
import hashlib
import json
import os
import re
from pathlib import Path

empty_sha256 = hashlib.sha256(b"").hexdigest()
source_path = Path("/tmp/source-metadata.json")
inputs_path = Path("/tmp/study-build-inputs.json")
source = json.loads(source_path.read_text(encoding="utf-8"))
inputs = json.loads(inputs_path.read_text(encoding="utf-8"))

expected_source_keys = {
    "image_digest",
    "lab_commit",
    "lab_dirty",
    "lab_patch_sha256",
    "neqo_commit",
    "neqo_pinned_commit",
    "neqo_dirty",
    "neqo_patch_sha256",
}
if set(source) != expected_source_keys:
    raise SystemExit("unexpected source-metadata schema")
if source["image_digest"] is not None:
    raise SystemExit("build-time source metadata must not claim an image digest")
for field in ("lab_commit", "neqo_commit", "neqo_pinned_commit"):
    if not re.fullmatch(r"[0-9a-f]{40}", source[field]):
        raise SystemExit(f"invalid {field}")
if source["lab_dirty"] or source["neqo_dirty"]:
    raise SystemExit("Rust code gate requires clean Lab and Neqo checkouts")
if source["lab_patch_sha256"] != empty_sha256:
    raise SystemExit("clean Lab checkout has a non-empty patch hash")
if source["neqo_patch_sha256"] != empty_sha256:
    raise SystemExit("clean Neqo checkout has a non-empty patch hash")
if source["neqo_commit"] != source["neqo_pinned_commit"]:
    raise SystemExit("Neqo HEAD does not match the Lab gitlink")

expected_input_keys = {
    "artifact_type",
    "cargo_lock_sha256",
    "debian_base_image",
    "rust_base_image",
    "schema_version",
    "uv_lock_sha256",
}
if set(inputs) != expected_input_keys:
    raise SystemExit("unexpected study-build-inputs schema")
if inputs["artifact_type"] != "qcsd-study-build-inputs" or inputs["schema_version"] != 1:
    raise SystemExit("unexpected study-build-inputs identity")
if inputs["rust_base_image"] != os.environ["RUST_IMAGE"]:
    raise SystemExit("Rust base-image receipt differs from the code-gate image")
cargo_lock_sha256 = hashlib.sha256(Path("Cargo.lock").read_bytes()).hexdigest()
if inputs["cargo_lock_sha256"] != cargo_lock_sha256:
    raise SystemExit("Cargo.lock differs from the source-metadata receipt")
PY
RUN --mount=type=cache,id=qcsd-cargo-registry-${TARGETARCH},target=/usr/local/cargo/registry \
    --mount=type=cache,id=qcsd-cargo-git-${TARGETARCH},target=/usr/local/cargo/git \
    bash -euxo pipefail -c '\
      mkdir -p /out/rust-code-gate/logs; \
      run_gate() { \
        gate_name="$1"; shift; \
        { \
          printf "gate=%s\n" "${gate_name}"; \
          printf "command="; printf "%q " "$@"; printf "\n"; \
          "$@"; \
          printf "status=passed\n"; \
        } 2>&1 | tee "/out/rust-code-gate/logs/${gate_name}.log"; \
      }; \
      run_gate cargo-fmt cargo fmt --check; \
      run_gate neqo-csdef-tests cargo test -p neqo-csdef --locked; \
      run_gate neqo-transport-tests cargo test -p neqo-transport --features qcsd --locked; \
      run_gate neqo-http3-tests cargo test -p neqo-http3 --features qcsd --locked; \
      run_gate neqo-bin-tests cargo test -p neqo-bin --features qcsd --locked; \
      run_gate workspace-clippy cargo clippy --workspace --all-targets --features qcsd --locked -- -D warnings; \
    '
RUN TARGETARCH="${TARGETARCH}" \
    RUST_IMAGE="${RUST_IMAGE}" \
    UV_IMAGE="${UV_IMAGE}" \
    DOCKERFILE_FRONTEND="${DOCKERFILE_FRONTEND}" \
    python3 - <<'PY'
import hashlib
import json
import os
import subprocess
from pathlib import Path

domain = "qcsd-rust-code-gate-v1"
root = Path("/out/rust-code-gate")
source_path = Path("/tmp/source-metadata.json")
inputs_path = Path("/tmp/study-build-inputs.json")
commands = [
    {"gate": "cargo-fmt", "argv": ["cargo", "fmt", "--check"]},
    {
        "gate": "neqo-csdef-tests",
        "argv": ["cargo", "test", "-p", "neqo-csdef", "--locked"],
    },
    {
        "gate": "neqo-transport-tests",
        "argv": ["cargo", "test", "-p", "neqo-transport", "--features", "qcsd", "--locked"],
    },
    {
        "gate": "neqo-http3-tests",
        "argv": ["cargo", "test", "-p", "neqo-http3", "--features", "qcsd", "--locked"],
    },
    {
        "gate": "neqo-bin-tests",
        "argv": ["cargo", "test", "-p", "neqo-bin", "--features", "qcsd", "--locked"],
    },
    {
        "gate": "workspace-clippy",
        "argv": [
            "cargo",
            "clippy",
            "--workspace",
            "--all-targets",
            "--features",
            "qcsd",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
    },
]
logs = {}
for command in commands:
    path = root / "logs" / f"{command['gate']}.log"
    data = path.read_bytes()
    if not data.endswith(b"status=passed\n"):
        raise SystemExit(f"gate log has no terminal pass marker: {path}")
    logs[command["gate"]] = {
        "path": f"logs/{path.name}",
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

def version(*argv):
    return subprocess.check_output(argv, text=True).strip()

receipt = {
    "schema_version": 1,
    "artifact_type": "qcsd-rust-code-gate",
    "domain": domain,
    "passed": True,
    "target_arch": os.environ["TARGETARCH"],
    "dockerfile_frontend": os.environ["DOCKERFILE_FRONTEND"],
    "rust_base_image": os.environ["RUST_IMAGE"],
    "uv_image": os.environ["UV_IMAGE"],
    "source_metadata": json.loads(source_path.read_text(encoding="utf-8")),
    "source_metadata_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
    "study_build_inputs": json.loads(inputs_path.read_text(encoding="utf-8")),
    "study_build_inputs_sha256": hashlib.sha256(inputs_path.read_bytes()).hexdigest(),
    "commands": commands,
    "logs": logs,
    "tool_versions": {
        "cargo": version("cargo", "--version"),
        "clippy": version("cargo", "clippy", "--version"),
        "rustc": version("rustc", "--version", "--verbose"),
        "rustfmt": version("cargo", "fmt", "--version"),
    },
}
payload = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
receipt["sha256"] = hashlib.sha256(domain.encode() + b"\0" + payload).hexdigest()
(root / "receipt.json").write_text(
    json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

# Release artifacts are built only from the source that passed every gate.
FROM neqo-code-gate AS neqo-builder
ARG TARGETARCH
RUN --mount=type=cache,id=qcsd-cargo-registry-${TARGETARCH},target=/usr/local/cargo/registry \
    --mount=type=cache,id=qcsd-cargo-git-${TARGETARCH},target=/usr/local/cargo/git \
    neqo_commit="$(python3 -c 'import json; print(json.load(open("/tmp/source-metadata.json"))["neqo_commit"])')"; \
    case "${neqo_commit}" in (*[!0-9a-f]*|'') exit 1;; esac; \
    test "${#neqo_commit}" -eq 40; \
    cargo build --locked --release -p neqo-csdef --bin qcsd-validate-parameters && \
    NEQO_QCSD_GIT_COMMIT="${neqo_commit}" cargo build --locked --release -p neqo-bin --features qcsd \
      --bin neqo-qcsd-client --bin neqo-server && \
    mkdir -p /out/bin /out/nss/lib /out/nss/test-db && \
    cp target/release/neqo-qcsd-client target/release/neqo-server \
      target/release/qcsd-validate-parameters /out/bin/ && \
    find /opt/mozilla/dist/Release/lib -name '*.so*' -type f -exec cp -L {} /out/nss/lib/ \; && \
    fixture_db="$(find /usr/local/cargo/git/checkouts -path '*/test-fixture/db/cert9.db' -print -quit)" && \
    test -n "${fixture_db}" && cp -a "$(dirname "${fixture_db}")/." /out/nss/test-db/

# Python is shared; capture and browser system packages stay in their own
# final targets.
FROM ${DEBIAN_IMAGE} AS lab-runtime
ENV DEBIAN_FRONTEND=noninteractive \
    UV_LINK_MODE=copy \
    UV_NO_CACHE=1 \
    UV_PROJECT_ENVIRONMENT=/opt/qcsd-venv \
    UV_PYTHON_DOWNLOADS=never \
    PATH=/opt/qcsd-venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates python3 tini && \
    rm -rf /var/lib/apt/lists/*
COPY --from=uv-bin /uv /uvx /usr/local/bin/
WORKDIR /opt/qcsd-lab
COPY pyproject.toml uv.lock README.md ./
COPY src/ ./src/
RUN uv lock --check && \
    uv sync --frozen --no-dev --no-editable && \
    install -m 0755 /opt/qcsd-venv/bin/qcsd-lab-internal /usr/local/bin/qcsd-lab-internal

FROM lab-runtime AS collection
RUN apt-get update && apt-get install -y --no-install-recommends \
    default-jre-headless ethtool git iproute2 time tshark util-linux wireshark-common && \
    rm -rf /var/lib/apt/lists/*
RUN uv lock --check && \
    uv sync --frozen --no-dev --no-editable --extra test --extra evaluation
COPY --from=neqo-builder /out/bin/ /usr/local/bin/
COPY --from=neqo-builder /out/nss/ /opt/nss/
COPY --from=neqo-code-gate /out/rust-code-gate/ \
    /usr/share/qcsd-lab/rust-code-gate/
COPY --from=osad-builder /out/usr/local/lib/qcsd/ /usr/local/lib/qcsd/
COPY --from=weka-builder /out/opt/qcsd/weka/ /opt/qcsd/weka/
COPY --from=source-metadata /source-metadata.json /usr/share/qcsd-lab/source.json
COPY --from=source-metadata /study-build-inputs.json \
    /usr/share/qcsd-lab/study-build-inputs.json
COPY --from=source-metadata /qualification-source-files.json /tmp/qualification-source-files.json
COPY --chmod=0755 docker/collection-entrypoint /usr/local/bin/
RUN python3 - <<'PY'
import hashlib
import importlib.util
import json
from pathlib import Path

domain = "qcsd-chaff-qualification-implementation-v1"
source_files = json.loads(Path("/tmp/qualification-source-files.json").read_text())
source = json.loads(Path("/usr/share/qcsd-lab/source.json").read_text())
package = Path(importlib.util.find_spec("qcsd_lab").submodule_search_locations[0])
installed_modules = {}
for source_path, source_sha256 in source_files.items():
    prefix = "src/qcsd_lab/"
    if not source_path.startswith(prefix):
        continue
    relative = source_path.removeprefix(prefix)
    installed = package / relative
    installed_sha256 = hashlib.sha256(installed.read_bytes()).hexdigest()
    if installed_sha256 != source_sha256:
        raise SystemExit(f"installed module differs from source: {source_path}")
    installed_modules[source_path] = {
        "path": installed.as_posix(),
        "sha256": installed_sha256,
    }
def file_receipt(path):
    value = Path(path)
    return {"path": path, "sha256": hashlib.sha256(value.read_bytes()).hexdigest()}
receipt = {
    "schema_version": 1,
    "artifact_type": "qcsd-chaff-qualification-implementation",
    "domain": domain,
    "source": source,
    "source_files": source_files,
    "installed_modules": installed_modules,
    "installed_entrypoint": file_receipt("/usr/local/bin/qcsd-lab-internal"),
    "neqo_qcsd_client": file_receipt("/usr/local/bin/neqo-qcsd-client"),
}
payload = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
receipt["sha256"] = hashlib.sha256(domain.encode() + b"\0" + payload).hexdigest()
Path("/usr/share/qcsd-lab/qualification-implementation.json").write_text(
    json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
Path("/tmp/qualification-source-files.json").unlink()
PY
ENV LD_LIBRARY_PATH=/opt/nss/lib \
    TEST_FIXTURE_DB=/opt/nss/test-db \
    QCSD_LAB_SOURCE_METADATA=/usr/share/qcsd-lab/source.json \
    NSS_VERSION=3.121 \
    NSPR_VERSION=4.38.2 \
    NSS_BUNDLE_SHA256=76b9a1364bc4522abc652c4d676498d5062f502f64e38b32e9e2c7a3fff530f1
LABEL org.opencontainers.image.title="neqo-qcsd-lab collection" \
      org.opencontainers.image.source="https://github.com/kaisequeira/neqo-qcsd-lab" \
      org.opencontainers.image.nss.version="3.121" \
      org.opencontainers.image.nspr.version="4.38.2"
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/collection-entrypoint"]

# The pinned author implementation is mounted read-only only into this
# network-isolated target.  It is never copied into the collection image.
FROM lab-runtime AS reference
RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf build-essential libssl-dev zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*
COPY --from=source-metadata /source-metadata.json /usr/share/qcsd-lab/source.json
ENV QCSD_LAB_SOURCE_METADATA=/usr/share/qcsd-lab/source.json
COPY tools/qcsd_csbuflo_author_harness.c \
    /usr/local/share/qcsd-lab/qcsd_csbuflo_author_harness.c
ENTRYPOINT ["qcsd-lab-internal"]

# Workload preparation is one public operation. This image contains both the
# browser discovery stack and the exact Neqo binary used for HTTP/3 preflight.
FROM collection AS prepare
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium fonts-liberation && \
    rm -rf /var/lib/apt/lists/*
RUN uv lock --check && \
    uv sync --frozen --no-dev --no-editable \
      --extra test --extra evaluation --extra discovery
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium
LABEL org.opencontainers.image.title="neqo-qcsd-lab prepare" \
      org.opencontainers.image.source="https://github.com/kaisequeira/neqo-qcsd-lab"
ENTRYPOINT ["/usr/bin/tini", "--", "qcsd-lab-internal"]
