# syntax=docker/dockerfile:1.7
ARG RUST_IMAGE=docker.io/library/rust:1.90-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f
ARG DEBIAN_IMAGE=docker.io/library/debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

# Inspect the local parent checkout and submodule. This stage is also the
# source of the immutable provenance copied into both runtime images.
FROM ${DEBIAN_IMAGE} AS source-metadata
RUN apt-get update && apt-get install -y --no-install-recommends git && \
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
      > /source-metadata.json

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

# Release artifacts are built only from the local submodule working tree.
FROM neqo-toolchain AS neqo-builder
ARG TARGETARCH
WORKDIR /src
COPY neqo-qcsd/ ./
RUN --mount=type=cache,id=qcsd-cargo-registry-${TARGETARCH},target=/usr/local/cargo/registry \
    --mount=type=cache,id=qcsd-cargo-git-${TARGETARCH},target=/usr/local/cargo/git \
    --mount=type=cache,id=qcsd-cargo-target-${TARGETARCH},target=/src/target \
    cargo build --locked --release -p neqo-bin --features qcsd \
      --bin neqo-qcsd-client --bin neqo-server && \
    mkdir -p /out/bin /out/nss/lib /out/nss/test-db && \
    cp target/release/neqo-qcsd-client target/release/neqo-server /out/bin/ && \
    find /opt/mozilla/dist/Release/lib -name '*.so*' -type f -exec cp -L {} /out/nss/lib/ \; && \
    fixture_db="$(find /usr/local/cargo/git/checkouts -path '*/test-fixture/db/cert9.db' -print -quit)" && \
    test -n "${fixture_db}" && cp -a "$(dirname "${fixture_db}")/." /out/nss/test-db/

# Python is shared; capture and browser system packages stay in their own
# final targets.
FROM ${DEBIAN_IMAGE} AS lab-runtime
ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates python3 python3-pip tini && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /opt/qcsd-lab
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN python3 -m pip install --break-system-packages .

FROM lab-runtime AS collection
RUN apt-get update && apt-get install -y --no-install-recommends \
    ethtool tshark util-linux wireshark-common && \
    rm -rf /var/lib/apt/lists/* && \
    python3 -m pip install --break-system-packages '.[test]'
COPY --from=neqo-builder /out/bin/ /usr/local/bin/
COPY --from=neqo-builder /out/nss/ /opt/nss/
COPY --from=source-metadata /source-metadata.json /usr/share/qcsd-lab/source.json
COPY --chmod=0755 docker/collection-entrypoint /usr/local/bin/
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

# Workload preparation is one public operation. This image contains both the
# browser discovery stack and the exact Neqo binary used for HTTP/3 preflight.
FROM collection AS prepare
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium fonts-liberation && \
    rm -rf /var/lib/apt/lists/* && \
    python3 -m pip install --break-system-packages '.[discovery]'
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium
LABEL org.opencontainers.image.title="neqo-qcsd-lab prepare" \
      org.opencontainers.image.source="https://github.com/kaisequeira/neqo-qcsd-lab"
ENTRYPOINT ["/usr/bin/tini", "--", "qcsd-lab-internal"]
