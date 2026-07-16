# syntax=docker/dockerfile:1.7
ARG RUST_IMAGE=docker.io/library/rust:1.90-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f
ARG DEBIAN_IMAGE=docker.io/library/debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

FROM ${RUST_IMAGE} AS neqo-builder
ARG TARGETARCH
ARG NSS_REVISION=66f18083cd45576abf05dd68558322f60246f622
ARG NSPR_REVISION=7acb8859be67e8c1811d0ee8dc8a51710c1f3f58
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates clang cmake git gyp libclang-dev libnspr4-dev llvm-dev \
    mercurial ninja-build perl pkg-config python3 && \
    rm -rf /var/lib/apt/lists/*
RUN mkdir -p /opt/mozilla && \
    hg clone -u "${NSS_REVISION}" https://hg.mozilla.org/projects/nss /opt/mozilla/nss && \
    hg clone -u "${NSPR_REVISION}" https://hg.mozilla.org/projects/nspr /opt/mozilla/nspr
ENV NSS_DIR=/opt/mozilla/nss
WORKDIR /src
COPY third_party/neqo-qcsd/ ./
# Release builds dynamically link the pinned NSS libraries on both supported
# architectures. The ARM64 GCM archive workaround applies to nss-rs's
# debug/static test links and is documented in docs/CAPTURE.md; injecting it
# here would incorrectly link it into this dynamic release build.
RUN cargo build --locked --release -p neqo-bin --features qcsd --lib && \
    NSS_PREBUILT=1 cargo build --locked --release -p neqo-bin --features qcsd \
      --bin neqo-qcsd-client --bin neqo-server && \
    mkdir -p /opt/nss/lib /opt/nss/test-db && \
    find /opt/mozilla/dist/Release/lib -name '*.so*' -type f -exec cp -L {} /opt/nss/lib/ \; && \
    fixture_db="$(find /usr/local/cargo/git/checkouts -path '*/test-fixture/db/cert9.db' -print -quit)" && \
    test -n "${fixture_db}" && cp -a "$(dirname "${fixture_db}")/." /opt/nss/test-db/

FROM ${DEBIAN_IMAGE} AS lab-base
ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl ethtool git iproute2 python3 python3-pip tini \
    tshark wireshark-common && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /opt/qcsd-lab
COPY pyproject.toml README.md ./
COPY src/ ./src/

FROM lab-base AS collection
RUN python3 -m pip install --break-system-packages '.[test]'
COPY --from=neqo-builder /src/target/release/neqo-qcsd-client /usr/local/bin/
COPY --from=neqo-builder /src/target/release/neqo-server /usr/local/bin/
COPY --from=neqo-builder /opt/nss /opt/nss
COPY --chmod=0755 containers/collection-entrypoint /usr/local/bin/
ENV LD_LIBRARY_PATH=/opt/nss/lib \
    TEST_FIXTURE_DB=/opt/nss/test-db \
    NSS_VERSION=3.121 \
    NSS_REVISION=66f18083cd45576abf05dd68558322f60246f622 \
    NSPR_VERSION=4.38.2 \
    NSPR_REVISION=7acb8859be67e8c1811d0ee8dc8a51710c1f3f58
LABEL org.opencontainers.image.title="neqo-qcsd-lab collection" \
      org.opencontainers.image.source="https://github.com/kaisequeira/neqo-qcsd-lab" \
      org.opencontainers.image.nss.version="3.121" \
      org.opencontainers.image.nspr.version="4.38.2"
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/collection-entrypoint"]

FROM lab-base AS discovery
RUN apt-get update && apt-get install -y --no-install-recommends chromium fonts-liberation && \
    rm -rf /var/lib/apt/lists/* && \
    python3 -m pip install --break-system-packages '.[discovery,test]'
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium
LABEL org.opencontainers.image.title="neqo-qcsd-lab discovery" \
      org.opencontainers.image.source="https://github.com/kaisequeira/neqo-qcsd-lab"
ENTRYPOINT ["/usr/bin/tini", "--", "qcsd-lab-internal"]
