#
# Copyright 2023, Colias Group, LLC
#
# SPDX-License-Identifier: BSD-2-Clause
#

FROM debian:bookworm

RUN apt-get update -q && \
    apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    rsync \
    # for seL4
    gcc-aarch64-linux-gnu \
    python3-dev \
    python3-venv \
    cmake \
    ninja-build \
    device-tree-compiler \
    libxml2-utils \
    gcc-riscv64-unknown-elf \
    # for bindgen
    libclang-dev \
    # for test scripts
    python3-pexpect \
    python3-requests \
    # for book
    libssl-dev \
    pkg-config \
    linkchecker \
    # for hacking
    bash-completion \
    man \
    less \
    sudo \
    && \
    # install these without --no-install-recommends
    apt-get install -y \
    qemu-system-arm \
    qemu-system-misc \
    && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

ARG RUSTUP_CHANNEL

RUN curl -sSf https://sh.rustup.rs | \
    bash -s -- -y --no-modify-path \
    --default-toolchain $RUSTUP_CHANNEL \
    --component rustfmt \
    --component rust-src

ENV PATH=/root/.cargo/bin:$PATH

ENV SEL4_INSTALL_DIR=/opt/seL4

RUN set -eux; \
    git clone \
    https://github.com/seL4/seL4.git \
    --config advice.detachedHead=false; \
    cd seL4; \
    git checkout cd6d3b8c25d49be2b100b0608cf0613483a6fffa;

RUN set -eux; \
    cd seL4; \
    python3 -m venv pyenv; \
    export PATH=$(realpath ./pyenv/bin):$PATH; \
    pip install tools/python-deps; \
    cmake \
    -DCMAKE_INSTALL_PREFIX=$SEL4_INSTALL_DIR \
    -DKernelPlatform=qemu-arm-virt \
    # TODO further develop kernel loader to make KernelArmHypervisorSupport=ON unecessary
    -DKernelArmHypervisorSupport=ON \
    -DKernelVerificationBuild=OFF \
    -DARM_CPU=cortex-a53 \
    -G Ninja \
    -S . \
    -B build; \
    ninja -C build all; \
    ninja -C build install; \
    rm -rf $(pwd);

RUN set -eux; \
    url="https://github.com/seL4/rust-sel4"; \
    rev="d2bc5cf71c5455f85898a4768e9dcbaea39e1a7e"; \
    common_args="--git $url --rev $rev --root $SEL4_INSTALL_DIR"; \
    CC_aarch64_unknown_none=aarch64-linux-gnu-gcc \
    SEL4_PREFIX=$SEL4_INSTALL_DIR \
    cargo install \
    -Z build-std=core,compiler_builtins \
    -Z build-std-features=compiler-builtins-mem \
    --target aarch64-unknown-none \
    $common_args \
    sel4-kernel-loader; \
    cargo install \
    $common_args \
    sel4-kernel-loader-add-payload;

RUN mkdir -p /opt/microkit/sdk \
    && curl -L https://github.com/seL4/microkit/releases/download/2.0.1/microkit-sdk-2.0.1-linux-x86-64.tar.gz \
    | tar -xzf - -C /opt/microkit/sdk --strip-components=1


ENV MICROKIT_SDK=/opt/microkit/sdk

ARG UID
ARG GID

RUN set -eux; \
    if [ $UID -eq 0 ]; then \
    if [ $GID -ne 0 ]; then \
    echo "error: \$UID == 0 but \$GID != 0" >&2; \
    exit 1; \
    fi; \
    else \
    if getent passwd $UID; then \
    echo "error: \$UID $UID already exists" >&2; \
    exit 1; \
    fi; \
    if ! getent group $GID; then \
    groupadd --gid $GID x; \
    fi; \
    useradd --uid $UID --gid $GID --groups sudo --create-home x; \
    fi;

RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER $UID

RUN set -eux; \
    if [ $UID -ne 0 ]; then \
    curl -sSf https://sh.rustup.rs | \
    bash -s -- -y --no-modify-path \
    --default-toolchain $RUSTUP_CHANNEL \
    --component rustfmt \
    --component rust-src; \
    fi;

ENV PATH=/home/x/.cargo/bin:$PATH

RUN cargo install mdbook@0.4.36

ENV SHELL=/bin/bash

# TODO HACK
RUN set -eu; \
    f=~/.gitconfig; \
    echo '[safe]' > $f; \
    echo 'directory = /work/code' >> $f;

WORKDIR /work
