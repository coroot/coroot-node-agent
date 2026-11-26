# The root filesystem of the Node.js test VM, as an initramfs archive. Build it with run.sh, from the repository
# root as the context.
#
# Every Node.js build gets its own root under /os, as a container image would, and runs there as a systemd
# service with RootDirectory=. The roots cover the ways Node.js links OpenSSL (into the executable, or a shared
# libssl.so used by node or by libnode.so), glibc and musl, and the Node.js major versions 18 to 24.

# The agent and the addon are cross-compiled: Go crashes under user-mode QEMU, so a foreign-architecture
# image cannot be built by running the compiler under emulation.
FROM node:22-bookworm-slim AS node-headers

FROM --platform=$BUILDPLATFORM debian:bullseye AS builder
ARG TARGETARCH
ARG BUILDARCH
# Debian 11 is served from snapshot.debian.org only, see the repository Dockerfile.
RUN sed -i -e '/deb.debian.org/d' -e 's|^# deb |deb |' /etc/apt/sources.list && \
    dpkg --add-architecture $TARGETARCH && \
    apt-get -o Acquire::Check-Valid-Until=false update && \
    case $TARGETARCH in \
        $BUILDARCH) cc=gcc ;; \
        amd64) cc=gcc-x86-64-linux-gnu ;; \
        arm64) cc=gcc-aarch64-linux-gnu ;; \
    esac && \
    apt-get install -y curl build-essential pkg-config openssl $cc libsystemd-dev:$TARGETARCH
ARG GO_VERSION
RUN curl -fsSL https://go.dev/dl/go${GO_VERSION}.linux-${BUILDARCH}.tar.gz -o go.tar.gz && \
    tar -C /usr/local -xzf go.tar.gz && rm go.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"
WORKDIR /tmp/src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=node-headers /usr/local/include/node /node-include
RUN case $TARGETARCH in \
        $BUILDARCH) cc=gcc ;; \
        amd64) cc=x86_64-linux-gnu-gcc ;; \
        arm64) cc=aarch64-linux-gnu-gcc ;; \
    esac && \
    CGO_ENABLED=1 GOARCH=$TARGETARCH CC=$cc PKG_CONFIG_PATH=/usr/lib/$($cc -dumpmachine)/pkgconfig \
        go build -mod=readonly -ldflags "-extldflags='-Wl,-z,lazy' -X 'github.com/coroot/coroot-node-agent/flags.Version=nodetest'" -o /out/coroot-node-agent . && \
    mkdir /out/app && cp kerneltest/nodejs/app/*.js /out/app/ && \
    $cc -shared -fPIC -O2 -I/node-include -o /out/app/addon.node kerneltest/nodejs/app/addon.c && \
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout /out/app/key.pem -out /out/app/cert.pem -days 3650 -subj /CN=nodetest 2>/dev/null

# The official builds: OpenSSL is linked into the node executable.
FROM node:18-bookworm-slim AS official-18
FROM node:20-bookworm-slim AS official-20
FROM node:22-bookworm-slim AS official-22
FROM node:24-bookworm-slim AS official-24
FROM node:22-alpine AS official-22-alpine

# The distribution builds: node or libnode.so uses the distribution's shared libssl.so.
FROM debian:bookworm-slim AS debian-12
RUN apt-get update && apt-get install -y --no-install-recommends nodejs && rm -rf /var/lib/apt/lists/*
FROM ubuntu:24.04 AS ubuntu-24.04
RUN apt-get update && apt-get install -y --no-install-recommends nodejs && rm -rf /var/lib/apt/lists/*
FROM alpine:3.20 AS alpine-3.20
RUN apk add --no-cache nodejs
FROM registry.access.redhat.com/ubi9/nodejs-22-minimal AS ubi-9

FROM debian:bookworm-slim AS rootfs
RUN apt-get update && \
    apt-get install -y --no-install-recommends systemd python3-minimal iproute2 curl && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/coroot-node-agent /usr/bin/coroot-node-agent
COPY --from=official-18 / /os/official-18/
COPY --from=official-20 / /os/official-20/
COPY --from=official-22 / /os/official-22/
COPY --from=official-24 / /os/official-24/
COPY --from=official-22-alpine / /os/official-22-alpine/
COPY --from=debian-12 / /os/debian-12/
COPY --from=ubuntu-24.04 / /os/ubuntu-24.04/
COPY --from=alpine-3.20 / /os/alpine-3.20/
COPY --from=ubi-9 / /os/ubi-9/
COPY --from=builder /out/app /app
RUN for root in /os/*; do mkdir -p "$root/nodetest" && cp /app/* "$root/nodetest/"; done && rm -rf /app
# The VM unpacks the archive into a tmpfs, which the kernel limits to half of the memory. A kernel with 64K pages
# (RHEL 8 on arm64) gives each file at least 64K, so the file count matters as much as the size: npm, headers,
# documentation, time zones and package databases are most of the files and the test runs none of them.
RUN for root in / /os/*; do \
        cd "$root" && rm -rf usr/local/lib/node_modules usr/lib/node_modules usr/local/include usr/include \
            usr/lib/.build-id usr/share/doc usr/share/man usr/share/locale usr/share/zoneinfo usr/share/perl5 \
            usr/share/bash-completion usr/share/licenses var/lib/dpkg var/lib/rpm; \
    done

# The archive is built here once per architecture. run.sh appends a small archive per kernel with its modules
# and the test script, because the kernel unpacks concatenated archives in order.
FROM --platform=$BUILDPLATFORM alpine:3.20 AS archive
RUN apk add --no-cache cpio
COPY --from=rootfs / /rootfs/
RUN cd /rootfs && find . | cpio -o -H newc 2>/dev/null | gzip -1 >/rootfs.cpio.gz

# BusyBox runs in the VM, so it has the VM's architecture.
FROM alpine:3.20 AS busybox
RUN apk add --no-cache busybox-static

FROM scratch AS output
COPY --from=archive /rootfs.cpio.gz /
COPY --from=busybox /bin/busybox.static /busybox
