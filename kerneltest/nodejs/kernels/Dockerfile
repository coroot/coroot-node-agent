# An upstream kernel for arm64 with the configuration of cilium/ci-kernels, the source of the upstream kernels
# in the CI matrix, plus config-arm64 from this directory. The image has the layout of ci-kernels: /boot/vmlinuz.
# Build it with build.sh.
ARG DEBIAN=trixie
FROM debian:${DEBIAN} AS build
ARG DEBIAN
# Debian 11 is served from snapshot.debian.org only, see the repository Dockerfile.
RUN if [ "$DEBIAN" = bullseye ]; then sed -i -e '/deb.debian.org/d' -e 's|^# deb |deb |' /etc/apt/sources.list; fi && \
    apt-get -o Acquire::Check-Valid-Until=false update && \
    apt-get install -y --no-install-recommends build-essential bc flex bison libelf-dev libssl-dev dwarves python3 cpio kmod curl ca-certificates xz-utils && \
    rm -rf /var/lib/apt/lists/*
ARG VERSION
RUN case $VERSION in \
        *-rc*) url=https://git.kernel.org/torvalds/t/linux-$VERSION.tar.gz ;; \
        *) url=https://cdn.kernel.org/pub/linux/kernel/v${VERSION%%.*}.x/linux-$VERSION.tar.xz ;; \
    esac && \
    curl -fsSL -o /linux.tar "$url" && mkdir /usr/src/linux && tar -xf /linux.tar -C /usr/src/linux --strip-components=1 && rm /linux.tar
WORKDIR /usr/src/linux
ARG CILIUM_CI_KERNELS=0e42a8a01052762e81bfc1850437337cadc77c35
ADD https://raw.githubusercontent.com/cilium/ci-kernels/${CILIUM_CI_KERNELS}/build/config /fragments/cilium-config
ADD https://raw.githubusercontent.com/cilium/ci-kernels/${CILIUM_CI_KERNELS}/build/config-arm64 /fragments/cilium-config-arm64
COPY config-arm64 /fragments/config-arm64
# Modules are not built, as in ci-kernels: whatever defconfig builds as a module is left out.
RUN make defconfig >/dev/null && \
    scripts/kconfig/merge_config.sh -m .config /fragments/cilium-config /fragments/cilium-config-arm64 /fragments/config-arm64 >/dev/null && \
    make olddefconfig >/dev/null && \
    for o in NF_CT_NETLINK BPF_SYSCALL KPROBES UPROBE_EVENTS FTRACE_SYSCALLS; do \
        grep -q "^CONFIG_$o=y" .config || { echo "CONFIG_$o is not set"; exit 1; }; \
    done
RUN make -j"$(nproc)" Image >/build.log 2>&1 || { tail -n 50 /build.log; exit 1; }
RUN mkdir -p /out/boot && cp arch/arm64/boot/Image /out/boot/vmlinuz && make -s kernelrelease >/out/boot/release

FROM scratch
COPY --from=build /out /
