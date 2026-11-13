#!/usr/bin/env bash
# Boots the agent's container image on a given kernel in QEMU and checks that
# the agent starts and captures an HTTP request. See README.md in this directory.
#
# Usage: kerneltest/run.sh <agent-image> <kernel>
#   e.g. kerneltest/run.sh coroot-node-agent:test 5.4
#        kerneltest/run.sh coroot-node-agent:test ghcr.io/coroot/ci-kernels:4.18-el8
#
# <kernel> is a tag of ghcr.io/cilium/ci-kernels (upstream kernels) or a full reference of
# an image with the same layout: /boot/vmlinuz and, optionally, /lib/modules.
set -euo pipefail

if [ $# -ne 2 ]; then
    echo "usage: $0 <agent-image> <kernel>" >&2
    exit 2
fi
IMAGE=$1
KERNEL=$2
KERNELS_REPO=${KERNELS_REPO:-ghcr.io/cilium/ci-kernels}
HELPER_IMAGE=${HELPER_IMAGE:-alpine:3.20}
TIMEOUT=${TIMEOUT:-600}

dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

case "$KERNEL" in
    */*) kernel_image=$KERNEL ;;
    *) kernel_image=$KERNELS_REPO:$KERNEL ;;
esac
echo ">> kernel $kernel_image"
c=$(docker create --platform linux/amd64 "$kernel_image" /none)
docker cp "$c:/boot/vmlinuz" "$work/vmlinuz"
mkdir "$work/modules"
# Distribution kernels need modules, the upstream builds have everything built in.
docker cp "$c:/lib/modules/." "$work/modules" 2>/dev/null || true
docker rm "$c" >/dev/null

echo ">> initramfs from $IMAGE"
cp "$dir/init" "$work/init"
c=$(docker create "$IMAGE")
# The archive is built in a container to keep root ownership and to cope with read-only directories of the image.
docker export "$c" | docker run --rm -i -v "$work:/work" "$HELPER_IMAGE" sh -c '
    mkdir /rootfs && tar -x -C /rootfs && install -m 755 /work/init /rootfs/init &&
    apk add --no-cache -q busybox-static >/dev/null && install -D -m 755 /bin/busybox.static /rootfs/kerneltest/busybox &&
    mkdir -p /rootfs/lib/modules && cp -a /work/modules/. /rootfs/lib/modules/ &&
    cd /rootfs && find . | cpio -o -H newc 2>/dev/null | gzip -1 > /work/initramfs.gz'
docker rm "$c" >/dev/null

qemu_args="-m 4G -smp 2 -nographic -no-reboot -kernel /work/vmlinuz -initrd /work/initramfs.gz"
have_qemu=0
command -v qemu-system-x86_64 >/dev/null && have_qemu=1
# QEMU in a container runs as root, so it only needs the device to exist.
if [ -w /dev/kvm ] || { [ $have_qemu = 0 ] && [ -e /dev/kvm ]; }; then
    qemu_args="-enable-kvm -cpu host $qemu_args"
    kvm_device="--device /dev/kvm"
else
    echo ">> /dev/kvm is not available, falling back to emulation (slow)"
    qemu_args="-cpu max $qemu_args"
    kvm_device=""
fi

echo ">> booting"
set +e
if [ $have_qemu = 1 ]; then
    # shellcheck disable=SC2086
    timeout "$TIMEOUT" qemu-system-x86_64 ${qemu_args//\/work/$work} -append "console=ttyS0 panic=-1 quiet" </dev/null >"$work/console.log" 2>&1
else
    # shellcheck disable=SC2086
    docker run --rm $kvm_device -v "$work:/work" "$HELPER_IMAGE" sh -c "
        apk add --no-cache -q qemu-system-x86_64 >/dev/null &&
        timeout $TIMEOUT qemu-system-x86_64 $qemu_args -append 'console=ttyS0 panic=-1 quiet'" </dev/null >"$work/console.log" 2>&1
fi
set -e

tr -d '\r' <"$work/console.log" | sed -n '/KERNELTEST kernel/,$p'
if grep -q "KERNELTEST PASS" "$work/console.log"; then
    exit 0
fi
if ! grep -q "KERNELTEST" "$work/console.log"; then
    echo ">> the VM produced no test output, console log follows"
    tr -d '\r' <"$work/console.log" | tail -n 50
fi
exit 1
