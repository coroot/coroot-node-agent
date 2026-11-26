#!/usr/bin/env bash
# Boots the Node.js test VM of an architecture on a kernel. See README.md in this directory.
#
# Usage: kerneltest/nodejs/run.sh <amd64|arm64> [<kernel image>]
#   e.g. kerneltest/nodejs/run.sh amd64 ghcr.io/cilium/ci-kernels:6.1
#        NO_BUILD=1 kerneltest/nodejs/run.sh arm64 local/ci-kernels:5.14-el9
#
# <kernel image> has /boot/vmlinuz and, for distribution kernels, /lib/modules, as the images of cilium/ci-kernels
# and coroot/ci-kernels do. Without it the script only builds the root filesystem.
set -euo pipefail

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "usage: $0 <amd64|arm64> [<kernel image>]" >&2
    exit 2
fi
ARCH=$1
KERNEL=${2:-}
TIMEOUT=${TIMEOUT:-1800}
MEMORY=${MEMORY:-8G}
CPUS=${CPUS:-4}
CACHE=${CACHE:-$HOME/.cache/coroot-node-agent-nodetest}

case "$ARCH" in
    amd64) qemu=qemu-system-x86_64 machine="" console=ttyS0 ;;
    arm64) qemu=qemu-system-aarch64 machine="-M virt" console=ttyAMA0 ;;
    *) echo "unsupported architecture: $ARCH" >&2; exit 2 ;;
esac
case "$(uname -m)" in
    x86_64 | amd64) host_arch=amd64 ;;
    aarch64 | arm64) host_arch=arm64 ;;
    *) echo "unsupported host architecture: $(uname -m)" >&2; exit 2 ;;
esac
for tool in $qemu timeout; do
    command -v "$tool" >/dev/null || { echo "$tool is required, see README.md" >&2; exit 2; }
done

dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$dir/../.." && pwd)
rootfs=$CACHE/$ARCH

if [ "${NO_BUILD:-}" != 1 ]; then
    echo ">> building the $ARCH root filesystem"
    go_version=$(sed -n 's/^ARG GO_VERSION=//p' "$root/Dockerfile")
    docker build -q --platform "linux/$ARCH" --build-arg "GO_VERSION=$go_version" --target output \
        --output "type=local,dest=$rootfs" -f "$dir/Dockerfile" "$root" >/dev/null
fi
[ -n "$KERNEL" ] || exit 0
[ -f "$rootfs/rootfs.cpio.gz" ] || { echo "no root filesystem in $rootfs, run without NO_BUILD=1" >&2; exit 2; }

work=$(mktemp -d)
containers=""
vm=""
# shellcheck disable=SC2329 # called by the trap
cleanup() {
    # timeout passes the signal on to QEMU
    [ -z "$vm" ] || kill "$vm" 2>/dev/null
    # shellcheck disable=SC2086
    [ -z "$containers" ] || docker rm -f $containers >/dev/null 2>&1
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

echo ">> kernel $KERNEL ($ARCH)"
c=$(docker create --platform "linux/$ARCH" "$KERNEL" /none)
containers="$containers $c"
mkdir -p "$work/extra/kerneltest" "$work/extra/usr/lib/modules"
docker cp "$c:/boot/vmlinuz" "$work/vmlinuz"
# RHEL 7 ships the arm64 Image compressed with gzip. QEMU boots both, but the page size check below reads the
# header of an uncompressed Image.
if [ "$(od -An -tx1 -N2 "$work/vmlinuz" | tr -d ' \n')" = 1f8b ]; then
    gzip -dc <"$work/vmlinuz" >"$work/Image" && mv "$work/Image" "$work/vmlinuz"
fi
# Distribution kernels need modules, the upstream builds have everything built in. The root filesystem is
# Debian, where /lib is a link to /usr/lib.
docker cp "$c:/lib/modules/." "$work/extra/usr/lib/modules" 2>/dev/null || true
cp "$dir/init" "$work/extra/init"
cp "$rootfs/busybox" "$work/extra/kerneltest/busybox"
chmod 755 "$work/extra/init" "$work/extra/kerneltest/busybox"
# The archive is built in a container, so that its files belong to root.
tar -C "$work/extra" -c . | docker run --rm -i "--platform=linux/$host_arch" alpine:3.20 sh -c \
    'mkdir /r && tar -x -o -C /r && cd /r && find . | cpio -o -H newc 2>/dev/null | gzip -1' >"$work/extra.cpio.gz"
cat "$rootfs/rootfs.cpio.gz" "$work/extra.cpio.gz" >"$work/initramfs.gz"

# Apple silicon has no 64K pages, so HVF cannot run a kernel built for them, such as RHEL 7 and 8 on arm64, and the
# VM hangs without output. The page size is in bits 1-2 of the flags of an arm64 Image
# (Documentation/arch/arm64/booting.rst). A kernel whose header cannot be read is emulated.
hvf_pages() {
    [ "$(od -An -tx1 -j56 -N4 "$work/vmlinuz" | tr -d ' \n')" = 41524d64 ] &&
        [ $(($(od -An -tu1 -j24 -N1 "$work/vmlinuz") >> 1 & 3)) != 3 ]
}
if [ "$ARCH" = "$host_arch" ] && [ -w /dev/kvm ]; then
    accel="-enable-kvm -cpu host"
elif [ "$ARCH" = arm64 ] && [ "$host_arch" = arm64 ] && [ "$(uname -s)" = Darwin ] && hvf_pages; then
    accel="-accel hvf -cpu host"
else
    echo ">> no hardware acceleration for this VM, falling back to emulation (slow)"
    accel="-cpu max"
fi

echo ">> booting"
# timeout runs in its own process group, out of reach of the terminal's signals: the VM runs in the background, so
# that the traps run at once and stop it
# shellcheck disable=SC2086
(cd "$work" && exec timeout "$TIMEOUT" $qemu $machine $accel -m "$MEMORY" -smp "$CPUS" -nographic -no-reboot \
    -kernel vmlinuz -initrd initramfs.gz -append "console=$console panic=-1 quiet kerneltest.time=$(date +%s)" \
    </dev/null >console.log 2>&1) &
vm=$!
status=0
wait "$vm" || status=$?
vm=""

tr -d '\r' <"$work/console.log" | sed -n '/KERNELTEST kernel/,$p'
# the first verdict counts: the test script prints one and powers the VM off
case "$(tr -d '\r' <"$work/console.log" | grep -oE 'KERNELTEST (PASS|FAIL)' | head -n 1)" in
    "KERNELTEST PASS") exit 0 ;;
    "KERNELTEST FAIL") exit 1 ;;
esac
if [ "$status" = 124 ]; then
    echo "KERNELTEST REASON: the VM did not finish within $TIMEOUT seconds"
else
    echo "KERNELTEST REASON: the VM stopped without a verdict, QEMU exit status $status"
fi
if ! grep -q "KERNELTEST" "$work/console.log"; then
    echo ">> the VM produced no test output, console log follows"
    tr -d '\r' <"$work/console.log" | tail -n 50
fi
exit 1
