#!/usr/bin/env bash
# Runs the Node.js test on every kernel of the CI matrix (.github/workflows/kernels.yml), on amd64 and arm64.
# See README.md in this directory.
#
# Usage: kerneltest/nodejs/matrix.sh [amd64] [arm64]
#
# JOBS                VMs to run at once (default 2)
# OUT                 directory for the console logs (default a new temporary directory)
# ARM64_KERNELS_REPO  repository of the arm64 kernels that kernels/build.sh builds (default local/ci-kernels)
set -euo pipefail

dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$dir/../.." && pwd)
JOBS=${JOBS:-2}
OUT=${OUT:-$(mktemp -d)}
mkdir -p "$OUT"
archs=("$@")
[ ${#archs[@]} -gt 0 ] || archs=(amd64 arm64)

# the runs are in this process group: stop their VMs too
trap 'trap - INT TERM; kill 0' INT TERM

kernels=$(awk "/^ *kernel:\$/ {f = 1; next} f && /^ *- / {sub(/^ *- */, \"\"); gsub(/'/, \"\"); print; next} f {exit}" "$root/.github/workflows/kernels.yml")

# kernel_ref <arch> <tag> prints the kernel image: for amd64 the one the Kernels workflow boots, for arm64 the one
# that kernels/build.sh builds, because neither cilium/ci-kernels nor coroot/ci-kernels publishes all of them.
kernel_ref() {
    if [ "$1" = arm64 ]; then
        echo "${ARM64_KERNELS_REPO:-local/ci-kernels}:$2"
        return
    fi
    case "$2" in
        *-*) echo "ghcr.io/coroot/ci-kernels:$2" ;;
        *) echo "ghcr.io/cilium/ci-kernels:$2" ;;
    esac
}

for arch in "${archs[@]}"; do
    rm -f "$OUT/$arch"-*.result "$OUT/$arch"-*.log "$OUT/$arch"-*.pull
    "$dir/run.sh" "$arch"
    runnable=()
    for tag in $kernels; do
        ref=$(kernel_ref "$arch" "$tag")
        if ! c=$(docker create --platform "linux/$arch" "$ref" /none 2>"$OUT/$arch-$tag.pull"); then
            echo "FAIL no $arch kernel image $ref: $(tail -n 1 "$OUT/$arch-$tag.pull")" >"$OUT/$arch-$tag.result"
            continue
        fi
        docker rm "$c" >/dev/null
        runnable+=("$ref")
    done
    if [ ${#runnable[@]} = 0 ]; then
        continue
    fi
    echo ">> running ${#runnable[@]} $arch VMs, $JOBS at a time, logs in $OUT"
    # The runs of one architecture go in parallel. The architectures go one after another, because pulling
    # the kernel of one architecture replaces the local image of the same tag for the other.
    # xargs stops starting runs when one is killed by a signal, so its status is ignored: a kernel without a
    # result file fails below.
    # shellcheck disable=SC2016
    printf '%s\n' "${runnable[@]}" | xargs -P "$JOBS" -I{} sh -c '
        tag=${2##*:}
        if NO_BUILD=1 "$1" "$3" "$2" >"$4/$3-$tag.log" 2>&1; then r=PASS; else r=FAIL; fi
        echo "$r $(grep -h "^KERNELTEST REASON" "$4/$3-$tag.log" | sed "s/^KERNELTEST REASON: //")" >"$4/$3-$tag.result"
        echo "$3 $tag $r"' _ "$dir/run.sh" {} "$arch" "$OUT" || true
done

echo
failed=0
for arch in "${archs[@]}"; do
    for tag in $kernels; do
        result=FAIL reason="the run did not finish"
        [ ! -f "$OUT/$arch-$tag.result" ] || read -r result reason <"$OUT/$arch-$tag.result"
        # The Kernels workflow does not block on a release candidate either.
        if [ "$result" = FAIL ] && [ "$tag" = mainline ]; then
            result="FAIL (allowed)"
        elif [ "$result" = FAIL ]; then
            failed=1
        fi
        printf '%-6s %-18s %-15s %s\n' "$arch" "$tag" "$result" "$reason"
    done
done
echo "logs: $OUT"
exit $failed
