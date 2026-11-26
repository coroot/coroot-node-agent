#!/usr/bin/env bash
# Builds the arm64 kernel images that the Node.js tests boot. See ../README.md.
#
# Usage: kerneltest/nodejs/kernels/build.sh [<tag>...]
#
# Without tags it builds every kernel in arm64.txt. The images are tagged $ARM64_KERNELS_REPO:<tag>,
# local/ci-kernels:<tag> by default.
set -euo pipefail

dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=${ARM64_KERNELS_REPO:-local/ci-kernels}
# The commit of coroot/ci-kernels that packages the distribution kernels.
coroot_ci_kernels=23e8d9840d2de07769eea47d14f40dc3d2d8081b

tags=("$@")
if [ ${#tags[@]} = 0 ]; then
    while read -r tag _; do
        tags+=("$tag")
    done < <(grep -v -e '^#' -e '^$' "$dir/arm64.txt")
fi

for tag in "${tags[@]}"; do
    spec=$(awk -v t="$tag" '$1 == t { sub(/^[^ ]+ +/, ""); print }' "$dir/arm64.txt")
    if [ -z "$spec" ]; then
        echo "unknown tag: $tag" >&2
        exit 1
    fi
    echo ">> $repo:$tag"
    case "$spec" in
        *://*)
            docker build -q --platform linux/arm64 --build-arg "PACKAGES=$spec" -t "$repo:$tag" \
                "https://github.com/coroot/ci-kernels.git#$coroot_ci_kernels" >/dev/null
            ;;
        *)
            read -r version debian <<<"$spec"
            docker build -q --platform linux/arm64 --build-arg "VERSION=$version" --build-arg "DEBIAN=${debian:-trixie}" -t "$repo:$tag" "$dir" >/dev/null
            ;;
    esac
done
