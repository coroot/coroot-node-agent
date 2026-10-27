GO ?= go
GO_IMAGE ?= golang:1.25-bookworm
TESTDATA_REPO ?= https://github.com/coroot/pyroscope-ebpf-testdata.git

# Rebuilds pyrobpf/*_bpfel_*.{go,o} and python/perf_bpfel_*.{go,o} from bpf/.
# Runs in Docker so that the clang version does not depend on the host.
.PHONY: bpf-generate
bpf-generate:
	docker run --rm -v $(CURDIR)/..:/src -w /src -e GOFLAGS=-buildvcs=false $(GO_IMAGE) \
		sh -c 'apt-get update -qq >/dev/null && apt-get install -y -qq clang llvm >/dev/null && go generate ./profiling/pyrobpf ./profiling/python'

# Python, glibc and musl binaries used to generate the offset tables and by the tests.
.PHONY: testdata
testdata:
	test -d testdata || git clone --depth 1 $(TESTDATA_REPO) testdata

.PHONY: python-offsets
python-offsets: testdata
	echo "//go:build amd64 && linux" > python/python_offsets_gen_amd64.go
	$(GO) run ./cmd/python_dwarfdump $(shell find testdata/python-x64 -name 'libpy*.so*' | grep -v pyston) \
		$(shell find testdata/python-x64 | grep -E "/python3\\.[0-9]+") >> python/python_offsets_gen_amd64.go
	$(GO) fmt python/python_offsets_gen_amd64.go

	echo "//go:build arm64 && linux" > python/python_offsets_gen_arm64.go
	$(GO) run ./cmd/python_dwarfdump $(shell find testdata/python-arm64 -name 'libpy*.so*' | grep -v pyston) \
		$(shell find testdata/python-arm64 | grep -E "/python3\\.[0-9]+") >> python/python_offsets_gen_arm64.go
	$(GO) fmt python/python_offsets_gen_arm64.go

.PHONY: glibc-offsets
glibc-offsets: testdata
	echo "//go:build amd64 && linux" > python/glibc_offsets_gen_amd64.go
	$(GO) run ./cmd/glibc_dwarfdump $(shell find testdata/glibc-x64 -name libc.so.6) >> python/glibc_offsets_gen_amd64.go
	$(GO) fmt python/glibc_offsets_gen_amd64.go

	echo "//go:build arm64 && linux" > python/glibc_offsets_gen_arm64.go
	$(GO) run ./cmd/glibc_dwarfdump $(shell find testdata/glibc-arm64 -name libc.so.6) >> python/glibc_offsets_gen_arm64.go
	$(GO) fmt python/glibc_offsets_gen_arm64.go

.PHONY: musl-offsets
musl-offsets: testdata
	echo "//go:build amd64 && linux" > python/musl_offsets_gen_amd64.go
	$(GO) run ./cmd/musl_dwarfdump $(shell find testdata/alpine-amd64 -name ld-musl-x86_64.so.1.debug) >> python/musl_offsets_gen_amd64.go
	$(GO) fmt python/musl_offsets_gen_amd64.go

	echo "//go:build arm64 && linux" > python/musl_offsets_gen_arm64.go
	$(GO) run ./cmd/musl_dwarfdump $(shell find testdata/alpine-arm64 -name ld-musl-aarch64.so.1.debug) >> python/musl_offsets_gen_arm64.go
	$(GO) fmt python/musl_offsets_gen_arm64.go
