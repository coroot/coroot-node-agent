# profiling

Continuous profiling for coroot-node-agent.

`profiling.go`, `goheap.go` and `prune.go` are the agent's own code: process
discovery, the collect and upload loop, the Go heap profiler and the
async-profiler integration for the JVM.

Everything else in this directory is the eBPF CPU profiler that was ported
from the `ebpf` module of [grafana/pyroscope](https://github.com/grafana/pyroscope)
(Apache License 2.0, see `LICENSE`). Upstream stopped developing that module in
March 2025. The code was taken from coroot/pyroscope at commit `758a0e72a`,
which already carried our fixes on top of upstream: perf map symbols, Go 1.26
pclntab, symbol bounds for stripped binaries and Python 3.14 offsets.

Compared to upstream, the port is trimmed to what the agent needs: targets are
a plain service name and container id resolved by the agent (no Alloy service
discovery or per-target options), logging goes through klog, the Alloy debug
info plumbing is gone, and the agent decides which processes are CPython
interpreters.

## Layout

| path | what |
|---|---|
| `ebpfspy/` | the profiling session: attaches the perf events and kprobes, reads the stack maps, symbolizes samples |
| `bpf/` | BPF C sources, the vendored libbpf and vmlinux headers |
| `pyrobpf/` | bpf2go output for `bpf/profile.bpf.c` (native frame-pointer unwinder) |
| `python/` | bpf2go output for `bpf/pyperf.bpf.c` and the CPython, glibc and musl struct offsets per version |
| `symtab/` | ELF, Go pclntab, kallsyms and perf map symbol tables with caches |
| `pprof/` | builds pprof profiles from the collected samples |
| `demangle/`, `cpuonline/` | helpers used by the session |
| `dwarfdump/`, `cmd/*_dwarfdump` | generators for the Python, glibc and musl offset tables |

## Regenerating the BPF objects

`pyrobpf/*_bpfel_*.{go,o}` and `python/perf_bpfel_*.{go,o}` are committed.
After changing anything under `bpf/`, run:

```
make -C profiling bpf-generate
```

It runs `go generate` for both packages inside a Docker container with clang.
The `go:generate` directives pin bpf2go to cilium/ebpf v0.12.3. That is the
generation of bpf2go that produced the committed files: with Debian clang 14 it
reproduces `pyrobpf/*.o` byte for byte. Releases from v0.13 on name the outputs
differently (`profile_x86_bpfel.o` instead of `profile_bpfel_x86.o`) and from
v0.17 on reject `-type global_config_t` because they emit the type on their
own, so bumping the pin means regenerating and renaming the committed files
in the same change.

## Offset tables and test fixtures

No binary fixtures are kept in this repository. The Python, glibc and musl
binaries that the offset tables under `python/` are generated from, and the ELF
fixtures the `symtab` tests use (`elf/`, with the Dockerfile that builds them),
live in https://github.com/coroot/pyroscope-ebpf-testdata (about 3.4 GB). It is
not a submodule any more. Clone it into `profiling/testdata` with:

```
make -C profiling testdata
```

Then `make -C profiling python-offsets`, `glibc-offsets` or `musl-offsets`
rewrites the corresponding tables. Add the new interpreter or libc build to the
fixtures repository first.

Tests that need those fixtures skip when `profiling/testdata` is absent.
`ebpfspy.TestEBPFPythonProfiler` loads BPF programs and runs Docker containers,
so it needs root on a Linux host and only runs when `VM=1` is set, like the
tracer tests.
