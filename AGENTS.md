# Agent Instructions

> **Context for this fork.** This branch of `coroot-node-agent` adds
> Windows support to a codebase that has been Linux-only since
> inception. The cardinal rule of the port (next section) shapes
> almost every other rule in this document: **the existing Linux code
> is kept unchanged.** Windows support is added through build-tagged
> sibling files and, where the underlying technology can't be shared,
> through parallel packages.
>
> Upstream contribution rules live in [`CONTRIBUTING.md`](CONTRIBUTING.md).
> This file (`AGENTS.md`) covers the fork-internal, day-to-day
> operating rules: build-tag discipline, the plans → beads → code
> workflow, doc sync, and the pre-commit sanity gates.

## Build-tag discipline (the cardinal rule of this branch)

This is the rule everything else hinges on.

1. **Do not edit existing Linux source to add Windows logic.** Linux
   files stay byte-identical wherever possible. If an existing file
   uses Linux-only packages (`golang.org/x/sys/unix`, `cilium/ebpf`,
   `vishvananda/netlink`, `/proc` reads, etc.) and currently lacks a
   build tag, add one as a single header line (`//go:build linux`)
   or rename the file to use the `_linux.go` suffix. That mechanical
   gating is allowed; functional changes to Linux files are not.

2. **Windows logic lives in sibling files.** For every Linux file
   that needs a Windows counterpart, add `foo_windows.go` (or
   `foo_<subsys>_windows.go`) exposing the same exported Go API.
   Tests follow the same pattern: `foo_windows_test.go`,
   `foo_linux_test.go`.

3. **`ebpftracer/` stays Linux-only.** Its C sources, `cilium/ebpf`
   dependency, BTF assumptions, and perf-map plumbing are too deeply
   Linux-coupled to share. Windows tracing lives in parallel
   packages:
   - **`ebpfwin/`** — Microsoft's eBPF-for-Windows port, used where
     it covers the surface we need.
   - **`etwtracer/`** — Event Tracing for Windows, used as the
     fallback where eBPF-for-Windows doesn't reach.
   Both packages satisfy the same constructor signature that
   `main.go` consumes today, switched in by build tag.

4. **Every commit must compile under both `GOOS`s.** See the
   sanity-check section below; this is enforced as a pre-commit
   expectation, not a CI-only check.

5. **No `runtime.GOOS == "windows"` branching inside shared files.**
   If a function needs platform-specific behavior, split it across
   `_linux.go` / `_windows.go` siblings. Runtime OS checks defeat
   the point of the build-tag split (they put Windows code in the
   Linux binary and vice versa) and are forbidden.

## Workflow: plans → beads → code → plan-complete

All non-trivial work on this branch follows this loop.

1. **Update the plan doc.** Edit (or create) the relevant
   `plans/*.md` to capture the design. The master plan for this
   branch is `plans/windows-port-plan.md`; sub-plans (e.g.
   `plans/etw-tracer-plan.md`, `plans/container-discovery-windows-plan.md`)
   may be split out as scope grows.
   The plan **MUST include an explicit `## Acceptance Criteria`
   section** — a testable, enumerated definition of what "this
   plan is complete" means. If you can't write that section, the
   plan isn't ready and you should not create beads against it.

2. **Generate beads from the plan.** Break the plan into `bd create`
   issues. Every issue **MUST reference its plan doc** in the
   description (path + section, e.g.
   `Plan: plans/windows-port-plan.md §3 Build-tag layout`).
   Use `--acceptance="..."` on the bead to mirror the relevant
   acceptance criterion from the plan.

3. **Agents claim and execute.** Standard
   `bd ready` → `bd update --claim` → implement → `bd close` cycle.
   Code commits update the plan doc in the same commit when
   behavior shifts.

4. **Close the plan when criteria are met.** Once every bead tied
   to a plan is closed AND every item in the plan's Acceptance
   Criteria is demonstrably satisfied (tests pass, behavior
   verified), update the plan doc to mark it complete (status
   header or a `Status: Complete` line at the top). A plan is **not**
   complete just because all its beads closed — the acceptance
   criteria are the gate.

### Acceptance criteria — required shape

Every plan doc needs a section like:

```markdown
## Acceptance Criteria

- [ ] CRIT-1: <testable claim, e.g. "`GOOS=windows go build ./...`
      and `GOOS=linux go build ./...` both succeed from a clean
      checkout — covered by the `crossbuild-check` Makefile target
      added in this plan.">
- [ ] CRIT-2: ...
```

Each item must be testable (a passing test, a CLI invocation with
expected output, a manual procedure with a clear pass/fail). Vague
criteria ("works well", "is robust") do not count.

### Beads → plan linkage — required shape

When creating a bead, use a heredoc for the description so the
full junior-developer-grade context (next section) fits comfortably:

```bash
bd create \
  --title="Split main.go uname/machineID/systemUUID into main_linux.go and main_windows.go" \
  --description="$(cat <<'EOF'
Plan: plans/windows-port-plan.md §5 (per-package map row for main.go) and §6 M1 (Node-level metrics on Windows).

WHAT TO DO
The current main.go contains three Linux-only helpers and one Linux-only check that prevent the program from compiling under GOOS=windows:
- uname()              — reads /proc/1/ns/uts and calls golang.org/x/sys/unix.Setns
- machineID()          — reads /etc/machine-id and similar Linux paths
- systemUUID()         — reads /sys/devices/virtual/dmi/id/product_uuid
- kernel-version gate  — exits if the running kernel is older than 4.16

Move all four into a new file main_linux.go. Keep the exported names and signatures byte-identical so the rest of main.go compiles unchanged. Then create main_windows.go with Windows-native implementations:
- uname():       hostname from os.Hostname(); OS version from golang.org/x/sys/windows.RtlGetVersion
- machineID():   read HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid (REG_SZ)
- systemUUID():  read Win32_ComputerSystemProduct.UUID via WMI
- kernel-version gate: no-op on Windows (return immediately)

WHY
main.go uses the return values of these helpers as Prometheus label values (machine_id, system_uuid) and as user-visible log lines. Everything in main.go past the helpers is platform-agnostic orchestration (HTTP server, signal handling, registry wiring) — only the four helpers need splitting. The build-tag discipline rule forbids runtime GOOS checks, so this split is compile-time only.

HOW TO VERIFY
- GOOS=linux   go build ./... still succeeds.
- GOOS=windows go build ./... now succeeds (it does not before this bead).
- On Linux, before vs. after this change, the binary's "hostname:", "kernel version:", and "machine-id:" startup log lines emit identical values for the same host.
- On a Windows host, the binary starts, logs a non-empty hostname and machine-id, and serves /metrics on the configured port.

EDGE CASES AND PITFALLS
- DO NOT modify the bodies of the four Linux helpers. The Linux-side diff for this bead is move-only — file rename to main_linux.go plus any import adjustments that fall out of the move. AGENTS.md §"Build-tag discipline" rule 1.
- machineID() on Windows MUST return a real value. main.go wraps it into a Prometheus label; an empty string would corrupt metric series across restarts.
- systemUUID() via WMI is the most code-heavy of the three. If full WMI integration is out of scope for this bead, returning an empty string is acceptable as a temporary stub — but you MUST file a discovered-from bead capturing the gap and note it in this bead's --notes before closing.
- No runtime.GOOS == "windows" branching anywhere. Only build-tag separation. AGENTS.md §"Build-tag discipline" rule 5.

PROJECT-SPECIFIC TERMINOLOGY
- "Build-tag discipline": the cardinal rule of this branch — Linux code stays unchanged; Windows logic lives in _windows.go sibling files (or parallel packages for ebpftracer). Full statement in AGENTS.md §"Build-tag discipline".
- "M1": the second milestone in plans/windows-port-plan.md §6, which covers node-level metrics on Windows. main.go must be cross-buildable before any other M1 work can ship.
EOF
)" \
  --acceptance="CRIT-1 (GOOS=windows go build ./... succeeds from a clean checkout) AND CRIT-3 (the Linux-side diff is move-only — no functional change to the bodies of uname, machineID, systemUUID, or the kernel-version gate)." \
  --type=feature --priority=2
```

The `Plan:` line in the description is mandatory. The body must
satisfy the standalone-completeness rule in the next section.

### Beads must stand alone — required completeness

**Every bead MUST be written for a naive but competent junior
developer.** Assume that developer can write the language, run the
standard toolchain, and read anything checked into the repo —
`AGENTS.md`, `README.md`, the `Makefile`, the source tree. Do **not**
assume they have read the plan doc, prior beads, or any conversation
that led to this bead being filed. The bead must remove all ambiguity
about scope and required work: if a competent reader could plausibly
interpret the description two different ways, the bead is not ready.

The `--description="..."` must contain enough context that such a
developer could execute the task end-to-end **without consulting a
senior developer, the plan doc, other beads, or any out-of-band
knowledge**. The mandatory `Plan: plans/<doc>.md §N` reference is for
*traceability* (where did this work originate), not *delegation* (go
read the plan to figure out what to do).

A junior developer reading the bead in isolation must already know:

- **What to do** — concrete files, packages, functions, or commands
  to create or modify. Name them.
- **Why** — the user-visible behavior, constraint, or design rule
  this serves. One or two sentences.
- **How to verify** — the test, command, or observable result that
  proves the work is done. This is reinforced by the mandatory
  `--acceptance="..."` flag but should also appear in the
  description in everyday terms.
- **Edge cases and pitfalls** — non-obvious constraints. Examples
  on this branch: "do not modify the existing Linux file beyond
  adding the `//go:build linux` header"; "preserve the exact
  exported function signature so the Linux caller compiles
  unchanged"; "the Windows stub must compile under `GOOS=windows`
  but is allowed to return `errors.New("not implemented on
  windows")` at runtime."
- **Project-specific terminology** — if the bead uses a term that
  only makes sense in context (e.g., "the M0 scaffolding", "the
  parallel-package pattern", "the dispatcher in §4"), explain it
  inline or paraphrase the relevant plan passage. Do not assume
  the reader will follow the `Plan:` link.

If you cannot write a description at that level of completeness,
the bead is not ready to file. Either the underlying plan section
is too thin (fix the plan first), or the work needs to be split
into smaller beads that *are* individually self-explanatory.

This rule applies equally to follow-up beads created via
`discovered-from` linkage — a bead filed mid-implementation must
still stand alone, because whoever picks it up next won't have
the discovering session's context.

### Scope a bead to one logical unit of work

A bead covers **one** subsection of the system, not a mixed bag.
Examples of correctly-scoped units:

- one page's UI update
- one API endpoint (or one cohesive set of changes to one endpoint)
- one DB migration
- one file's build-tag split
- one parallel-package implementation (e.g. `etwtracer/`)

If a bead touches two unrelated subsystems, requires two independent
acceptance criteria, or has a description that reads "...and then
also...", it should be split. Scope is bounded by the work, not by a
line count — a single split that genuinely needs five pitfalls
documented is still one bead.

## Documentation must match code

**Every commit that changes user-visible behavior must update the
user docs in the same commit.** This is a hard rule.

User-visible surfaces that trigger doc updates:

- CLI flags (added, removed, renamed, default changed)
- Go build tags / build matrix (new `GOOS` or `GOARCH` supported or dropped)
- Binary names, container image tags, port numbers
- Build commands (`make`, `go build` invocations, packaging scripts)
- System dependencies (new libraries, kernel versions, Windows SDK requirements)
- Platform support (new OS/arch added or dropped — this whole branch is the canonical example)
- Container / deployment manifests (`manifests/*.yaml`, Dockerfiles)
- Runtime requirements (capabilities, privileged mode, registry access)
- Metric names and labels (`container_*`, `node_*`) — these are a public API for downstream Coroot

### Design docs are living specifications

`plans/*.md` files are **not** "internal notes that can lag behind."
They are the design source of truth that drives implementation. For
work that goes through the plans → beads → code loop, the relevant
plan doc must be updated **before** or **alongside** the code change.

For bug fixes and refactors that don't shift the design, the plan
doc may stay unchanged.

### Documentation layout

Project docs are split across two top-level directories. Pick the
right one when adding new docs.

- **`docs/`** — *user-facing documentation*. Setup guides,
  troubleshooting, operator how-tos, public metric references.
  Anything someone reading the project to learn how to **use** it
  would want.

- **`plans/`** — *design / implementation documentation*. Architecture
  notes, proposed-but-not-yet-shipped features, internal mechanism
  inventories. Anything someone reading the project to learn how it
  **works inside**, or how it **might work in the future**, would
  want.

Quick test: if the doc tells the reader "what to do with
coroot-node-agent," it goes in `docs/`. If it tells them "what
coroot-node-agent does inside, or what it should do," it goes in
`plans/`.

## Use Makefile targets

**ALWAYS use Makefile targets** when one exists for the task you're
performing. Before running a raw command, check if there's a `make`
target that does the same thing. Makefile targets encode
project-specific flags, sequences, and conventions that raw commands
may miss.

```bash
# Examples already in the Makefile:
make lint              # NOT: gofmt / go vet / goimports directly
make test              # NOT: go test ./... directly
```

If unsure whether a target exists, `grep` the Makefile or read it
top-to-bottom — it's short.

The Windows port will extend the Makefile with cross-build targets
(e.g. `build-linux`, `build-windows`, `crossbuild-check`); once
those land, use them rather than raw `GOOS=... go build`.

## Test coverage required

**ALL code changes MUST be covered by tests.** Do not submit code
without corresponding test coverage.

- New functions/methods require unit tests
- Bug fixes require a test that reproduces the bug
- Tests use Go's stdlib `testing` package and live alongside the
  code as `_test.go` files
- Platform-specific tests use the suffix-based build constraint:
  `foo_windows_test.go` is compiled only when `GOOS=windows`;
  `foo_linux_test.go` only when `GOOS=linux`
- Run `make test` before committing

## Sanity check before committing

Run from the repo root:

```bash
make lint                                  # gofmt / go vet / goimports / go mod tidy
make test                                  # go test ./... on the host GOOS
GOOS=linux   go build ./...                # Linux build still green
GOOS=windows go build ./...                # Windows build still green
```

The two cross-builds are mandatory on this branch — they're how we
enforce the build-tag discipline rule. If either fails, the commit
isn't ready.

If you changed a CLI flag or a metric name, grep the docs for the
old name before opening the PR.

## Non-interactive shell commands

**ALWAYS use non-interactive flags** with file operations to avoid
hanging on confirmation prompts.

Shell commands like `cp`, `mv`, and `rm` may be aliased to include
`-i` (interactive) mode on some systems, causing the agent to hang
indefinitely waiting for y/n input.

**Use these forms instead:**

```bash
# Force overwrite without prompting
cp -f source dest           # NOT: cp source dest
mv -f source dest           # NOT: mv source dest
rm -f file                  # NOT: rm file

# For recursive operations
rm -rf directory            # NOT: rm -r directory
cp -rf source dest          # NOT: cp -r source dest
```

**Other commands that may prompt:**

- `scp` / `ssh` — use `-o BatchMode=yes` to fail instead of prompting
- `apt-get` — use `-y` flag
- `brew` — use `HOMEBREW_NO_AUTO_UPDATE=1` env var

## Documentation diagrams

When adding diagrams to documentation, **always use Mermaid**
(```mermaid code blocks). Never use ASCII art diagrams.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->
