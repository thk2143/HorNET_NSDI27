# E1 — correctness and semantic coverage

Does hornet give the same answer the Linux kernel does? Three suites ask that at
different granularities, and they differ in where the expected answer comes
from.

| Suite | What it asks | Expected answer from |
|---|---|---|
| `conformance` | instruction semantics | 305 of bpf_conformance's ISA tests, whose r0 the kernel agrees with |
| `cases` | helper and map modeling, the XDP memory model, CFG state merging, read-after-write, pipelines | the kernel (`BPF_PROG_TEST_RUN`), recorded once, plus hand-derived specs |
| `corpus` | real programs and their specs | a recorded verdict baseline (regression check) |

Each suite compares per-check status against a recorded baseline, so a status
that changes is a failure until it is re-recorded.

## The tests

359 tests in all: 305 from bpf_conformance and 54 written for this evaluation.
Every test checks the return value `r0` and, where the test observes them, the
output packet and the map state, through the ordinary verification pipeline.

**Instruction-level semantics — 305 tests.** bpf_conformance states, per test,
a bytecode program, its initial registers and memory, and the return value the
ISA prescribes. Each test asks two questions: that an execution returning that
value exists, and that no execution returns a different one. Of the suite's 313
tests, eight are excluded because they use constructs outside the prototype's
scope — BPF-to-BPF and indirect calls (`call_local`, `callx`,
`rfc9669_call_local`), atomic compare-and-exchange (`lock_cmpxchg*`,
`rfc9669_lock_cmpxchg*`) and an unbounded loop (`prime`). The remaining 305 all
pass, covering the arithmetic, bitwise, branch and memory-access semantics.

**Extended NF semantics — 54 tests.** Within the prototype's scope of eight map
types and 22 helper functions, these small XDP programs broaden the coverage to
operation outcomes, state changes and their interaction. Map and helper tests
exercise lookups, atomic updates, packet adjustments and outcomes that depend
on flags or capacity; tail-call tests examine a callee's packet and map
accesses, including after a caller-side head adjustment; memory tests cover
packet bounds, large offsets and global data; state-merging and read/write
tests check branch-dependent references, access ordering and the visibility of
a write to a later read; and three small NFs combine these in ARP filtering,
VLAN stripping and flow counting with redirection. The expected outcome of each
test is what Linux produced for the same input and initial state, recorded once
with `BPF_PROG_TEST_RUN`, plus specifications derived by hand from the kernel's
helper code. All 250 checks pass. [`cases/README.md`](cases/README.md) lists
every test and what it checks.

```bash
venv/bin/python benchmark/e1-correctness/run.py            # all three suites
venv/bin/python benchmark/e1-correctness/run.py cases      # one of them
venv/bin/python benchmark/e1-correctness/run.py cases --filter map_hash_lookup
```

## Contents

```
run.py         the suite runner
conformance.py the conformance suite
casesuite.py   the cases suite; casefiles.py reads cases/
cases/         one directory per test program: concrete runs and hand specs
objs/          the test programs, compiled
oracle/        kernel.json, the recorded kernel answers, and the runner that
               recorded them (needs root and a C compiler to re-record)
conformance/   the hornet plugin bpf_conformance drives
```

The cases and corpus suites read recorded answers and need no privileges. The
`conformance` suite additionally needs the bpf_conformance runner:
`conformance/build.sh` clones and builds it (network, cmake).
