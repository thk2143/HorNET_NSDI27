# Hornet

Hornet is a static analyzer and verifier for compiled eBPF/XDP programs. It
decodes an ELF object, builds a control-flow graph, tracks symbolic state
through it, and decides a JSON specification about the program with an SMT
solver — answering with a verdict and, for a violation, a concrete
counterexample.

This repository is the paper artifact: the analyzer and the four experiments
that evaluate it.

## Layout

```
hornet/       the analyzer
  bpf/          ELF -> instructions -> basic-block CFG
  track/        CFG -> symbolic values, per-block state, recorded events
  verify/       a JSON spec + those records -> a verdict and a witness
  report/       the same records -> a description of the program
benchmark/    the four experiments (E1-E4)
example/      the open-source XDP programs the experiments analyze
SPEC.md       the specification format
```

## Setup

```bash
./setup.sh
```

Creates `venv/`, installs `requirements.txt` into it and runs a 250-check smoke
test against the recorded kernel answers (`--no-check` skips the test,
`PYTHON=...` picks the interpreter). Or by hand:

```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

Python 3.12 or newer. Everything below assumes `venv/`.

## Run

```bash
venv/bin/python -m hornet -i OBJECT.o -e ENTRY_SYMBOL -c SPEC.json -s verify
venv/bin/python -m hornet -i OBJECT.o -e ENTRY_SYMBOL -s info       # describe it
```

The specification is JSON: the world the program starts in, and the conditions
to decide about it. [`SPEC.md`](SPEC.md) documents the format.

For instance, the 226-block load balancer and one of its specifications:

```bash
venv/bin/python -m hornet -i example/katran/balancer_main.o \
    -e balancer_ingress -c benchmark/specs/katran/balancer_main.json
```

## Check the artifact

Two commands reproduce the correctness results end to end; both read recorded
answers, need no privileges and finish in seconds:

```bash
venv/bin/python benchmark/e1-correctness/run.py cases    # 250/250 checks passed
venv/bin/python benchmark/e1-correctness/run.py corpus   #  22/22 checks passed
```

Each experiment has its own runner and its own README under `benchmark/`:

| | What it runs | Notes |
|---|---|---|
| `e1-correctness` | `cases`, `corpus`, `conformance` | `conformance` additionally builds an external ISA test runner (network, cmake) |
| `e2-performance` | verification time over the nine-NF dataset | two phases, reported separately |
| `e3-casestudy` | cost of a whole verification session | |
| `e4-ablation` | what path pruning and value resolution contribute | |

Every runner measures hornet alone. The tools the evaluation compares against
are third-party and are not part of this artifact.
