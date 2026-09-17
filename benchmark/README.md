# Experiments

Four experiments evaluate hornet, one directory each.

| | Question |
|---|---|
| [`e1-correctness/`](e1-correctness/) | Are hornet's answers the same ones the kernel gives, and how much of the BPF semantics does it cover? |
| [`e2-performance/`](e2-performance/) | What does verification cost on nine open-source NFs, with nothing constraining the input? |
| [`e3-casestudy/`](e3-casestudy/) | What does a whole verification session cost — one program, a list of properties? |
| [`e4-ablation/`](e4-ablation/) | What do path pruning and value resolution each contribute to that cost? |

Shared by all four: `common.py` (where the programs are, and how to track one)
and `specs/` (the specification fixtures for the open-source corpus, in the
format [`../SPEC.md`](../SPEC.md) describes).

All four measure hornet alone; no baseline tool is part of this artifact.
`common.py` also defines `PROGRAMS`, the nine-NF dataset E2 runs on.
