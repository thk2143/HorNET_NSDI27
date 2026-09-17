# E2 — verification time

What does it cost to answer the hardest question that can be asked about an NF
without naming a property?

> Which XDP actions can this program return?

That is the worst case on purpose. Answering it means deciding reachability for
every return in the program, so the solver has to traverse the entire
control-flow space rather than the slice one named property needs. Nothing
narrows the input either: **no packet bytes are pinned, the packet length is a
free variable, and no map holds a seeded entry**, so every state configuration
the program admits stays in play.

```bash
venv/bin/python benchmark/e2-performance/run.py
venv/bin/python benchmark/e2-performance/run.py --only katran
venv/bin/python benchmark/e2-performance/run.py --repeat 1 --csv e2.csv
```

Baselines are out of scope here: this runner measures the hornet side alone.

## The dataset

Nine open-source XDP network functions, defined once in
[`../common.py`](../common.py) as `PROGRAMS` and listed here smallest first.

| NF | source | object |
|---|---|---|
| fw | hXDP | `hxdp/xdp_fw_kern.o` |
| traffic-pacing-edt | bpf-examples | `bpf-examples/xdp_cpumap_qinq.o` |
| hercules | Hercules | `hercules/redirect_userspace.o` |
| fluvia | Fluvia | `fluvia/xdp_bpfel.o` |
| xdp-filter-alw-eth | xdp-tools | `xdp-tools/xdpfilt_alw_eth.o` |
| xdp-filter-dny-eth | xdp-tools | `xdp-tools/xdpfilt_dny_eth.o` |
| crab | CRAB | `crab/lb_kern.o` |
| dhcp-relay | bpf-examples | `bpf-examples/dhcp_kern_xdp.o` |
| katran | Katran | `katran/balancer_main.o` |

They span packet filtering, load balancing and stateful processing, and range
from a 17-block firewall to katran at 226 blocks — the largest in the dataset,
and the only one whose cost is not dominated by fixed overhead.

**The two xdp-filter rows are separate NFs, not one measured twice.**
xdp-filter is one source file that a `#define` block compiles into any of ten
programs, and each is loaded on its own; `alw` and `dny` differ by
`FILT_MODE_ALLOW` vs `FILT_MODE_DENY`, which exchanges `XDP_DROP` and
`XDP_PASS` at the returns and changes nothing else. Identical control flow and
the same two map lookups, opposite answers — so the pair doubles as a control
on whether the return-value question is about reachability rather than about
which constant sits at an exit.

## The two phases

`run.py` times them separately, because they answer to different parts of the
design and scale differently.

| | What runs | What it costs |
|---|---|---|
| **phase 1** | ELF decode, CFG construction, one tracking pass | flat — it is a single walk over the program, so it moves with block count and nothing else |
| **phase 2** | the verification chain (path pruning, value resolution) plus one Z3 query per XDP return value | the whole variance in the table |

Phase 2 is reported as a sum and also split into its two stages, `chain` (state
threaded forward through the CFG, which is where path-aware merging and
semantic-guided reduction do their work) and `query` (the five solver calls).
The split is what shows *where* a program's cost sits: for katran the query
stage is the answer, for dhcp-relay and crab it is the chain.

Phase 1 is sensitive to Python's bytecode cache — a first run on a cold
`__pycache__` pays the compile — so do not read a single cold measurement as
the analyzer's own cost.

## Method

Every measurement runs in a **fresh process**, and the reported number is the
median of `--repeat` of them (5 by default).

Forking per program is not a convenience. `cfg.get_next_block_no` and
`loader._fail` exit the interpreter on a loop or a missing symbol, which no
`except Exception` catches; and Z3's state accumulates within a process, so the
same query on the same term is slower as a process's second solve than as its
first. Re-pinning the seed does not recover it, so the only way to time a
program without the previous one in it is to start over.

The solver's random seed is pinned to 0, which makes the return sets
deterministic: a repetition that disagreed would mean the answer depends on the
machine, so `run.py` reports `UNSTABLE` rather than averaging the two.

## Reading the output

The table ends with the three ranges the evaluation is stated in — phase 1
across the whole dataset, the total for the eight NFs other than the largest,
and the largest one broken out with its spread over the repetitions. The
spread is there to be looked at: if `[lo-hi]` is wide, the median in the row
above it is not a number to quote.
