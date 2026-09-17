# E4 — ablation

E3 measured what a campaign costs with the verification chain as it ships. This
takes the same campaigns and switches the chain's stages off one at a time, so
each stage's share of the cost is measured rather than asserted.

| Config | What it removes |
|---|---|
| `full` | nothing — the chain E3 measured |
| `-P` | path pruning: edges the input decides no longer fold away |
| `-R` | value resolution: reads stay variables, and their assignments go to the solver |
| `-P-R` | both |

Every configuration is semantics-preserving, so each one must still reach the
campaign's verdict on every property; the runner checks that and fails if not.

```bash
venv/bin/python benchmark/e4-ablation/run.py
venv/bin/python benchmark/e4-ablation/run.py --only fw --config full --repeat 1
```

Each measurement runs in a fresh process, and repetition *i* pins the solver's
random seed to *i*.
