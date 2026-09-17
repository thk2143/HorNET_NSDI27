from __future__ import annotations

import dataclasses

from track.expr import JoinValue

_PRIM = (int, float, str, bytes, bool, type(None))


def _children(o):
    if isinstance(o, (list, tuple, set)):
        return list(o)
    if isinstance(o, dict):
        return list(o.values())
    out, named = [], set()
    if dataclasses.is_dataclass(o) and not isinstance(o, type):
        for f in dataclasses.fields(o):
            named.add(f.name)
            out.append(getattr(o, f.name))
    for k, v in getattr(o, '__dict__', {}).items():
        if k not in named and k != '_h':
            out.append(v)
    return out


def live_phis(blocks) -> set[int]:
    roots = []
    for b in blocks:
        roots += list(b.actions)
        roots += [c for c in (b.cond, b.cond_f, b.cond_t) if c is not None]
        roots += list(b.ptr_facts.values())
        roots += list(b.pkt_ptr_facts.values())
        if b.exit and b.regs[0] is not None:
            roots.append(b.regs[0])
        roots += [s for s in b.sources if not isinstance(s, JoinValue)]

    live, seen, stack = set(), set(), roots
    while stack:
        x = stack.pop()
        if isinstance(x, _PRIM) or id(x) in seen:
            continue
        seen.add(id(x))
        if isinstance(x, JoinValue):
            live.add(id(x))
        stack.extend(_children(x))
    return live


def drop_dead_phis(blocks, verbose: bool = False) -> int:
    live = live_phis(blocks)
    kept = dropped = 0
    for b in blocks:
        keep = []
        for s in b.sources:
            if isinstance(s, JoinValue):
                if id(s) not in live:
                    dropped += 1
                    continue
                kept += 1
            keep.append(s)
        b.sources = keep
    if verbose:
        print(f"phi dce: kept {kept}, dropped {dropped}")
    return kept
