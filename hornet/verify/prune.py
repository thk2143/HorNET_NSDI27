from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from z3 import Bool, is_false, is_true, simplify

from track.encode import _and, _not, _or_all


@dataclass
class BlockInfo:
    num:        int
    reach:      Any
    edge_taken: Any = True
    edge_fall:  Any = True
    in_edges:   list = field(default_factory=list)
    imprecise:  bool = False


def successors(s) -> list:
    out = []
    if s.succ_t is not None:
        out.append(s.succ_t)
    if s.succ_f is not None and s.succ_f != s.succ_t:
        out.append(s.succ_f)
    return out


def forward_reachable(blocks: list) -> set:
    seen, stack = set(), [0]
    while stack:
        b = stack.pop()
        if b in seen or not 0 <= b < len(blocks):
            continue
        seen.add(b)
        stack.extend(successors(blocks[b]))
    return seen


def topo_order(blocks: list, live: set) -> list:
    order, color, stack = [], {}, [(0, False)]
    while stack:
        b, done = stack.pop()
        if done:
            color[b] = 2
            order.append(b)
            continue
        if color.get(b):
            continue
        color[b] = 1
        stack.append((b, True))
        for u in successors(blocks[b]):
            if u not in live:
                continue
            if color.get(u) == 1:
                raise RuntimeError(f"prune: cycle detected at block {u}")
            if color.get(u) != 2:
                stack.append((u, False))
    order.reverse()
    if len(order) != len(live):
        raise RuntimeError(
            f"prune: topological sort covered {len(order)} of {len(live)} live "
            "blocks -- the CFG is not the DAG this encoding assumes")
    return order


def ancestors(blocks: list, order: list) -> dict:
    anc: dict[int, set] = {}
    for b in order:
        s = set()
        for p in blocks[b].preds:
            if p in anc:
                s.add(p)
                s |= anc[p]
        anc[b] = s
    return anc


def _lit(t):
    if t is True or t is False:
        return t
    r = simplify(t)
    return True if is_true(r) else False if is_false(r) else r


def _branch_guards(b, st):
    if b.cond is None:
        c = Bool(f'branch{b.num}_taken')
        return c, _not(c), True
    c = _lit(b.cond.to_z3(st))
    return c, _not(c), False


def analyze(blocks: list, state_at, targets=None, info: dict = None) -> dict:
    live = forward_reachable(blocks)
    if targets is not None:
        keep = {0}
        for t in targets:
            if t in live:
                keep |= _slice_to(blocks, live, t)
        live = keep

    order = topo_order(blocks, live)
    if info is None:
        info = {}
    for b in order:
        s = blocks[b]
        if b == 0:
            reach, in_edges = True, []
        else:
            in_edges = []
            for p in sorted(set(s.preds)):
                pi = info.get(p)
                if pi is None or pi.reach is False:
                    continue
                ps = blocks[p]
                if ps.succ_t == b:
                    g = _and(pi.reach, pi.edge_taken)
                    if g is not False:
                        in_edges.append((p, 'taken', g))
                if ps.succ_f == b:
                    g = _and(pi.reach, pi.edge_fall)
                    if g is not False:
                        in_edges.append((p, 'fall', g))
            reach = _or_all([g for _, _, g in in_edges])

        taken = fall = True
        imprecise = False
        if s.kind == 'branch':
            taken, fall, imprecise = _branch_guards(s, state_at(b))
        info[b] = BlockInfo(num=b, reach=reach, edge_taken=taken,
                            edge_fall=fall, in_edges=in_edges,
                            imprecise=imprecise)
    return info


def _slice_to(blocks: list, live: set, target: int) -> set:
    bwd, stack = set(), [target]
    while stack:
        b = stack.pop()
        if b in bwd:
            continue
        bwd.add(b)
        for p in blocks[b].preds:
            if p in live and p not in bwd:
                stack.append(p)
    return bwd


def exit_blocks(blocks: list) -> list:
    return [b.num for b in blocks if b.kind == 'exit']
