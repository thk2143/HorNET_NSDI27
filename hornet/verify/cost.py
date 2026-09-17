from __future__ import annotations

from z3 import is_app


def _walk(expr, seen: set, counts: dict) -> None:
    if expr is None or expr is True or expr is False:
        return
    stack = [expr]
    while stack:
        e = stack.pop()
        if not is_app(e):
            continue
        eid = e.get_id()
        if eid in seen:
            continue
        seen.add(eid)
        name = e.decl().name()
        counts[name] = counts.get(name, 0) + 1
        for i in range(e.num_args()):
            stack.append(e.arg(i))


def ast_stats(*exprs) -> dict:
    seen: set = set()
    counts: dict = {}
    for e in exprs:
        _walk(e, seen, counts)
    counts['total'] = len(seen)
    return counts


def query_cost(ctx, blocks) -> dict:
    from verify import prune

    best = 0
    for b in prune.exit_blocks(blocks):
        if b not in ctx.info or ctx.reach(b) is False:
            continue
        st = ctx.ret_state(b)
        if st is None:
            continue
        total = ast_stats(ctx.reach(b), st.r0)['total']
        if total > best:
            best = total
    return {'nodes': best, 'stores': getattr(ctx, 'n_stores', None)}
