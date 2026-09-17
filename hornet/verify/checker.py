from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from z3 import And, BitVecVal, SolverFor, sat, simplify

from verify import prune
from verify import witness as _witness
from verify.forward import ForwardContext
from track.encode import _and, _not


@dataclass
class CheckResult:
    name:    str
    kind:    str
    verdict: str
    detail:  str = ''
    witness: Any = field(default=None, repr=False)


Context = ForwardContext


def _query(guard, body, ctx=None):
    combined = _and(guard, body)
    if combined is True or combined is False or ctx is None:
        return combined
    defs = ctx.definitions(guard, body)
    return And(combined, *defs) if defs else combined


def _decide(solver, guard, body, ctx=None):
    combined = _query(guard, body, ctx)
    if combined is False:
        return False, None
    solver.push()
    if combined is not True:
        solver.add(simplify(combined))
    result = solver.check()
    model = solver.model() if result == sat else None
    solver.pop()
    return result == sat, model


UNMODELLED_EFFECTS = {
    'perf_event_output': 'recorded but has no state effect (genuinely none to model)',
    'adjust_meta': 'bpf_xdp_adjust_meta moves data_meta; the metadata area has '
                   'no byte array, so the move is recorded but not applied',
}


def _vacuous(solver, ctx, block, cache) -> bool:
    r = ctx.reach(block)
    if r is True:
        return False
    if r is False:
        return True
    if block not in cache:
        cache[block] = not _decide(solver, r, True, ctx)[0]
    return cache[block]


def check_block_condition(bc, ctx, solver, vac_cache) -> CheckResult:
    r = ctx.reach(bc.block)
    if bc.block not in ctx.info or r is False:
        v = 'unsat' if bc.assert_mode == 'exists' else 'holds'
        return CheckResult(bc.name, 'block_condition', v,
                           detail=f'block {bc.block} unreachable')

    body = bc.cond.to_z3(ctx.state_at(bc.block))
    if bc.assert_mode == 'exists':
        ok, model = _decide(solver, r, body, ctx)
        verdict = 'sat' if ok else 'unsat'
    else:
        ok, model = _decide(solver, r, _not(body), ctx)
        verdict = 'violated' if ok else 'holds'

    detail = f'block={bc.block}'
    if ctx.info[bc.block].imprecise:
        detail += ' (imprecise: unrecorded branch condition)'
    for note in ctx.dropped_effects(bc.block):
        detail += f' (UNMODELLED: {note})'
    if verdict in ('holds', 'unsat') and _vacuous(solver, ctx, bc.block, vac_cache):
        detail += ' (VACUOUS: block is unreachable under this input)'
    w = (_witness.build(model, ctx, bc.block, bc.cond, ctx.state_at(bc.block))
         if model is not None else None)
    return CheckResult(bc.name, 'block_condition', verdict, detail=detail, witness=w)


def check_exit_condition(ec, ctx, solver) -> CheckResult:
    live = [b for b in prune.exit_blocks(ctx.blocks)
            if b in ctx.info and ctx.reach(b) is not False]
    if not live:
        v = 'unsat' if ec.assert_mode == 'exists' else 'holds'
        return CheckResult(ec.name, 'exit_condition', v, detail='no reachable exit')

    per_exit, w, hit = {}, None, None
    for b in live:
        st = ctx.ret_state(b)
        if st is None:
            continue
        body = ec.cond.to_z3(st)
        if ec.assert_mode == 'exists':
            ok, model = _decide(solver, ctx.reach(b), body, ctx)
            per_exit[b] = ok
            if ok and w is None:
                w, hit = _witness.build(model, ctx, b, ec.cond, st), b
        else:
            bad, model = _decide(solver, ctx.reach(b), _not(body), ctx)
            per_exit[b] = not bad
            if bad and w is None:
                w, hit = _witness.build(model, ctx, b, ec.cond, st), b

    detail = 'exits: ' + ', '.join(f'{b}={"ok" if v else "bad"}'
                                   for b, v in sorted(per_exit.items()))
    if hit is not None:
        detail += f' | witness at exit {hit}'
    for note in sorted({n for b in live for n in ctx.dropped_effects(b)}):
        detail += f' (UNMODELLED: {note})'
    if ec.assert_mode == 'exists':
        verdict = 'sat' if any(per_exit.values()) else 'unsat'
    else:
        verdict = 'holds' if all(per_exit.values()) else 'violated'
    return CheckResult(ec.name, 'exit_condition', verdict, detail=detail, witness=w)


def reach_report(ctx, solver) -> list:
    order = sorted(ctx.info)
    entry = order[0] if order else None
    dead, out = set(), []
    for b in order:
        preds = ctx.blocks[b].preds or []
        if b != entry and preds and all(p in dead or p not in ctx.info
                                        for p in preds):
            dead.add(b)
            out.append(CheckResult(
                f'block{b}', 'reachability', 'unsat',
                detail=f'kind={ctx.blocks[b].kind}; every predecessor is dead'))
            continue
        live = _decide(solver, ctx.reach(b), True, ctx)[0]
        if not live:
            dead.add(b)
        out.append(CheckResult(f'block{b}', 'reachability',
                               'sat' if live else 'unsat',
                               detail=f'kind={ctx.blocks[b].kind}'))
    return out


def reachable_return_values(blocks: list, maps: list,
                            init_st=None, values=range(5), ctx=None) -> list:
    if ctx is None:
        ctx = ForwardContext(blocks, maps, init_st=init_st)
    solver = SolverFor('QF_ABV')
    exits = [b for b in prune.exit_blocks(blocks)
             if b in ctx.info and ctx.reach(b) is not False
             and blocks[b].ret_expr is not None]
    out = []
    for v in values:
        rhs = BitVecVal(v, 64)
        for b in exits:
            if _decide(solver, ctx.reach(b), ctx.ret_state(b).r0 == rhs, ctx)[0]:
                out.append(v)
                break
    return out


def context_for(policies, blocks: list, maps: list, init_st=None,
                calls: dict = None, reach_all: bool = False) -> ForwardContext:
    policies = list(policies)
    targets = sorted({bc.block for p in policies
                      for bc in p.block_conditions.values()})
    if not policies or reach_all or any(p.exit_conditions for p in policies):
        targets = None
    cond_trees = [c.cond for p in policies
                  for c in (*p.block_conditions.values(),
                            *p.exit_conditions.values())]
    return ForwardContext(blocks, maps, init_st=init_st, calls=calls,
                          targets=targets, cond_trees=cond_trees)


def check(policy, blocks: list, maps: list,
          init_st=None, calls: dict = None, reach_all: bool = False,
          ctx: ForwardContext = None) -> list:
    if ctx is None:
        ctx = context_for([policy], blocks, maps, init_st=init_st,
                          calls=calls, reach_all=reach_all)

    solver = SolverFor('QF_ABV')
    vac_cache: dict = {}
    results = [check_block_condition(bc, ctx, solver, vac_cache)
               for bc in policy.block_conditions.values()]
    results += [check_exit_condition(ec, ctx, solver)
                for ec in policy.exit_conditions.values()]
    if reach_all:
        results += reach_report(ctx, solver)
    return results


def render(results: list, show_witness: bool = True,
           pipeline: bool = True) -> str:
    lines = []
    for r in results:
        lines.append(f"  {r.kind:15} {r.name:30} -> {r.verdict:9} {r.detail}")
        if show_witness and r.witness is not None:
            lines += [f"      {line}"
                      for line in r.witness.render(pipeline=pipeline).splitlines()]
    lines.append(f"decided: {len(results)} condition(s)")
    return '\n'.join(lines)


def report(results: list, show_witness: bool = True,
           pipeline: bool = True) -> None:
    print(render(results, show_witness=show_witness, pipeline=pipeline))
