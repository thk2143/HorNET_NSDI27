import argparse
import json
import os
import statistics
import subprocess
import sys

HERE  = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.dirname(HERE)
E3    = os.path.join(BENCH, 'e3-casestudy')
sys.path.insert(0, BENCH)
sys.path.insert(0, E3)
import common
from campaign import CAMPAIGNS

SPECS = os.path.join(E3, 'specs')


class Config:
    def __init__(self, name, prune_paths, resolve_values, removes):
        self.name, self.removes = name, removes
        self.flags = dict(prune_paths=prune_paths, resolve_values=resolve_values,
                          hybrid_fold=True)


CONFIGS = [
    Config('full',  True,  True,  '-'),
    Config('-P',    False, True,  'path pruning'),
    Config('-R',    True,  False, 'value resolution'),
    Config('-P-R',  False, False, 'both'),
]


_CHILD = r'''
import json, os, sys, time
sys.path.insert(0, {bench!r})
import common
from z3 import set_param, simplify
set_param('smt.random_seed', {seed}); set_param('sat.random_seed', {seed})
from verify import checker
from verify.cost import ast_stats
from verify.forward import ForwardContext
from verify.spec import load_spec, z3_state_from_input

specs = {specs!r}
with common.quiet():
    t0 = time.perf_counter()
    prog = common.track(common.object_path({rel!r}), {entry!r})
    track = time.perf_counter() - t0

    t0 = time.perf_counter()
    against = dict(maps=prog.maps, blocks=prog.blocks, calls=prog.calls)
    policies = [load_spec(p, **against) for p in specs]
    init = (z3_state_from_input(policies[0].input, prog.maps)
            if policies[0].input else None)
    parse = time.perf_counter() - t0

    t0 = time.perf_counter()
    ctx = ForwardContext(prog.blocks, prog.maps, init_st=init,
                         calls=prog.calls, **{flags!r})
    chain = time.perf_counter() - t0

    rows = []
    for path, policy in zip(specs, policies):
        t0 = time.perf_counter()
        results = checker.check(policy, prog.blocks, prog.maps, init_st=init,
                                calls=prog.calls, ctx=ctx)
        solve = time.perf_counter() - t0
        rows.append(dict(spec=os.path.basename(path), solve=solve,
                         verdicts={{r.name: r.verdict for r in results}}))

out = dict(blocks=len(prog.blocks), track=track, parse=parse, chain=chain,
           rows=rows)

if {probe!r}:
    # Structure, not time: everything below is after the timed part and
    # never calls the solver. `_decide` is swapped for a counter that sizes
    # the exact formula the real one would have solved (checker._query) and
    # answers "unsat" -- which builds no witness, so it cannot fail.
    info = ctx.info
    live = [b for b in info if ctx.reach(b) is not False]
    folded = sum(1 for b in live if prog.blocks[b].branch
                 for g in (info[b].edge_taken, info[b].edge_fall) if g is False)
    probe = dict(queries=0, nodes=0, simplified=0, ite=0, defs=0)
    def sizing(solver, guard, body, ctx=None):
        probe['queries'] += 1
        q = checker._query(guard, body, ctx)
        if q is not True and q is not False:
            st = ast_stats(q)
            probe['nodes'] += st['total']
            probe['ite'] += st.get('if', 0)
            probe['simplified'] += ast_stats(simplify(q))['total']
            probe['defs'] += len(ctx.definitions(guard, body)) if ctx else 0
        return False, None
    checker._decide = sizing
    with common.quiet():
        for policy in policies:
            checker.check(policy, prog.blocks, prog.maps, init_st=init,
                          calls=prog.calls, ctx=ctx)
    out['structure'] = dict(
        slice=len(info), live=len(live), dead=len(info) - len(live),
        folded_edges=folded, stores=ctx.n_stores, read_vars=len(ctx.defs),
        fold_regions=len(ctx.fold), **probe)

print('@@JSON@@' + json.dumps(out))
'''


def run_one(camp, cfg, timeout, seed, probe):
    specs = [os.path.join(SPECS, f'{camp.label(p)}.json') for p in camp.props]
    src = _CHILD.format(bench=BENCH, rel=camp.obj, entry=camp.entry,
                        specs=specs, flags=cfg.flags, seed=seed, probe=probe)
    try:
        p = subprocess.run([sys.executable, '-c', src], capture_output=True,
                           text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {'status': 'timeout'}
    for line in p.stdout.splitlines():
        if line.startswith('@@JSON@@'):
            out = json.loads(line[len('@@JSON@@'):])
            out['status'], out['seed'] = 'ok', seed
            return out
    return {'status': 'error', 'seed': seed,
            'detail': (p.stderr or p.stdout)[-400:].strip()}


def _med(xs):
    return statistics.median(xs) if xs else None


def summarize(runs):
    ok = [r for r in runs if r['status'] == 'ok']
    if not ok:
        return None
    solve = [sum(x['solve'] for x in r['rows']) for r in ok]
    verify = [r['chain'] + s for r, s in zip(ok, solve)]
    total = [r['track'] + r['parse'] + v for r, v in zip(ok, verify)]
    n = len(ok[0]['rows'])
    return dict(
        n=len(ok), failed=len(runs) - len(ok),
        chain=_med([r['chain'] for r in ok]),
        solve=_med(solve),
        verify=_med(verify), verify_lo=min(verify), verify_hi=max(verify),
        total=_med(total), lo=min(total), hi=max(total),
        track=_med([r['track'] for r in ok]),
        parse=_med([r['parse'] for r in ok]),
        per_prop=[_med([r['rows'][i]['solve'] for r in ok]) for i in range(n)],
        structure=next((r['structure'] for r in ok if 'structure' in r), None),
        blocks=ok[0]['blocks'])


def check_verdicts(camp, cfg, runs):
    bad = []
    for r in runs:
        if r['status'] != 'ok':
            continue
        for p, row in zip(camp.props, r['rows']):
            got = '/'.join(sorted(set(row['verdicts'].values())))
            if got != p.expect:
                bad.append(f'{camp.label(p)} [{cfg.name}]: {got}, '
                           f'campaign expects {p.expect}')
    return sorted(set(bad))


def _t(x):
    return '-' if x is None else f'{x:.3f}s'


def report(camp, configs, summ, runs):
    full = summ.get('full')
    blocks = next((s['blocks'] for s in summ.values() if s), '?')
    reps = max((s['n'] for s in summ.values() if s), default=0)
    print(f'\n=== {camp.nf} — {camp.obj}, {blocks} blocks, '
          f'5 properties, median of {reps} fresh process(es), seeds 0..{reps - 1}')
    hdr = (f"    {'config':6} {'removes':18} {'track':>7} {'parse':>7} "
           f"{'chain':>7} {'solve':>8} {'verify':>8} {'x':>6} {'total':>8} "
           f"{'x':>6}   {'total spread':>15}")
    print(hdr)
    print('    ' + '-' * (len(hdr) - 4))
    for cfg in configs:
        s = summ.get(cfg.name)
        if s is None:
            st = {r['status'] for r in runs[cfg.name]}
            print(f"    {cfg.name:6} {cfg.removes:18} {'/'.join(sorted(st)).upper()}")
            continue

        def rel(key):
            return (f"{s[key] / full[key]:5.2f}x"
                    if full and cfg.name != 'full' else '     -')
        fail = f"  ({s['failed']} failed)" if s['failed'] else ''
        print(f"    {cfg.name:6} {cfg.removes:18} {_t(s['track']):>7} "
              f"{_t(s['parse']):>7} {_t(s['chain']):>7} {_t(s['solve']):>8} "
              f"{_t(s['verify']):>8} {rel('verify'):>6} {_t(s['total']):>8} "
              f"{rel('total'):>6}   [{s['lo']:.3f}-{s['hi']:.3f}]{fail}")

    print(f"\n    {'per-property solve':25}" +
          ''.join(f'{p.key:>9}' for p in camp.props))
    for cfg in configs:
        s = summ.get(cfg.name)
        if s is not None:
            print(f"    {cfg.name:25}" +
                  ''.join(f'{x:8.3f}s' for x in s['per_prop']))

    print(f"\n    {'structure':6} {'live/slice':>10} {'dead':>5} {'F-edges':>8} "
          f"{'stores':>7} {'readvars':>9} {'defs':>6} {'nodes':>9} "
          f"{'simplified':>11} {'ite':>6}")
    for cfg in configs:
        s = summ.get(cfg.name)
        st = s and s['structure']
        if not st:
            continue
        print(f"    {cfg.name:6} {st['live']:>5}/{st['slice']:<4} {st['dead']:>5} "
              f"{st['folded_edges']:>8} {st['stores']:>7} {st['read_vars']:>9} "
              f"{st['defs']:>6} {st['nodes']:>9,} {st['simplified']:>11,} "
              f"{st['ite']:>6,}")
    print('    (nodes / simplified / ite / defs: summed over the '
          f"{(full or {}).get('structure', {}).get('queries', '?')} "
          'solver queries of the campaign)')


def overview(camps, configs, dump):
    names = [g.name for g in configs]
    for key, title in (('total', 'campaign total (track + parse + chain + solve)'),
                       ('verify', 'verify only (chain + solve)')):
        print(f"\n=== {title}, median\n    {'NF':9}" +
              ''.join(f'{n:>16}' for n in names))
        for camp in camps:
            summ = dump[camp.nf]['summary']
            full = summ.get('full')
            cells = []
            for n in names:
                s = summ.get(n)
                if s is None:
                    cells.append(f"{'n/a':>16}")
                elif full and n != 'full':
                    cells.append(f"{s[key]:8.3f}s ({s[key] / full[key]:4.2f}x)")
                else:
                    cells.append(f"{s[key]:15.3f}s")
            print(f'    {camp.nf:9}' + ''.join(cells))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--only')
    ap.add_argument('--config', action='append',
                    choices=[c.name for c in CONFIGS])
    ap.add_argument('--repeat', type=int, default=5)
    ap.add_argument('--timeout', type=int, default=600,
                    help='wall cap per process (default 600)')
    ap.add_argument('--json', help='write raw measurements here')
    args = ap.parse_args()

    camps = [c for c in CAMPAIGNS if not args.only or args.only in c.nf]
    configs = [c for c in CONFIGS if not args.config or c.name in args.config]
    if not camps:
        print(f'no campaign matches {args.only!r}', file=sys.stderr)
        return 2

    print('E4 ablation — E3\'s campaigns, verify stages switched off one at a '
          f'time, {args.repeat} rep(s), {args.timeout}s cap per process')

    runs = {c.nf: {g.name: [] for g in configs} for c in camps}
    for rep in range(args.repeat):
        for camp in camps:
            for cfg in configs:
                r = run_one(camp, cfg, args.timeout, seed=rep, probe=(rep == 0))
                runs[camp.nf][cfg.name].append(r)
                if r['status'] != 'ok':
                    print(f"  rep {rep + 1} {camp.nf} {cfg.name}: {r['status']} "
                          f"{r.get('detail', '')[-200:]}", file=sys.stderr)

    warnings, dump = [], {}
    for camp in camps:
        summ = {g.name: summarize(runs[camp.nf][g.name]) for g in configs}
        for g in configs:
            warnings += check_verdicts(camp, g, runs[camp.nf][g.name])
        report(camp, configs, summ, runs[camp.nf])
        dump[camp.nf] = {'summary': summ, 'runs': runs[camp.nf]}

    overview(camps, configs, dump)

    if args.json:
        with open(args.json, 'w') as f:
            json.dump(dump, f, indent=2)
        print(f'\nraw measurements -> {args.json}')

    if warnings:
        print('\nCHECK — a configuration changed a verdict (an ablation must not):')
        for w in warnings:
            print('  ' + w)
        return 1
    print('\nevery configuration reached the campaign verdict on every property.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
