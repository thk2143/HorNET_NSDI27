import argparse
import json
import os
import subprocess
import sys

HERE  = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.dirname(HERE)
sys.path.insert(0, BENCH)
sys.path.insert(0, HERE)
from campaign import CAMPAIGNS

SPECS = os.path.join(HERE, 'specs')


_CHILD = r'''
import json, os, sys, time
sys.path.insert(0, {bench!r})
import common
from z3 import set_param
set_param('smt.random_seed', 0); set_param('sat.random_seed', 0)
from verify import checker
from verify.spec import load_spec, z3_state_from_input

specs = {specs!r}
with common.quiet():
    t0 = time.perf_counter()
    prog = common.track(common.object_path({rel!r}), {entry!r})
    track = time.perf_counter() - t0

    # The input world is the same for every property, so it is parsed and
    # turned into a Z3 entry state once. Parsing each spec still happens per
    # property -- that is the file the engineer edited.
    t0 = time.perf_counter()
    world = load_spec(specs[0], maps=prog.maps, blocks=prog.blocks,
                      calls=prog.calls)
    init = z3_state_from_input(world.input, prog.maps) if world.input else None
    ctx = checker.Context(prog.blocks, prog.maps, init_st=init,
                          calls=prog.calls)
    chain = time.perf_counter() - t0

    rows = []
    for path in specs:
        t0 = time.perf_counter()
        policy = load_spec(path, maps=prog.maps, blocks=prog.blocks,
                           calls=prog.calls)
        parse = time.perf_counter() - t0
        t0 = time.perf_counter()
        results = checker.check(policy, prog.blocks, prog.maps, init_st=init,
                                calls=prog.calls, ctx=ctx)
        solve = time.perf_counter() - t0
        rows.append(dict(spec=os.path.basename(path), parse=parse, solve=solve,
                         verdicts={{r.name: r.verdict for r in results}}))
print('@@JSON@@' + json.dumps(dict(
    blocks=len(prog.blocks), track=track, chain=chain, rows=rows)))
'''


def run_campaign(camp, timeout):
    specs = [os.path.join(SPECS, f'{camp.label(p)}.json') for p in camp.props]
    src = _CHILD.format(bench=BENCH, rel=camp.obj, entry=camp.entry,
                        specs=specs)
    try:
        p = subprocess.run([sys.executable, '-c', src], capture_output=True,
                           text=True, timeout=timeout * (len(specs) + 2))
    except subprocess.TimeoutExpired:
        return {'status': 'timeout'}
    for line in p.stdout.splitlines():
        if line.startswith('@@JSON@@'):
            out = json.loads(line[len('@@JSON@@'):])
            out['status'] = 'ok'
            out['track_runs'] = 1
            return out
    return {'status': 'error', 'detail': (p.stderr or p.stdout)[-300:].strip()}


def verdict_of(vs):
    return '/'.join(sorted(set(vs.values()))) or '-'


def report(camp, h):
    print(f'\n=== {camp.nf} — {camp.obj}')
    print(f'    world: {camp.world}')

    hdr = (f"    {'prop':4} {'property':30} {'expect':9} "
           f"{'verdict':>9} {'parse':>8} {'solve':>8}")
    print(hdr)
    print('    ' + '-' * (len(hdr) - 4))

    warn = []
    for i, p in enumerate(camp.props):
        if h['status'] != 'ok':
            print(f"    {p.key:4} {p.name:30} {p.expect:9} {'-':>9}")
            continue
        r = h['rows'][i]
        got = verdict_of(r['verdicts'])
        print(f"    {p.key:4} {p.name:30} {p.expect:9} "
              f"{got:>9} {r['parse']:7.2f}s {r['solve']:7.2f}s")
        if got != p.expect and got in ('holds', 'violated'):
            warn.append(f'{camp.label(p)}: {got}, expected {p.expect}')

    if h['status'] == 'ok':
        one_time = h['track'] + h['chain']
        per_prop = sum(r['parse'] + r['solve'] for r in h['rows'])
        print(f"\n    one-time {one_time:6.2f}s (track {h['track']:.2f} + "
              f"chain {h['chain']:.2f}, {h['blocks']} blocks)"
              f" + 5 properties {per_prop:6.2f}s"
              f"  = {one_time + per_prop:6.2f}s")
    return warn


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--only')
    ap.add_argument('--timeout', type=int, default=300,
                    help='per-property wall cap (default 300)')
    ap.add_argument('--json', help='write raw measurements here')
    args = ap.parse_args()

    camps = [c for c in CAMPAIGNS if not args.only or args.only in c.nf]
    if not camps:
        print(f'no campaign matches {args.only!r}', file=sys.stderr)
        return 2

    print('E3 case study — one campaign per NF, 5 properties each')
    print('  The input world is FIXED within a campaign; only the property '
          'moves. The program\n  is tracked once and the chain built once, so'
          ' a property costs a parse and a solve.')

    warnings, dump = [], {}
    for camp in camps:
        h = run_campaign(camp, args.timeout)
        dump[camp.nf] = h
        if h['status'] != 'ok':
            print(f"\n=== {camp.nf}: {h['status']}: {h.get('detail', '')}",
                  file=sys.stderr)
        warnings += report(camp, h)

    if args.json:
        with open(args.json, 'w') as f:
            json.dump(dump, f, indent=2)
        print(f'\nraw measurements -> {args.json}')

    if warnings:
        print('\nCHECK — a verdict did not come out as the campaign predicts:')
        for w in warnings:
            print('  ' + w)
        return 1
    print('\nevery property came out as the campaign predicts.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
