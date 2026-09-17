import argparse
import csv
import json
import os
import statistics
import subprocess
import sys

HERE  = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.dirname(HERE)
sys.path.insert(0, BENCH)
import common

FIELDS = ['nf', 'source', 'status', 'blocks', 'edges', 'maps', 'returns',
          'phase1_s', 'chain_s', 'query_s', 'phase2_s', 'total_s',
          'total_lo_s', 'total_hi_s', 'runs']


# ── the child: measures ONE program in a fresh process ───────────────────────
#
# Forking per program is not optional. cfg.get_next_block_no and loader._fail
# call exit(1) on a loop or a missing symbol, and `except Exception` does not
# catch SystemExit. Z3 state also accumulates within a process: the same query
# on the same term is measurably slower as a process's second solve than as its
# first, and neither gc nor re-pinning the seed recovers it.
_CHILD = r'''
import json, sys, time
sys.path.insert(0, {bench!r})
import common

out, buf = dict(status='ok'), None
try:
    from z3 import set_param
    set_param('smt.random_seed', {seed}); set_param('sat.random_seed', {seed})
    from verify import checker

    with common.quiet() as buf:
        # phase 1 -- ELF decode, CFG construction, one tracking pass.
        t0 = time.perf_counter()
        prog = common.track(common.object_path({rel!r}), {entry!r})
        out['track'] = time.perf_counter() - t0

        # phase 2a -- the verification chain: path pruning and value
        # resolution, with NO spec, so nothing constrains the input.
        t0 = time.perf_counter()
        ctx = checker.Context(prog.blocks, prog.maps, calls=prog.calls)
        out['chain'] = time.perf_counter() - t0

        # phase 2b -- one query per XDP return value: can the NF return it?
        t0 = time.perf_counter()
        rets = checker.reachable_return_values(prog.blocks, prog.maps, ctx=ctx)
        out['query'] = time.perf_counter() - t0

    out.update(blocks=len(prog.blocks),
               edges=sum((b.succ_t is not None) + (b.succ_f is not None)
                         for b in prog.blocks),
               maps=len(prog.maps), rets=sorted(rets))
except SystemExit:
    msg = buf.getvalue() if buf is not None else ''
    out = dict(status=('loop' if 'cannot find next block' in msg
                       else 'no_symbol' if 'No symbol named' in msg
                       else 'exit'))
except BaseException as e:
    out = dict(status=type(e).__name__, detail=str(e)[:200])
print('@@JSON@@' + json.dumps(out))
'''


def run_one(rel, entry, timeout, seed):
    src = _CHILD.format(bench=BENCH, rel=rel, entry=entry, seed=seed)
    try:
        p = subprocess.run([sys.executable, '-c', src], capture_output=True,
                           text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {'status': 'timeout'}
    for line in p.stdout.splitlines():
        if line.startswith('@@JSON@@'):
            return json.loads(line[len('@@JSON@@'):])
    return {'status': 'crash', 'detail': (p.stderr or p.stdout)[-300:].strip()}


def summarize(runs):
    ok = [r for r in runs if r['status'] == 'ok']
    if not ok:
        return None
    med = lambda k: statistics.median(r[k] for r in ok)
    total = [r['track'] + r['chain'] + r['query'] for r in ok]
    # Deterministic: same seed, same object. A repetition that disagreed would
    # mean the answer depends on the machine, so say so rather than average it.
    rets = {tuple(r['rets']) for r in ok}
    return dict(
        runs=len(ok), blocks=ok[0]['blocks'], edges=ok[0]['edges'],
        maps=ok[0]['maps'],
        rets=sorted(rets)[0] if len(rets) == 1 else None,
        phase1=med('track'), chain=med('chain'), query=med('query'),
        phase2=med('chain') + med('query'),
        total=statistics.median(total), lo=min(total), hi=max(total))


def _ms(x):
    return f'{x * 1000:.1f}ms' if x < 1 else f'{x:.2f}s'


def report(rows, repeat):
    print(f'E2 performance — nine open-source XDP NFs, hornet only\n')
    print('  The query asks every XDP return the NF can produce, so the solver')
    print('  has to traverse the whole control-flow space. Nothing constrains')
    print('  the input: no packet bytes, no packet length, no map entries.\n')
    print('  phase 1  ELF decode + CFG + tracking pass')
    print('  phase 2  verification chain (path pruning, value resolution)')
    print('           + the five return-value queries\n')
    hdr = (f"{'NF':20} {'source':13} {'blk':>4} {'map':>4} {'returns':22} "
           f"{'phase 1':>9} {'chain':>9} {'query':>10} {'phase 2':>10} "
           f"{'total':>10}")
    print(hdr)
    print('-' * len(hdr))

    for label, source, s, status in rows:
        if s is None:
            print(f'{label:20} {source:13} {status.upper()}')
            continue
        rets = (','.join(common.XDP_ACTIONS[v] for v in s['rets'])
                if s['rets'] is not None else 'UNSTABLE')
        print(f"{label:20} {source:13} {s['blocks']:>4} {s['maps']:>4} "
              f"{rets:22} {_ms(s['phase1']):>9} {_ms(s['chain']):>9} "
              f"{_ms(s['query']):>10} {_ms(s['phase2']):>10} "
              f"{_ms(s['total']):>10}")

    done = [(l, s) for l, _src, s, _st in rows if s is not None]
    if not done:
        return
    print(f'\nmedian of {repeat} fresh process(es) per NF, Z3 seed pinned to 0.')

    p1 = [s['phase1'] for _l, s in done]
    print(f'  phase 1 across the dataset: {_ms(min(p1))}-{_ms(max(p1))}')

    big = max(done, key=lambda ls: ls[1]['total'])
    rest = [(l, s) for l, s in done if l != big[0]]
    if rest:
        t = [s['total'] for _l, s in rest]
        print(f'  the {len(rest)} NFs other than {big[0]}: '
              f'{_ms(min(t))}-{_ms(max(t))}')
    print(f"  {big[0]}: {_ms(big[1]['total'])} total, "
          f"{_ms(big[1]['phase2'])} of it phase 2 "
          f"[{big[1]['lo']:.2f}-{big[1]['hi']:.2f}s over {big[1]['runs']} runs]")


def write_csv(path, rows):
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, FIELDS)
        w.writeheader()
        for label, source, s, status in rows:
            row = {f: '' for f in FIELDS}
            row.update(nf=label, source=source, status=status)
            if s is not None:
                rets = ('' if s['rets'] is None else
                        ','.join(common.XDP_ACTIONS[v] for v in s['rets']))
                row.update(blocks=s['blocks'], edges=s['edges'], maps=s['maps'],
                           returns=rets, runs=s['runs'],
                           phase1_s=round(s['phase1'], 4),
                           chain_s=round(s['chain'], 4),
                           query_s=round(s['query'], 4),
                           phase2_s=round(s['phase2'], 4),
                           total_s=round(s['total'], 4),
                           total_lo_s=round(s['lo'], 4),
                           total_hi_s=round(s['hi'], 4))
            w.writerow(row)
    print(f'\nwrote {path}')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--only', help='one NF label from the dataset')
    ap.add_argument('--repeat', type=int, default=5,
                    help='fresh processes per NF; the median is reported')
    ap.add_argument('--timeout', type=float, default=900.0,
                    help='per-process wall cap (default 900)')
    ap.add_argument('--csv', help='also write the table to this file')
    args = ap.parse_args()

    corpus = [p for p in common.PROGRAMS
              if not args.only or p[0] == args.only]
    if not corpus:
        print(f'no NF matches {args.only!r}', file=sys.stderr)
        return 2

    rows = []
    for label, source, obj in corpus:
        path = common.object_path(obj)
        if not os.path.isfile(path):
            rows.append((label, source, None, 'object missing'))
            continue
        entry = common.entry_of(os.path.basename(obj)[:-2])
        runs = [run_one(obj, entry, args.timeout, seed=0)
                for _ in range(args.repeat)]
        s = summarize(runs)
        status = 'ok' if s else runs[0].get('status', 'crash')
        if not s:
            detail = runs[0].get('detail', '')
            print(f'{label:20} {status} {detail}', file=sys.stderr)
        rows.append((label, source, s, status))

    report(rows, args.repeat)
    if args.csv:
        write_csv(args.csv, rows)
    return 0 if all(s is not None for _l, _s, s, _st in rows) else 1


if __name__ == '__main__':
    sys.exit(main())
