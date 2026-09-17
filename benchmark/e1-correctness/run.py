import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common

HERE = os.path.dirname(os.path.abspath(__file__))
BASELINE = os.path.join(HERE, 'baseline.json')


def load_baseline() -> dict:
    with open(BASELINE) as f:
        return json.load(f)


def _decide(obj, entry, spec_path):
    from verify import checker
    from verify.spec import load_spec, z3_state_from_input
    prog = common.track_cached(obj, entry)
    policy = load_spec(spec_path, maps=prog.maps, blocks=prog.blocks,
                       calls=prog.calls)
    init_st = (z3_state_from_input(policy.input, prog.maps)
               if policy.input else None)
    t0 = time.time()
    results = checker.check(policy, prog.blocks, prog.maps,
                            init_st=init_st, calls=prog.calls)
    return {r.name: r.verdict for r in results}, time.time() - t0


def corpus(filt=None, record=False):
    expected = load_baseline()
    recorded, carried, out = {}, [], []
    for label, obj, entry, spec_path in common.cases(filt):
        if not os.path.isfile(obj):
            out.append((label, None, 'object not found'))
            if record and label in expected:
                recorded[label], _ = expected[label], carried.append(label)
            continue
        try:
            got, elapsed = _decide(obj, entry, spec_path)
        except Exception as e:
            known = label in common.KNOWN_TRACK_FAILURES
            out.append((label, None if known else False,
                        f'{type(e).__name__}: {e}'
                        + (' (known tracking gap)' if known else '')))
            if record and label in expected:
                recorded[label], _ = expected[label], carried.append(label)
            continue
        if not got:
            continue
        if record:
            recorded[label] = got
            continue
        exp = expected.get(label)
        if exp is None:
            out.append((label, False, f'{got} (not in baseline)'))
            continue
        conds = sorted(set(exp) | set(got))
        for i, cond in enumerate(conds):
            e, g = exp.get(cond, '<missing>'), got.get(cond, '<missing>')
            out.append((f'{label}:{cond}', e == g,
                        f'expected={e:9} got={g}'
                        + (f'   [{elapsed:.2f}s]' if i == 0 else '')))
    if record:
        with open(BASELINE, 'w') as f:
            json.dump(recorded, f, indent=2, sort_keys=True)
            f.write('\n')
        print(f'recorded {len(recorded)} fixture(s) '
              f'/ {sum(len(v) for v in recorded.values())} verdict(s) '
              f'to {os.path.relpath(BASELINE, common.ROOT)}')
        for label in carried:
            print(f'  carried forward (undecidable this run): {label}')
        if filt:
            print(f'  NOTE: --filter {filt!r} was in effect; fixtures it '
                  f'excluded are NOT in this baseline.')
    return out


def conformance(filt=None, record=False):
    import conformance as conf
    return conf.run(filt, record)


def cases(filt=None, record=False):
    import casesuite
    return casesuite.run(filt, record)


SUITES = {'conformance': conformance, 'cases': cases, 'corpus': corpus}
RECORDABLE = tuple(SUITES)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('suites', nargs='*', choices=list(SUITES),
                    help='suites to run (default: all)')
    ap.add_argument('--filter', help='restrict to matching fixtures')
    ap.add_argument('--record', action='store_true',
                    help='rewrite the named suites\' baselines instead of checking')
    args = ap.parse_args()

    wanted = args.suites or list(SUITES)
    if args.record:
        wanted = [s for s in args.suites if s in RECORDABLE]
        if not wanted:
            ap.error(f'--record needs the suite(s) to record, one of {", ".join(RECORDABLE)}')

    n_pass = n_fail = n_skip = 0
    for name in wanted:
        print(f'[{name}]')
        results = SUITES[name](args.filter, args.record)
        if args.record:
            continue
        for label, ok, detail in results:
            if ok is None:
                n_skip += 1
                mark = 'SKIP'
            else:
                n_pass += ok
                n_fail += not ok
                mark = 'PASS' if ok else 'FAIL'
            print(f'    {mark}  {label:58} {detail}')
        n = sum(1 for _, ok, _ in results if ok is not None)
        print(f'    -- {sum(1 for _, ok, _ in results if ok)}/{n} passed\n')

    if args.record:
        return 0
    print(f'{n_pass}/{n_pass + n_fail} checks passed'
          + (f', {n_fail} FAILED' if n_fail else '')
          + (f', {n_skip} skipped' if n_skip else ''))
    return 1 if n_fail else 0


if __name__ == '__main__':
    sys.path.insert(0, HERE)
    sys.exit(main())
