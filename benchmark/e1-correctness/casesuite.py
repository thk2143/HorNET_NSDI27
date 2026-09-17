import collections
import contextlib
import json
import os
import re
import signal

import common
import casefiles as cf

BASELINE = os.path.join(cf.CASES, 'baseline.json')
TIMEOUT = int(os.environ.get('HORNET_E1_TIMEOUT', '120'))

STATUSES = ('PASS', 'WRONG', 'UNDETERMINED', 'UNSUPPORTED', 'KERNEL_REJECTED',
            'STALE', 'HARNESS')
NOT_RECORDED = ('STALE', 'HARNESS')


class _Timeout(BaseException):
    pass


@contextlib.contextmanager
def _deadline(seconds):
    def on_alarm(signum, frame):
        raise _Timeout()
    old = signal.signal(signal.SIGALRM, on_alarm)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


_REFUSAL = re.compile(r'not implemented|unknown helper')


def _unsupported(e) -> str:
    if isinstance(e, _Timeout):
        return f'crash: timeout after {TIMEOUT}s'
    msg = f'{type(e).__name__}: {e}' if str(e) else type(e).__name__
    kind = 'rejected' if _REFUSAL.search(str(e)) else 'crash'
    return f'{kind}: {" ".join(msg.split())[:160]}'


_PROGS: dict = {}


def _track(case):
    key = (case.object_path, case.entry, tuple(case.tails))
    if key not in _PROGS:
        try:
            with common.quiet(), _deadline(TIMEOUT):
                _PROGS[key] = common.track(case.object_path, case.entry,
                                           tails=cf.tail_specs(case))
        except KeyboardInterrupt:
            raise
        except BaseException as e:
            _PROGS[key] = e
    return _PROGS[key]


def _resolve_nth(node, calls):
    from verify.spec import HELPER_IMM, SpecError
    if isinstance(node, list):
        return [_resolve_nth(n, calls) for n in node]
    if not isinstance(node, dict):
        return node
    if 'nth' in node and 'helper' in node and 'idx' not in node:
        imm = HELPER_IMM.get(node['helper'])
        sites = sorted(i for i, rec in calls.items() if rec.imm == imm)
        k = int(node['nth'])
        if imm is None or not 0 <= k < len(sites):
            raise SpecError(f"no call #{k} of {node['helper']!r} "
                            f"(this program has {len(sites)})")
        out = {key: v for key, v in node.items() if key != 'nth'}
        out['idx'] = sites[k]
        return out
    return {key: _resolve_nth(v, calls) for key, v in node.items()}


def _concrete_state(prog, run):
    from z3 import Array, BitVecSort, BitVecVal, BoolSort, BoolVal, K, Store
    from track.encode import (_make_init_state, PKT_ADDR_BITS, ARRAY_MAP_TYPES,
                              PROG_MAP_TYPES)
    from verify.spec import SpecError

    data = cf.pkt_bytes(run['pkt'])
    pkt0 = Array('pkt0', BitVecSort(PKT_ADDR_BITS), BitVecSort(8))
    for i, b in enumerate(data):
        pkt0 = Store(pkt0, BitVecVal(i, PKT_ADDR_BITS), BitVecVal(b, 8))

    by_name = {m['name']: m for m in prog.maps}
    seeds = {}
    for name, entries in (run.get('maps') or {}).items():
        m = by_name.get(name)
        if m is None:
            raise SpecError(f'no map {name!r} (have {sorted(by_name)})')
        seeds[m['id']] = {
            int.from_bytes(cf.mem_bytes(k, m['key_size']), 'little'):
            int.from_bytes(cf.mem_bytes(v, m['value_size']), 'little')
            for k, v in entries.items()}

    map0 = []
    for m in prog.maps:
        Key = BitVecSort(max(m['key_size'], 1) * 8)
        Val = BitVecSort(max(m['value_size'], 1) * 8)
        if m['type'] in PROG_MAP_TYPES:
            map0.append([Array(f"present{m['id']}", Key, BoolSort()),
                         Array(f"value{m['id']}", Key, Val)])
            continue
        present = K(Key, BoolVal(False))
        value = (K(Key, BitVecVal(0, Val.size())) if m['type'] in ARRAY_MAP_TYPES
                 else Array(f"value{m['id']}", Key, Val))
        for k, v in seeds.get(m['id'], {}).items():
            kk = BitVecVal(k, Key.size())
            present = Store(present, kk, BoolVal(True))
            value = Store(value, kk, BitVecVal(v, Val.size()))
        map0.append([present, value])

    ctx = run.get('ctx') or {}
    return _make_init_state(
        prog.maps, pkt0=pkt0, map0=map0,
        rx_index0=BitVecVal(ctx.get('rx_queue_index', 0), 64),
        ingress=BitVecVal(ctx.get('ingress_ifindex', 1), 64),
        egress=BitVecVal(0, 64),
        pkt_len_val=BitVecVal(len(data), 64))


def _observations(answer) -> list:
    obs = [('r0', None, answer['r0'])]
    for name, keys in sorted((answer.get('maps') or {}).items()):
        for k, v in sorted(keys.items()):
            atom = ({'map': name, 'key': k, 'contains': False} if v is None
                    else {'map': name, 'key': k, 'value': v})
            obs.append((f'map:{name}[{k}]', atom, v))
    for sym, v in sorted((answer.get('bss') or {}).items()):
        obs.append((f'bss:{sym}', {'bss': sym, 'size': (len(v) - 2) // 2, 'value': v}, v))
    if 'pkt' in answer:
        data = bytes.fromhex(answer['pkt'][2:])
        obs.append(('pkt', {'and': [
            {'offset': 0, 'size': len(data), 'value': list(data)},
            {'pkt_len': {'min': len(data), 'max': len(data)}}]}, f'{len(data)} bytes'))
    return obs


def _verdicts(policy, ctx) -> dict:
    from z3 import SolverFor
    from verify import checker
    solver = SolverFor('QF_ABV')
    out, vacuous = {}, {}
    for bc in policy.block_conditions.values():
        try:
            out[bc.name] = checker.check_block_condition(bc, ctx, solver, vacuous).verdict
        except Exception as e:
            out[bc.name] = e
    for ec in policy.exit_conditions.values():
        try:
            out[ec.name] = checker.check_exit_condition(ec, ctx, solver).verdict
        except Exception as e:
            out[ec.name] = e
    return out


def _r0_verdict(ctx, prog, pins, want):
    from z3 import And, BoolVal, Extract, SolverFor
    from verify import prune
    from verify.checker import _decide
    solver = SolverFor('QF_ABV')
    some, other = False, None
    for b in prune.exit_blocks(prog.blocks):
        if b not in ctx.info or ctx.reach(b) is False or prog.blocks[b].ret_expr is None:
            continue
        st = ctx.ret_state(b)
        low = Extract(31, 0, st.r0)
        pin = And(*[p.to_z3(st) for p in pins]) if pins else BoolVal(True)
        if not some:
            some = _decide(solver, ctx.reach(b), And(pin, low == want), ctx)[0]
        if other is None:
            ok, model = _decide(solver, ctx.reach(b), And(pin, low != want), ctx)
            if ok:
                other = model.eval(low, model_completion=True).as_long()
    return some, other


def _check_run(case, prog, name, run, answer) -> list:
    from verify import checker
    from verify.spec import parse_spec, _parse_cond

    base = f'{case.label}/{name}'
    samples = answer['samples'] if 'samples' in answer else [answer]
    labels = [lab for lab, _a, _v in _observations(samples[0])]
    if isinstance(prog, BaseException):
        return [(f'{base}:{lab}', 'UNSUPPORTED', _unsupported(prog)) for lab in labels]

    try:
        with _deadline(TIMEOUT):
            pins_raw = _resolve_nth(run.get('pin') or [], prog.calls)
            exits = {'pinned_exit': {'assert': 'exists', 'cond': {'and': pins_raw}}}
            wanted = []
            for si, sample in enumerate(samples):
                for lab, atom, value in _observations(sample):
                    if atom is None:
                        wanted.append((lab, si, value, None))
                        continue
                    key = f'o{len(exits)}'
                    exits[f'{key}_all'] = {'assert': 'all', 'cond': (
                        {'or': [{'not': {'and': pins_raw}}, atom]} if pins_raw else atom)}
                    exits[f'{key}_any'] = {'assert': 'exists',
                                           'cond': {'and': pins_raw + [atom]}}
                    wanted.append((lab, si, value, key))
            policy = parse_spec({'exit_conditions': exits}, maps=prog.maps,
                                blocks=prog.blocks, calls=prog.calls)
            init = _concrete_state(prog, run)
            ctx = checker.context_for([policy], prog.blocks, prog.maps,
                                      init_st=init, calls=prog.calls)
            verdicts = _verdicts(policy, ctx)
            if isinstance(verdicts['pinned_exit'], Exception):
                raise verdicts['pinned_exit']
            pins = [_parse_cond(p, prog.maps, prog.calls) for p in pins_raw]
            if verdicts['pinned_exit'] == 'unsat':
                why = ('no reachable exit under the pinned helper outcomes' if pins
                       else 'no reachable exit')
                return [(f'{base}:{lab}', 'UNDETERMINED', why) for lab in labels]

            per_label = collections.OrderedDict()
            for lab, si, value, key in wanted:
                if key is None:
                    try:
                        some, other = _r0_verdict(ctx, prog, pins, value)
                    except Exception as e:
                        per_label.setdefault(lab, []).append((value, None, None, _unsupported(e)))
                        continue
                    all_ok = other is None
                    note = '' if all_ok else f'hornet also admits r0={other:#x}'
                else:
                    v_any, v_all = verdicts[f'{key}_any'], verdicts[f'{key}_all']
                    broken = next((v for v in (v_any, v_all) if isinstance(v, Exception)), None)
                    if broken is not None:
                        per_label.setdefault(lab, []).append((value, None, None, _unsupported(broken)))
                        continue
                    some = v_any == 'sat'
                    all_ok = v_all == 'holds'
                    note = '' if all_ok else 'not at every exit'
                per_label.setdefault(lab, []).append((value, some, all_ok, note))
    except KeyboardInterrupt:
        raise
    except BaseException as e:
        return [(f'{base}:{lab}', 'UNSUPPORTED', _unsupported(e)) for lab in labels]

    rows = []
    warn = sorted({w for s in samples for w in s.get('warn', ())})
    for lab, got in per_label.items():
        broken = next((note for _v, some, _a, note in got if some is None), None)
        if broken is not None:
            rows.append((f'{base}:{lab}', 'UNSUPPORTED', broken))
            continue
        shown = ' / '.join('absent' if v is None else f'{v:#x}' if isinstance(v, int)
                           else str(v) for v, *_ in got)
        if case.nondet:
            ok = all(some for _v, some, _a, _n in got)
            status = 'PASS' if ok else 'WRONG'
            detail = f'kernel samples {shown}' + ('' if ok else ': one is ruled out')
        else:
            value, some, all_ok, note = got[0]
            if not some:
                status, detail = 'WRONG', f'kernel {shown}: hornet rules it out'
            elif all_ok:
                status, detail = 'PASS', f'kernel {shown}'
            else:
                status, detail = 'UNDETERMINED', f'kernel {shown}; {note}'
        if warn:
            detail += f'  (kernel warns: {", ".join(warn)})'
        rows.append((f'{base}:{lab}', status, detail))
    return rows


def _kernel_rows(case, prog, kernel) -> list:
    rows = []
    entry = kernel.get(case.label)
    shas = cf.object_shas(case)
    for name, run in sorted(case.runs['runs'].items()):
        base = f'{case.label}/{name}'
        rec = (entry or {}).get('runs', {}).get(name)
        if rec is None:
            rows.append((f'{base}:r0', 'STALE', 'no kernel answer recorded'))
            continue
        if entry.get('objects_sha256') != shas:
            rows.append((f'{base}:r0', 'STALE', 'object rebuilt since it was recorded'))
            continue
        if rec.get('run_sha256') != cf.run_sha(case, run):
            rows.append((f'{base}:r0', 'STALE', 'run changed since it was recorded'))
            continue
        if rec.get('load', 'ok') != 'ok' and 'samples' not in rec:
            rows.append((f'{base}:load', 'KERNEL_REJECTED',
                         f'verifier: {(rec.get("log") or ["?"])[-1][:120]}'))
            continue
        if 'run_errno' in rec:
            rows.append((f'{base}:r0', 'HARNESS',
                         f'test_run failed with errno {rec["run_errno"]}'))
            continue
        rows.extend(_check_run(case, prog, name, run, rec))
    return rows


_WRONG = {('violated', 'holds'), ('sat', 'unsat')}
_UNDETERMINED = {('holds', 'violated'), ('unsat', 'sat')}


def _spec_rows(case, prog, path) -> list:
    from verify import checker
    from verify.spec import SpecError, parse_spec, z3_state_from_input

    with open(path) as f:
        raw = json.load(f)
    base = f'{case.label}/{os.path.basename(path)[:-5]}'
    expect = raw.get('_expect') or {}
    want_error = raw.get('_expect_error')
    names = sorted(expect) or ['parse']
    if isinstance(prog, BaseException):
        return [(f'{base}:{n}', 'UNSUPPORTED', _unsupported(prog)) for n in names]

    try:
        policy = parse_spec(_resolve_nth(raw, prog.calls), maps=prog.maps,
                            blocks=prog.blocks, calls=prog.calls)
    except SpecError as e:
        if want_error and want_error in str(e):
            return [(f'{base}:parse', 'PASS', f'rejected as expected: {e}')]
        return [(f'{base}:parse', 'WRONG' if want_error else 'HARNESS', f'SpecError: {e}')]
    if want_error:
        return [(f'{base}:parse', 'WRONG', f'expected a SpecError naming {want_error!r}')]

    try:
        with _deadline(TIMEOUT):
            init = (z3_state_from_input(policy.input, prog.maps)
                    if policy.input else None)
            ctx = checker.context_for([policy], prog.blocks, prog.maps,
                                      init_st=init, calls=prog.calls)
            got = _verdicts(policy, ctx)
    except KeyboardInterrupt:
        raise
    except BaseException as e:
        return [(f'{base}:{n}', 'UNSUPPORTED', _unsupported(e)) for n in names]

    rows = []
    for n in sorted(set(got) | set(expect)):
        e, g = expect.get(n), got.get(n)
        if isinstance(g, Exception):
            rows.append((f'{base}:{n}', 'UNSUPPORTED', _unsupported(g)))
        elif e is None or g is None:
            rows.append((f'{base}:{n}', 'HARNESS',
                         'no _expect for this condition' if e is None
                         else '_expect names a condition the spec does not have'))
        elif e == g:
            rows.append((f'{base}:{n}', 'PASS', g))
        elif (e, g) in _WRONG:
            rows.append((f'{base}:{n}', 'WRONG', f'expected {e}, hornet {g}'))
        elif (e, g) in _UNDETERMINED:
            rows.append((f'{base}:{n}', 'UNDETERMINED', f'expected {e}, hornet {g}'))
        else:
            rows.append((f'{base}:{n}', 'HARNESS', f'expected {e}, hornet {g}'))
    return rows


def _orphans(cases) -> list:
    rows = []
    have = {c.object_path for c in cases}
    tails = {cf.tail_parts(t)[0] for c in cases for t in c.tails}
    if os.path.isdir(cf.OBJS):
        for f in sorted(os.listdir(cf.OBJS)):
            p = os.path.join(cf.OBJS, f)
            if f.endswith('.o') and p not in have and p not in tails and not f.endswith('_cb.o'):
                rows.append((f[:-2], 'HARNESS', 'object has no case directory'))
    for c in cases:
        if not os.path.isfile(c.object_path):
            rows.append((c.label, 'HARNESS', f'no object {c.object}'))
        elif not c.runs and not c.specs:
            rows.append((c.label, 'HARNESS', 'case has neither runs.json nor a spec'))
    return rows


def _family(label):
    return label.split('/', 1)[0].split('_', 1)[0]


def _oracle(label, cases_by_label):
    parts = label.split('/')
    case = cases_by_label.get(parts[0])
    if case is None:
        return '-'
    what = parts[1].split(':', 1)[0] if len(parts) > 1 else ''
    if case.runs and what in case.runs.get('runs', {}):
        return 'kernel-nondet' if case.nondet else 'kernel'
    return 'hand'


def _table(title, key, rows):
    counts = collections.defaultdict(collections.Counter)
    for label, status, _ in rows:
        counts[key(label)][status] += 1
    shown = [s for s in STATUSES if any(c[s] for c in counts.values())]
    width = max([14] + [len(k) + 2 for k in counts])
    print(f'    {title:{width}}' + ''.join(f'{s:>16}' for s in shown) + f'{"total":>8}')
    for k in sorted(counts):
        c = counts[k]
        print(f'    {k:{width}}' + ''.join(f'{c[s]:>16}' for s in shown)
              + f'{sum(c.values()):>8}')
    total = collections.Counter(s for _, s, _ in rows)
    print(f'    {"all":{width}}' + ''.join(f'{total[s]:>16}' for s in shown)
          + f'{sum(total.values()):>8}\n')


def _summary(rows, cases_by_label):
    if not rows:
        print('    no cases\n')
        return
    counted = rows
    _table('family', _family, rows)
    _table('oracle', lambda l: _oracle(l, cases_by_label), rows)
    wrong = [r for r in counted if r[1] == 'WRONG']
    print(f'    WRONG — hornet is unsound here ({len(wrong)}):')
    for label, _, detail in wrong:
        print(f'      {label:52} {detail}')
    reasons = collections.Counter(
        re.sub(r'0x[0-9a-f]+|\d+', 'N', f'{s}  {d}')[:100]
        for _, s, d in counted if s in ('UNSUPPORTED', 'UNDETERMINED'))
    print('\n    UNSUPPORTED / UNDETERMINED by reason:')
    for reason, k in reasons.most_common():
        print(f'      {k:4}  {reason}')
    print()


def run(filt=None, record=False):
    cases = cf.discover(filt)
    kernel = cf.load_kernel()
    rows = [] if filt else _orphans(cases)
    if filt:
        rows = [r for r in _orphans(cases) if r[1] == 'HARNESS' and
                not r[2].startswith('object has no case')]
    for case in cases:
        if not os.path.isfile(case.object_path):
            continue
        prog = _track(case)
        if case.runs:
            rows.extend(_kernel_rows(case, prog, kernel))
        for path in case.specs:
            rows.extend(_spec_rows(case, prog, path))

    _summary(rows, {c.label: c for c in cases})

    try:
        with open(BASELINE) as f:
            expected = json.load(f)
    except FileNotFoundError:
        expected = {}

    if record:
        recorded = dict(expected) if filt else {}
        recorded.update({label: s for label, s, _ in rows if s not in NOT_RECORDED})
        with open(BASELINE, 'w') as f:
            json.dump(recorded, f, indent=2, sort_keys=True)
            f.write('\n')
        n = sum(1 for _, s, _ in rows if s not in NOT_RECORDED)
        print(f'recorded {n} check status(es) to '
              f'{os.path.relpath(BASELINE, common.ROOT)}')
        for label, s, d in rows:
            if s in NOT_RECORDED:
                print(f'  NOT recorded ({s}): {label}: {d}')
        return []

    out = []
    for label, status, detail in rows:
        exp = expected.get(label)
        ok = status not in NOT_RECORDED and status == exp
        base = 'not in baseline' if exp is None else f'baseline {exp}'
        out.append((label, ok, f'{status:15} ({base})  {detail}'[:170]))
    return out
