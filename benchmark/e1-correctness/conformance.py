import collections
import json
import os
import re
import subprocess

HERE     = os.path.dirname(os.path.abspath(__file__))
SRC      = os.path.join(HERE, 'bpf_conformance')
RUNNER   = os.path.join(SRC, 'build', 'bin', 'bpf_conformance_runner')
TESTS    = os.path.join(SRC, 'tests')
PLUGIN   = os.path.join(HERE, 'conformance', 'hornet_plugin')
BASELINE = os.path.join(HERE, 'conformance', 'baseline.json')

SCOPE = ['--cpu_version', 'v4', '--include_groups', 'callx', 'packet']
HORNET = ['--elf', 'true', '--xdp_prolog', 'true']
EXCLUDE = ['call_local', 'callx', 'lock_cmpxchg', 'lock_cmpxchg32', 'prime',
           'rfc9669_call_local', 'rfc9669_lock_cmpxchg32',
           'rfc9669_lock_cmpxchg64']

STATUSES = ('PASS', 'WRONG', 'UNSUPPORTED', 'UNDETERMINED', 'SKIP', 'HARNESS')
_UNSUPPORTED, _UNDETERMINED = {2, 5, 6}, {3, 4}


_LINE = re.compile(r'^(PASS|FAIL|ERROR|SKIP): "?([^"\s]+)"?\s*(.*)$')


def _run(plugin, scope, filt=None, extra=()):
    cmd = [RUNNER, '--test_file_directory', TESTS, '--plugin_path', plugin,
           '--exclude_regex', rf'^({"|".join(EXCLUDE)})\.data$', *scope, *extra]
    if filt:
        cmd += ['--include_regex', re.escape(filt)]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    rows = {}
    for line in out.splitlines():
        m = _LINE.match(line)
        if m:
            name = os.path.basename(m.group(2))
            name = name[:-5] if name.endswith('.data') else name
            if name not in EXCLUDE:
                rows[name] = (m.group(1), m.group(3))
    return rows


def _classify(verdict, message):
    if verdict == 'PASS':
        return 'PASS', ''
    if verdict == 'SKIP':
        return 'SKIP', message
    if verdict == 'FAIL':
        m = re.search(r'incorrect return value (\d+) expected (\d+)', message)
        if m:
            return 'WRONG', f'got {int(m.group(1)):#x} expected {int(m.group(2)):#x}'
        return 'HARNESS', message
    m = re.search(r'error code (-?\d+) and output (.*)', message)
    if m:
        code = int(m.group(1))
        if code in _UNSUPPORTED:
            return 'UNSUPPORTED', m.group(2)
        if code in _UNDETERMINED:
            return 'UNDETERMINED', m.group(2)
    return 'HARNESS', message


def _versions(filt):
    need = {}
    for v in ('v3', 'v2', 'v1'):
        scope = ['--cpu_version', v] + SCOPE[2:]
        for name, (verdict, _) in _run('/bin/false', scope, filt).items():
            need.setdefault(name, 'v4')
            if verdict != 'SKIP':
                need[name] = v
    return need


_FAMILIES = [
    ('program',    r'^(prime|subnet|stack|mem-len)$'),
    ('atomic',     r'^lock_'),
    ('call',       r'^call'),
    ('jmp32',      r'^j\w*32'),
    ('jmp',        r'^(j|exit)'),
    ('byteswap',   r'^(be|le|bswap|swap)\d'),
    ('mul/div/mod', r'^(mul|s?div|s?mod)'),
    ('shift',      r'^(lsh|rsh|arsh)'),
    ('movsx',      r'^(movsx|mov64-sign)'),
    ('load/store', r'^(ld|st)'),
    ('alu',        r'^(add|sub|and|or|xor|neg|mov|alu)'),
]


def _family(name):
    base = name[len('rfc9669_'):] if name.startswith('rfc9669_') else name
    return next((f for f, rx in _FAMILIES if re.match(rx, base)), 'other')


def _table(title, key, results):
    counts = collections.defaultdict(collections.Counter)
    for name, (status, _) in results.items():
        counts[key(name)][status] += 1
    shown = [s for s in STATUSES if any(c[s] for c in counts.values())]
    print(f'    {title:14}' + ''.join(f'{s:>13}' for s in shown) + f'{"total":>8}')
    for k in sorted(counts):
        c = counts[k]
        print(f'    {k:14}' + ''.join(f'{c[s]:>13}' for s in shown)
              + f'{sum(c.values()):>8}')
    total = collections.Counter(s for s, _ in results.values())
    print(f'    {"all":14}' + ''.join(f'{total[s]:>13}' for s in shown)
          + f'{sum(total.values()):>8}\n')


def _summary(results, versions):
    _table('ISA version', lambda n: versions.get(n, '?'), results)
    _table('family', _family, results)
    wrong = sorted(n for n, (s, _) in results.items() if s == 'WRONG')
    print(f'    WRONG — hornet returned one r0 and it is not the kernel\'s '
          f'({len(wrong)}):')
    for n in wrong:
        print(f'      {n:34} {results[n][1]}')
    reasons = collections.Counter(
        re.sub(r'0x[0-9a-f]+|\d+', 'N', results[n][1])[:90]
        for n, (s, _) in results.items() if s in ('UNSUPPORTED', 'UNDETERMINED'))
    print(f'\n    UNSUPPORTED / UNDETERMINED by reason:')
    for reason, k in reasons.most_common():
        print(f'      {k:4}  {reason}')
    print()


def run(filt=None, record=False):
    if not os.path.isfile(RUNNER):
        return [('conformance', None, 'runner not built — run '
                 'benchmark/e1-correctness/conformance/build.sh')]

    results = {name: _classify(*r)
               for name, r in _run(PLUGIN, SCOPE, filt, HORNET).items()}
    if not results:
        return [('conformance', False, 'the runner reported no tests')]
    _summary(results, _versions(filt))

    try:
        with open(BASELINE) as f:
            expected = json.load(f)
    except FileNotFoundError:
        expected = {}

    if record:
        broken = sorted(n for n, (s, _) in results.items() if s == 'HARNESS')
        recorded = dict(expected) if filt else {}
        recorded.update({n: s for n, (s, _) in results.items() if s != 'HARNESS'})
        with open(BASELINE, 'w') as f:
            json.dump(recorded, f, indent=2, sort_keys=True)
            f.write('\n')
        print(f'recorded {len(recorded)} test status(es) to '
              f'{os.path.relpath(BASELINE, os.path.dirname(os.path.dirname(HERE)))}')
        for n in broken:
            print(f'  NOT recorded (harness failure): {n}: {results[n][1]}')
        return []

    out = []
    for name in sorted(results):
        status, detail = results[name]
        exp = expected.get(name)
        ok = status != 'HARNESS' and status == exp
        base = 'not in baseline' if exp is None else f'baseline {exp}'
        out.append((name, ok, f'{status:12} ({base})  {detail}'[:150]))
    return out
