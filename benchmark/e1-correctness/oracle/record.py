import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
E1   = os.path.dirname(HERE)
sys.path.insert(0, os.path.dirname(E1))
sys.path.insert(0, E1)
import common
import casefiles as cf

RUNNER = os.path.join(HERE, 'build', 'kernel_run')
CAPS   = 'cap_bpf,cap_net_admin,cap_perfmon+ep'


class Refused(Exception):
    pass


def _launcher() -> list:
    if os.geteuid() == 0:
        return []
    getcap = shutil.which('getcap') or '/usr/sbin/getcap'
    try:
        caps = subprocess.run([getcap, RUNNER], capture_output=True, text=True).stdout
    except OSError:
        caps = ''
    return [] if 'cap_bpf' in caps else ['sudo', '-n']


def _decode(case):
    from bpf.loader import Loader
    with common.quiet():
        got = Loader(case.object_path, case.entry, False).decode_binary()
    return {m['name']: m for m in got['maps']}, got['bss']


def command(case, name, run, cycles, maps, launcher=()):
    cmd = [*launcher, RUNNER, '--obj', case.object_path, '--prog', case.entry,
           '--cpu', str(case.cpu), '--cycles', str(cycles)]
    for t in case.tails:
        path, entry, mp, slot = cf.tail_parts(t)
        cmd += ['--tail', f'{path}:{entry}@{mp + "/" if mp else ""}{slot}']

    def mapdef(mname):
        if mname not in maps:
            raise Refused(f'{name}: no map {mname!r} (have {sorted(maps)})')
        return maps[mname]

    for mname, entries in (run.get('maps') or {}).items():
        m = mapdef(mname)
        for k, v in entries.items():
            cmd += ['--map', mname, cf.mem_bytes(k, m['key_size']).hex(),
                    cf.mem_bytes(v, m['value_size']).hex()]
    cmd += ['--pkt', cf.pkt_bytes(run['pkt']).hex()]
    if 'ctx' in run:
        c = run['ctx']
        cmd += ['--ctx', str(c.get('ingress_ifindex', 1)), str(c.get('rx_queue_index', 0))]

    observe = run.get('observe') or {}
    for mname, keys in (observe.get('maps') or {}).items():
        m = mapdef(mname)
        if keys == '*':
            cmd += ['--dump-all', mname]
        else:
            for k in keys:
                cmd += ['--dump', mname, cf.mem_bytes(k, m['key_size']).hex()]
    if observe.get('bss'):
        cmd.append('--dump-bss')
    if observe.get('pkt'):
        cmd.append('--data-out')
    return cmd


def parse(stdout: str):
    version, cycles, cur = None, [], None
    for line in stdout.splitlines():
        w = line.split()
        if not w:
            continue
        if w[0] == 'error':
            raise Refused(f'runner: {line[6:]}')
        if w[0] == 'version':
            version = line[len('version '):]
        elif w[0] == 'cycle':
            cur = {'maps': {}, 'warn': []}
            cycles.append(cur)
        elif w[0] == 'load':
            cur['load'] = 'ok' if w[1] == 'ok' else {'rejected': int(w[2])}
        elif w[0] == 'run':
            cur['r0'], cur['errno'] = int(w[2]), int(w[4])
        elif w[0] == 'pkt':
            cur['pkt'] = '0x' + (w[1] if len(w) > 1 else '')
        elif w[0] == 'map':
            cur['maps'].setdefault(w[1], {})['0x' + w[2]] = (
                None if w[3] == 'absent' else '0x' + w[3])
        elif w[0] == 'bss':
            cur['bss'] = w[1] if len(w) > 1 else ''
        elif w[0] == 'warn':
            cur['warn'].append(' '.join(w[1:]))
    return version, cycles


def _answer(cycle: dict, bss_syms: dict, run: dict) -> dict:
    out = {'load': cycle.get('load')}
    if cycle.get('load') != 'ok':
        return out
    if cycle.get('errno'):
        out['run_errno'] = cycle['errno']
        return out
    out['r0'] = cycle['r0']
    if cycle['maps']:
        out['maps'] = cycle['maps']
    wanted = (run.get('observe') or {}).get('bss') or []
    if wanted:
        raw = bytes.fromhex(cycle.get('bss', ''))
        out['bss'] = {}
        for sym in wanted:
            if sym not in bss_syms:
                raise Refused(f'no .bss symbol {sym!r} (have {sorted(bss_syms)})')
            o, n = bss_syms[sym]['offset'], bss_syms[sym]['size']
            out['bss'][sym] = '0x' + raw[o:o + n].hex()
    if 'pkt' in cycle:
        out['pkt'] = cycle['pkt']
    if cycle['warn']:
        out['warn'] = sorted(set(cycle['warn']))
    return out


def record_case(case, cycles, dry_run, launcher):
    maps, bss_syms = _decode(case)
    calls = cf.called_helpers(case)
    varying = sorted(cf.NONDET_HELPERS[h] for h in calls & set(cf.NONDET_HELPERS))
    if varying and not case.nondet:
        raise Refused(f'calls {", ".join(varying)} but runs.json does not say '
                      f'"nondet": true')

    entry = {'objects_sha256': cf.object_shas(case), 'runs': {}}
    version = None
    for name, run in sorted(case.runs['runs'].items()):
        cmd = command(case, name, run, cycles, maps, launcher)
        if dry_run:
            print('   ', ' '.join(cmd))
            continue
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0 and 'error' not in proc.stdout:
            raise Refused(f'{name}: runner exited {proc.returncode}: '
                          f'{(proc.stderr or proc.stdout).strip()[-400:]}')
        version, got = parse(proc.stdout)
        if len(got) != cycles:
            raise Refused(f'{name}: expected {cycles} cycle(s), got {len(got)}')
        answers = [_answer(c, bss_syms, run) for c in got]
        rec = {'run_sha256': cf.run_sha(case, run)}
        distinct = []
        for a in answers:
            if a not in distinct:
                distinct.append(a)
        if len(distinct) == 1:
            rec.update(distinct[0])
        elif case.nondet:
            rec['samples'] = distinct
        else:
            raise Refused(f'{name}: the kernel answered differently across '
                          f'{cycles} cycles: {distinct}')
        if distinct[0].get('load') != 'ok':
            rec['log'] = proc.stderr.strip().splitlines()[-20:]
        entry['runs'][name] = rec
        shown = rec.get('r0', rec.get('samples', rec.get('load')))
        print(f'    {name:24} r0={shown}')
    return entry, version


def main():
    ap = argparse.ArgumentParser(
        description="record the kernel's answers to E1's concrete runs")
    ap.add_argument('--filter', help='only cases whose label contains this')
    ap.add_argument('--cycles', type=int, default=5)
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()

    if not os.path.isfile(RUNNER):
        sys.exit(f'runner not built: run {os.path.relpath(HERE, common.ROOT)}/build.sh')
    launcher = _launcher()
    if (launcher and not args.dry_run
            and subprocess.run(['sudo', '-n', 'true'], capture_output=True).returncode != 0):
        rel = os.path.relpath(RUNNER, common.ROOT)
        sys.exit('the runner needs privilege and sudo has no ticket here. Either\n'
                 f'  grant it once:   sudo setcap {CAPS} {rel}\n'
                 '  or, in a terminal: sudo -v && python '
                 f'{os.path.relpath(__file__, common.ROOT)} {" ".join(sys.argv[1:])}')

    kernel = cf.load_kernel()
    cases = [c for c in cf.discover(args.filter) if c.runs]
    recorded, refused, version = [], [], None
    for case in cases:
        print(case.label)
        try:
            entry, v = record_case(case, args.cycles, args.dry_run, launcher)
        except (Refused, ValueError, KeyError) as e:
            refused.append((case.label, str(e)))
            print(f'    REFUSED: {e}')
            continue
        version = v or version
        if not args.dry_run:
            kernel[case.label] = entry
            recorded.append(case.label)

    if args.dry_run:
        return 0
    if recorded:
        kernel['_provenance'] = {
            'runner': version, 'cycles': args.cycles,
            'runner_sha256': cf.file_sha(RUNNER),
            'recorded': datetime.datetime.now().isoformat(timespec='seconds'),
        }
        with open(cf.KERNEL, 'w') as f:
            json.dump(kernel, f, indent=2, sort_keys=True)
            f.write('\n')
    print(f'\nrecorded {len(recorded)} case(s) to {os.path.relpath(cf.KERNEL, common.ROOT)}'
          + (f', refused {len(refused)}' if refused else ''))
    for label, why in refused:
        print(f'  REFUSED {label}: {why}')
    return 1 if refused else 0


if __name__ == '__main__':
    sys.exit(main())
