import hashlib
import json
import os
from dataclasses import dataclass, field

import common

HERE   = os.path.dirname(os.path.abspath(__file__))
CASES  = os.path.join(HERE, 'cases')
OBJS   = os.path.join(HERE, 'objs')
KERNEL = os.path.join(HERE, 'oracle', 'kernel.json')

NONDET_HELPERS = {5: 'bpf_ktime_get_ns', 7: 'bpf_get_prandom_u32',
                  118: 'bpf_jiffies64', 125: 'bpf_ktime_get_boot_ns',
                  160: 'bpf_ktime_get_coarse_ns', 208: 'bpf_ktime_get_tai_ns'}


@dataclass
class Case:
    stem:  str
    dir:   str
    runs:  dict = None
    specs: list = field(default_factory=list)

    @property
    def label(self) -> str:
        return self.stem

    @property
    def meta(self) -> dict:
        return self.runs or {}

    @property
    def object(self) -> str:
        return self.meta.get('object', f'{self.stem}.o')

    @property
    def object_path(self) -> str:
        return object_path(self.object)

    @property
    def entry(self) -> str:
        return self.meta.get('entry') or common.entry_of(
            os.path.basename(self.object)[:-2])

    @property
    def tails(self) -> list:
        return list(self.meta.get('tails', ()))

    @property
    def cpu(self) -> int:
        return int(self.meta.get('cpu', 0))

    @property
    def nondet(self) -> bool:
        return bool(self.meta.get('nondet', False))

    @property
    def family(self) -> str:
        return self.stem.split('_', 1)[0]


def discover(filt=None) -> list:
    out = []
    for stem in sorted(os.listdir(CASES)):
        d = os.path.join(CASES, stem)
        if not os.path.isdir(d):
            continue
        case = Case(stem, d)
        if filt and filt not in case.label:
            continue
        for f in sorted(os.listdir(d)):
            if not f.endswith('.json'):
                continue
            if f == 'runs.json':
                with open(os.path.join(d, f)) as fh:
                    case.runs = json.load(fh)
            else:
                case.specs.append(os.path.join(d, f))
        out.append(case)
    return out


def object_path(rel: str) -> str:
    return os.path.join(OBJS, rel)


def tail_parts(text: str) -> tuple:
    obj, rest = text.rsplit(':', 1)
    entry, where = rest.split('@', 1)
    mp, _, slot = where.rpartition('/')
    return object_path(obj), entry, (mp or None), int(slot)


def tail_specs(case) -> list:
    from bpf.link import parse_tail_spec
    return [parse_tail_spec(os.path.join(OBJS, t)) for t in case.tails]


def _strip(node):
    if isinstance(node, dict):
        return {k: _strip(v) for k, v in node.items() if not k.startswith('_')}
    if isinstance(node, list):
        return [_strip(v) for v in node]
    return node


def file_sha(path: str) -> str:
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def run_sha(case, run: dict) -> str:
    doc = {'object': case.object, 'entry': case.entry, 'tails': case.tails,
           'cpu': case.cpu, 'run': _strip(run)}
    return hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()


def object_shas(case) -> dict:
    paths = [case.object_path] + [tail_parts(t)[0] for t in case.tails]
    return {os.path.relpath(p, OBJS): file_sha(p) for p in paths}


def mem_bytes(literal, size: int) -> bytes:
    from verify.spec import _parse_val_bytes
    return bytes(_parse_val_bytes(literal, size))


def pkt_bytes(text: str) -> bytes:
    data = bytes.fromhex(''.join(text.split()))
    if len(data) < 14:
        raise ValueError(f'a packet must be at least 14 bytes (ETH_HLEN), got {len(data)}')
    return data


def called_helpers(case) -> set:
    ids = set()
    for obj in [case.object_path] + [tail_parts(t)[0] for t in case.tails]:
        dump = obj[:-2] + '-bytecode.txt'
        if not os.path.exists(dump):
            continue
        with open(dump) as f:
            for line in f:
                parts = line.split('call ', 1)
                if len(parts) == 2 and parts[1].startswith('0x'):
                    ids.add(int(parts[1].split()[0], 16))
    return ids


def load_kernel() -> dict:
    try:
        with open(KERNEL) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
